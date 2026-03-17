use crate::state::Screen;
use dioxus::core::spawn_forever;
use dioxus::prelude::*;
use verso_core::config::{BackendConfig, BitcoindAuth, ScanConfig};
use std::path::PathBuf;

const MAX_LOG_LINES: usize = 250;

fn push_log_line(log: &mut Vec<String>, line: String) {
    if line.starts_with("[sync]") {
        if let Some(last) = log.last_mut() {
            if last.starts_with("[sync]") {
                *last = line;
                return;
            }
        }
    }

    log.push(line);
    if log.len() > MAX_LOG_LINES {
        let overflow = log.len() - MAX_LOG_LINES;
        log.drain(0..overflow);
    }
}

#[component]
pub fn InputView(
    screen: Signal<Screen>,
    descriptor: Signal<String>,
    report: Signal<Option<verso_core::report::Report>>,
    scan_error: Signal<Option<String>>,
    log: Signal<Vec<String>>,
    rpc_test_status: Signal<Option<String>>,
) -> Element {
    let mut network = use_signal(|| "mainnet".to_string());
    let mut backend_type = use_signal(|| "bitcoind".to_string());
    let mut esplora_url = use_signal(|| "https://mempool.space/api".to_string());
    let mut bitcoind_url = use_signal(|| "http://127.0.0.1:8332".to_string());
    let mut bitcoind_cookie = use_signal(String::new);
    let mut bitcoind_user = use_signal(String::new);
    let mut bitcoind_pass = use_signal(String::new);
    let mut rpc_test_status = rpc_test_status;

    let on_submit = move |_| {
        let desc_val = descriptor();
        if desc_val.trim().is_empty() {
            return;
        }

        let descs: Vec<String> = desc_val
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        if descs.is_empty() {
            scan_error.set(Some("No descriptor provided".into()));
            screen.set(Screen::Error);
            return;
        }

        if descs.len() > 2 {
            scan_error.set(Some(
                "Please provide at most two descriptors (external + internal), one per line."
                    .into(),
            ));
            screen.set(Screen::Error);
            return;
        }

        let network_parsed = match network().as_str() {
            "mainnet" | "bitcoin" => bitcoin::Network::Bitcoin,
            "testnet" | "testnet4" => bitcoin::Network::Testnet,
            "regtest" => bitcoin::Network::Regtest,
            other => {
                scan_error.set(Some(format!(
                    "Unknown network: {}. Use mainnet, testnet4, or regtest.",
                    other
                )));
                screen.set(Screen::Error);
                return;
            }
        };

        let backend = if backend_type() == "bitcoind" {
            let rpc_url = bitcoind_url().trim().to_string();
            if rpc_url.is_empty() {
                scan_error.set(Some("Bitcoind RPC URL cannot be empty.".into()));
                screen.set(Screen::Error);
                return;
            }

            let user = bitcoind_user().trim().to_string();
            let pass = bitcoind_pass().trim().to_string();
            let has_cookie = !bitcoind_cookie().trim().is_empty();
            let has_user = !user.is_empty();
            let has_pass = !pass.is_empty();

            if has_cookie && (has_user || has_pass) {
                scan_error.set(Some(
                    "Choose exactly one bitcoind auth method: cookie file OR username/password."
                        .into(),
                ));
                screen.set(Screen::Error);
                return;
            }

            if !(has_cookie || (has_user && has_pass)) {
                scan_error.set(Some(
                    "Bitcoind auth requires either cookie file, or both username and password."
                        .into(),
                ));
                screen.set(Screen::Error);
                return;
            }

            let auth = if has_cookie {
                let cookie_path = PathBuf::from(bitcoind_cookie().trim());
                BitcoindAuth::Cookie(cookie_path)
            } else {
                BitcoindAuth::UserPass { user, pass }
            };

            BackendConfig::Bitcoind {
                url: rpc_url,
                auth,
            }
        } else {
            let url = esplora_url().trim().to_string();
            if url.is_empty() {
                scan_error.set(Some("Esplora URL cannot be empty.".into()));
                screen.set(Screen::Error);
                return;
            }
            BackendConfig::Esplora { url }
        };
        let descriptor_count = descs.len();

        let (progress_tx, mut progress_rx) =
            tokio::sync::mpsc::unbounded_channel::<verso_core::config::ScanProgress>();

        let config = ScanConfig {
            descriptors: descs,
            network: network_parsed,
            backend,
            known_risky_txids: None,
            known_exchange_txids: None,
            derivation_limit: 1000,
            data_dir: None,
            ephemeral: true,
            progress_tx: Some(progress_tx),
        };

        let backend_diag = match &config.backend {
            BackendConfig::Bitcoind { url, auth } => match auth {
                BitcoindAuth::Cookie(_) => {
                    format!("bitcoind(auth=cookie file, url={url})")
                }
                BitcoindAuth::UserPass { user, .. } => {
                    format!("bitcoind(auth=user/pass: {user}, url={url})")
                }
            },
            BackendConfig::Esplora { url } => {
                format!("esplora(url={url})")
            }
        };

        // Reset prior results before switching screens.
        log.write().clear();
        report.set(None);
        scan_error.set(None);
        screen.set(Screen::Loading);
        {
            let mut lines = log.write();
            push_log_line(
                &mut lines,
                format!(
                    "[init] starting scan: network={:?}, descriptors={}",
                    network_parsed, descriptor_count
                ),
            );
            push_log_line(&mut lines, format!("[init] backend={backend_diag}"));
        }

        let mut screen_s = screen;
        let mut report_s = report;
        let mut error_s = scan_error;
        let mut log_s = log;

        // This task must outlive InputView because the component is dropped as
        // soon as we switch to Loading.
        spawn_forever(async move {
            let scan_task = tokio::task::spawn_blocking(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|err| {
                        verso_core::VersoError::InvalidConfig(format!(
                            "failed to create scan runtime: {err}"
                        ))
                    })?;

                runtime.block_on(verso_core::scan(config))
            });

            while let Some(p) = progress_rx.recv().await {
                let mut lines = log_s.write();
                push_log_line(&mut lines, format!("[{}] {}", p.phase, p.message));
            }

            let result = scan_task.await;

            match result {
                Ok(Ok(r)) => {
                    report_s.set(Some(r));
                    screen_s.set(Screen::Report);
                }
                Ok(Err(e)) => {
                    error_s.set(Some(e.to_string()));
                    screen_s.set(Screen::Error);
                }
                Err(join_err) => {
                    let msg = if join_err.is_panic() {
                        let payload = join_err.into_panic();
                        if let Some(message) = payload.downcast_ref::<&'static str>() {
                            let rendered = format!("Scan task panicked: {message}");
                            let mut lines = log_s.write();
                            push_log_line(&mut lines, format!("[fatal] {rendered}"));
                            rendered
                        } else if let Some(message) = payload.downcast_ref::<String>() {
                            let rendered = format!("Scan task panicked: {message}");
                            let mut lines = log_s.write();
                            push_log_line(&mut lines, format!("[fatal] {rendered}"));
                            rendered
                        } else {
                            let rendered = "Scan task panicked: unknown panic payload".to_string();
                            let mut lines = log_s.write();
                            push_log_line(&mut lines, format!("[fatal] {rendered}"));
                            rendered
                        }
                    } else {
                        let rendered = format!("Scan task failed: {join_err}");
                        let mut lines = log_s.write();
                        push_log_line(&mut lines, format!("[fatal] {rendered}"));
                        rendered
                    };

                    error_s.set(Some(msg));
                    screen_s.set(Screen::Error);
                }
            }
        });
    };

    let can_submit = !descriptor().trim().is_empty();

    let on_test_rpc = move |_| {
        if backend_type() != "bitcoind" {
            return;
        }

        let rpc_url = bitcoind_url().trim().to_string();
        if rpc_url.is_empty() {
            rpc_test_status.set(Some("Bitcoind RPC URL cannot be empty.".into()));
            return;
        }

        let user = bitcoind_user().trim().to_string();
        let pass = bitcoind_pass().trim().to_string();
        let has_cookie = !bitcoind_cookie().trim().is_empty();
        let has_user = !user.is_empty();
        let has_pass = !pass.is_empty();

        if has_cookie && (has_user || has_pass) {
            rpc_test_status.set(Some(
                "Choose exactly one auth method for testing: cookie file OR username/password."
                    .into(),
            ));
            return;
        }

        if !(has_cookie || (has_user && has_pass)) {
            rpc_test_status.set(Some(
                "Bitcoind test requires either cookie file, or both username and password."
                    .into(),
            ));
            return;
        }

        let auth = if has_cookie {
            BitcoindAuth::Cookie(PathBuf::from(bitcoind_cookie().trim()))
        } else {
            BitcoindAuth::UserPass { user, pass }
        };

        let mut rpc_test_status = rpc_test_status;
        rpc_test_status.set(Some("Testing Bitcoin RPC connection...".into()));

        spawn(async move {
            let test_result = tokio::task::spawn_blocking(move || {
                verso_core::backend::test_bitcoind_connection(&rpc_url, &auth)
            })
            .await;

            match test_result {
                Ok(Ok(msg)) => rpc_test_status.set(Some(format!("✅ {msg}"))),
                Ok(Err(err)) => rpc_test_status.set(Some(format!("❌ {err}"))),
                Err(join_err) => {
                    let msg = if join_err.is_panic() {
                        "❌ RPC test panicked unexpectedly".to_string()
                    } else {
                        format!("❌ RPC test failed: {join_err}")
                    };
                    rpc_test_status.set(Some(msg))
                }
            }
        });
    };

    rsx! {
        div { class: "input-view",
            p { class: "input-headline", "Forensic Analysis" }
            p { class: "input-subheadline", "Scan a wallet for privacy vulnerabilities" }

            div { class: "form-field",
                label { class: "form-label", "Descriptor" }
                textarea {
                    class: "descriptor-input",
                    rows: 3,
                    value: descriptor(),
                    oninput: move |e| descriptor.set(e.value()),
                    placeholder: "wpkh([fingerprint/84'/0'/0']xpub.../0/*)\n— or paste a bare xpub / zpub / tpub"
                }
                p { class: "form-hint",
                    "One or two descriptors (external + internal), one per line. Bare extended keys are auto-wrapped."
                }
            }

            div { class: "form-row",
                div { class: "form-field",
                    label { class: "form-label", "Network" }
                    select {
                        class: "form-select",
                        value: network(),
                        onchange: move |e| network.set(e.value()),
                        option { value: "mainnet", "MAINNET" }
                        option { value: "testnet", "TESTNET" }
                        option { value: "regtest", "REGTEST" }
                    }
                }
                div { class: "form-field",
                    label { class: "form-label", "Backend" }
                    select {
                        class: "form-select",
                        value: backend_type(),
                        onchange: move |e| backend_type.set(e.value()),
                        option { value: "esplora", "ESPLORA" }
                        option { value: "bitcoind", "BITCOIN CORE RPC" }
                    }
                }
            }

            if backend_type() == "esplora" {
                div { class: "form-field",
                    label { class: "form-label", "Esplora URL" }
                    input {
                        r#type: "text",
                        class: "form-input",
                        value: esplora_url(),
                        oninput: move |e| esplora_url.set(e.value()),
                    }
                }
            }

            if backend_type() == "bitcoind" {
                div { class: "form-field",
                    label { class: "form-label", "RPC URL" }
                    input {
                        r#type: "text",
                        class: "form-input",
                        value: bitcoind_url(),
                        oninput: move |e| bitcoind_url.set(e.value()),
                    }
                }
                div { class: "form-field",
                    label { class: "form-label", "Cookie File" }
                    input {
                        r#type: "text",
                        class: "form-input",
                        placeholder: "~/.bitcoin/regtest/.cookie",
                        value: bitcoind_cookie(),
                        oninput: move |e| bitcoind_cookie.set(e.value()),
                    }
                }
                div { class: "form-field",
                    label { class: "form-label", "RPC Username" }
                    input {
                        r#type: "text",
                        class: "form-input",
                        value: bitcoind_user(),
                        oninput: move |e| bitcoind_user.set(e.value()),
                    }
                }
                div { class: "form-field",
                    label { class: "form-label", "RPC Password" }
                    input {
                        r#type: "password",
                        class: "form-input",
                        value: bitcoind_pass(),
                        oninput: move |e| bitcoind_pass.set(e.value()),
                    }
                }
                button {
                    class: "btn-secondary",
                    onclick: on_test_rpc,
                    "Test RPC Connection"
                }
                if let Some(status) = rpc_test_status() {
                    p { class: "form-hint", "{status}" }
                }
                p { class: "form-hint",
                    "Use either the cookie file OR username/password for authentication."
                }
            }

            button {
                class: "btn-analyze",
                onclick: on_submit,
                disabled: !can_submit,
                span { class: "btn-icon", "⬡" }
                "Analyze Wallet"
            }
        }
    }
}
