use crate::state::Screen;
use dioxus::core::spawn_forever;
use dioxus::prelude::*;
use verso_core::config::{BackendConfig, BitcoindAuth, ScanConfig};
use std::path::PathBuf;

#[component]
pub fn InputView(
    screen: Signal<Screen>,
    descriptor: Signal<String>,
    report: Signal<Option<verso_core::report::Report>>,
    scan_error: Signal<Option<String>>,
    log: Signal<Vec<String>>,
) -> Element {
    let mut network = use_signal(|| "mainnet".to_string());
    let mut backend_type = use_signal(|| "bitcoind".to_string());
    let mut esplora_url = use_signal(|| "https://mempool.space/api".to_string());
    let mut bitcoind_url = use_signal(|| "http://127.0.0.1:8332".to_string());
    let mut bitcoind_cookie = use_signal(String::new);
    let mut bitcoind_user = use_signal(String::new);
    let mut bitcoind_pass = use_signal(String::new);

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

        // Reset prior results before switching screens.
        log.write().clear();
        report.set(None);
        scan_error.set(None);
        screen.set(Screen::Loading);

        let mut screen_s = screen;
        let mut report_s = report;
        let mut error_s = scan_error;
        let mut log_s = log;

        // This task must outlive InputView because the component is dropped as
        // soon as we switch to Loading.
        spawn_forever(async move {
            let scan_fut = verso_core::scan(config);
            tokio::pin!(scan_fut);

            // Drive the scan and drain progress messages as they arrive.
            // Each push to log_s immediately updates the LoadingView because
            // that component reads log_s during render — no use_effect needed.
            let result = loop {
                tokio::select! {
                    result = &mut scan_fut => break result,
                    msg = progress_rx.recv() => {
                        if let Some(p) = msg {
                            log_s.write().push(format!("[{}] {}", p.phase, p.message));
                        }
                    }
                }
            };

            // Drain any messages that arrived between the last yield and completion.
            while let Ok(p) = progress_rx.try_recv() {
                log_s.write().push(format!("[{}] {}", p.phase, p.message));
            }

            match result {
                Ok(r) => {
                    report_s.set(Some(r));
                    screen_s.set(Screen::Report);
                }
                Err(e) => {
                    error_s.set(Some(e.to_string()));
                    screen_s.set(Screen::Error);
                }
            }
        });
    };

    let can_submit = !descriptor().trim().is_empty();

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
