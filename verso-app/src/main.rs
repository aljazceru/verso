use dioxus::prelude::*;

mod components;
mod screens;
mod state;

const APP_HEAD: &str = concat!(
    r#"
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="anonymous">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,400;0,500;0,600;0,700;0,800;1,400&display=swap">
    <style>
    "#,
    include_str!("../assets/style.css"),
    r#"
    </style>
"#
);

fn main() {
    if cfg!(target_arch = "wasm32") {
        dioxus::launch(app);
    } else {
        dioxus::LaunchBuilder::desktop()
            .with_cfg(
                dioxus_desktop::Config::new()
                    .with_background_color((11, 12, 25, 255))
                    .with_custom_head(APP_HEAD.to_string()),
            )
            .launch(app);
    }
}

fn app() -> Element {
    let screen = use_signal(|| state::Screen::Input);
    let descriptor = use_signal(String::new);
    let report = use_signal(|| Option::<verso_core::report::Report>::None);
    let scan_error = use_signal(|| Option::<String>::None);
    // Vec<String> log — pushed directly from the background task.
    // No use_effect middleman, so no message is ever dropped.
    let log: Signal<Vec<String>> = use_signal(Vec::new);
    let mut dark_mode = use_signal(|| true);

    let theme = if dark_mode() { "dark" } else { "light" };
    let toggle_icon = if dark_mode() { "☀" } else { "◐" };
    let toggle_label = if dark_mode() { "LIGHT" } else { "DARK" };

    let status_text = match screen() {
        state::Screen::Input => "",
        state::Screen::Loading => "SCANNING",
        state::Screen::Report => "COMPLETE",
        state::Screen::Error => "ERROR",
    };

    rsx! {
        if cfg!(target_arch = "wasm32") {
            document::Link {
                rel: "stylesheet",
                href: "https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,400;0,500;0,600;0,700;0,800;1,400&display=swap"
            }
            document::Stylesheet {
                href: asset!("/assets/style.css")
            }
        }

        div {
            class: "app",
            "data-theme": theme,

            header { class: "app-header",
                div { class: "app-logo",
                    "₿ VERSO"
                    span { "Bitcoin Privacy Auditor" }
                }
                div { class: "header-right",
                    div { class: "header-status",
                        "{status_text}"
                    }
                    button {
                        class: "theme-toggle",
                        onclick: move |_| dark_mode.set(!dark_mode()),
                        span { class: "theme-toggle-icon", "{toggle_icon}" }
                        "{toggle_label}"
                    }
                    div { class: "app-version", "v0.1.0" }
                }
            }

            main { class: "app-main",
                match screen() {
                    state::Screen::Input => rsx! {
                        screens::input::InputView {
                            screen, descriptor, report, scan_error, log,
                        }
                    },
                    state::Screen::Loading => rsx! {
                        screens::loading::LoadingView {
                            screen, log, descriptor,
                        }
                    },
                    state::Screen::Report => rsx! {
                        screens::report::ReportView { screen, report }
                    },
                    state::Screen::Error => rsx! {
                        screens::error::ErrorView { screen, scan_error }
                    },
                }
            }
        }
    }
}
