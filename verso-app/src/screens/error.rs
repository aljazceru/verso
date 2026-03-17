use crate::state::Screen;
use dioxus::prelude::*;

#[component]
pub fn ErrorView(screen: Signal<Screen>, scan_error: Signal<Option<String>>) -> Element {
    let error_msg = scan_error().unwrap_or_else(|| "Unknown error".to_string());

    let hint = error_hint(&error_msg);

    rsx! {
        div { class: "error-view",
            p { class: "error-header", "Scan Failed" }

            div { class: "error-message-box",
                "{error_msg}"
            }

            if !hint.is_empty() {
                p { class: "error-hint", "{hint}" }
            }

            div { class: "error-actions",
                button {
                    class: "btn-retry",
                    onclick: move |_| screen.set(Screen::Input),
                    "↩ Try Again"
                }
                button {
                    class: "btn-secondary",
                    onclick: move |_| {
                        scan_error.set(None);
                        screen.set(Screen::Input);
                    },
                    "New Scan"
                }
            }
        }
    }
}

fn error_hint(msg: &str) -> &'static str {
    let msg = msg.to_lowercase();

    if msg.contains("descriptor parse") || msg.contains("descriptorparse") {
        "Check that the descriptor is valid. Bare extended keys (xpub/zpub/tpub) are accepted."
    } else if msg.contains("timed out") || msg.contains("timeout") {
        "Esplora request timed out. Verify your network connectivity and retry."
    } else if msg.contains("too many requests")
        || msg.contains("rate limit")
        || msg.contains("service unavailable")
        || msg.contains("temporarily unavailable")
    {
        "Esplora rate-limited or temporarily unavailable. Retry with a shorter scan frequency."
    } else if msg.contains("connect") || msg.contains("connection") {
        "Verify your node is running and the URL/port are correct."
    } else if msg.contains("auth") || msg.contains("cookie") || msg.contains("401") {
        "Authentication failed. Check your cookie file path or username/password."
    } else if msg.contains("network") {
        "Network mismatch — make sure the selected network matches your node."
    } else {
        ""
    }
}
