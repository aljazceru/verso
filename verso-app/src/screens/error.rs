use dioxus::prelude::*;
use crate::state::Screen;

#[component]
pub fn ErrorView(
    screen: Signal<Screen>,
    scan_error: Signal<Option<String>>,
) -> Element {
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
    if msg.contains("descriptor parse") || msg.contains("DescriptorParse") {
        "Check that the descriptor is valid. Bare extended keys (xpub/zpub/tpub) are accepted."
    } else if msg.contains("connect") || msg.contains("Connection") || msg.contains("connection") {
        "Verify your node is running and the URL/port are correct."
    } else if msg.contains("auth") || msg.contains("cookie") || msg.contains("401") {
        "Authentication failed. Check your cookie file path or username/password."
    } else if msg.contains("network") || msg.contains("Network") {
        "Network mismatch — make sure the selected network matches your node."
    } else {
        ""
    }
}
