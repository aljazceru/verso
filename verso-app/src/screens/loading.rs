use crate::state::Screen;
use dioxus::prelude::*;

#[component]
pub fn LoadingView(
    screen: Signal<Screen>,
    // Accumulated log messages pushed directly by the scan task.
    // Reading this signal in the render body means any push triggers a re-render.
    log: Signal<Vec<String>>,
    descriptor: Signal<String>,
) -> Element {
    let desc = descriptor();
    let short_desc = if desc.len() > 72 {
        format!("{}…{}", &desc[..36], &desc[desc.len() - 20..])
    } else {
        desc.clone()
    };

    let lines = log.read();

    rsx! {
        div { class: "loading-view",
            div { class: "loading-header",
                p { class: "loading-title", "Scanning" }
                p { class: "loading-descriptor", "{short_desc}" }
            }

            div { class: "scan-progress-bar",
                div { class: "scan-progress-fill" }
            }

            div {
                id: "scan-log",
                class: "log-container",

                if lines.is_empty() {
                    div { class: "log-line",
                        span { class: "log-phase", "init" }
                        span { "Starting…" }
                    }
                }

                for line in lines.iter() {
                    {
                        let (phase, rest) = parse_log_line(line);
                        rsx! {
                            div { class: "log-line",
                                span { class: "log-phase", "{phase}" }
                                span { "{rest}" }
                            }
                        }
                    }
                }

                // Blinking cursor always at the bottom
                div { class: "log-line",
                    span { class: "log-cursor" }
                }
            }
        }
    }
}

/// Split `"[phase] message"` into `("phase", "message")`.
fn parse_log_line(line: &str) -> (&str, &str) {
    if let Some(rest) = line.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            let phase = &rest[..close];
            let msg = rest[close + 1..].trim_start_matches(' ');
            return (phase, msg);
        }
    }
    ("info", line)
}
