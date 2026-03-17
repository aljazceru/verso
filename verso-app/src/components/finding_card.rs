use dioxus::prelude::*;
use verso_core::report::{Finding, Severity};
use crate::components::{SeverityBadge, DetailsPanel};

#[component]
pub fn FindingCard(finding: Finding) -> Element {
    let mut expanded = use_signal(|| false);

    let sev_class = match finding.severity {
        Severity::Critical => "finding-card sev-critical",
        Severity::High     => "finding-card sev-high",
        Severity::Medium   => "finding-card sev-medium",
        Severity::Low      => "finding-card sev-low",
    };

    let card_class = if *expanded.read() {
        format!("{} expanded", sev_class)
    } else {
        sev_class.to_string()
    };

    rsx! {
        div {
            class: "{card_class}",

            div {
                class: "card-header",
                onclick: move |_| {
                    let cur = *expanded.read();
                    expanded.set(!cur);
                },
                SeverityBadge {
                    finding_type: finding.finding_type.clone(),
                    severity: finding.severity.clone(),
                }
                span { class: "card-description", "{finding.description}" }
                span { class: "chevron", "▾" }
            }

            if *expanded.read() {
                div { class: "card-body",
                    DetailsPanel { details: finding.details.clone() }

                    if let Some(ref correction) = finding.correction {
                        div { class: "correction-panel",
                            p { class: "correction-label", "How to fix" }
                            p { class: "correction-text", "{correction}" }
                        }
                    }
                }
            }
        }
    }
}
