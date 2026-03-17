use dioxus::prelude::*;
use crate::state::Screen;
use crate::components::{FindingCard, SummaryBar};

#[component]
pub fn ReportView(
    screen: Signal<Screen>,
    report: Signal<Option<verso_core::report::Report>>,
) -> Element {
    let r = report();

    rsx! {
        div { class: "report-view",
            if let Some(ref rep) = r {
                // ── Header
                div { class: "report-header",
                    div { class: "report-title-group",
                        h2 { "Scan Report" }
                        p {
                            if rep.summary.clean {
                                "No privacy issues detected"
                            } else {
                                "Privacy vulnerabilities found"
                            }
                        }
                    }
                    button {
                        class: "btn-secondary",
                        onclick: move |_| screen.set(Screen::Input),
                        "↩ New Scan"
                    }
                }

                // ── Status banner
                if rep.summary.clean {
                    div { class: "clean-banner", "✓ Clean — wallet follows good privacy practices" }
                } else {
                    {
                        let n = rep.summary.findings;
                        let s = if n == 1 { "" } else { "s" };
                        rsx! {
                            div { class: "issues-banner",
                                "⚠ {n} finding{s} requiring attention"
                            }
                        }
                    }
                }

                // ── Stats bar
                SummaryBar { report: rep.clone() }

                // ── Findings
                if !rep.findings.is_empty() {
                    div {
                        div { class: "section-header",
                            "Findings"
                            span { class: "section-count", "{rep.findings.len()}" }
                        }
                        div { class: "findings-list",
                            for finding in rep.findings.iter().cloned() {
                                FindingCard { finding }
                            }
                        }
                    }
                }

                // ── Warnings
                if !rep.warnings.is_empty() {
                    div {
                        div { class: "section-header",
                            "Warnings"
                            span { class: "section-count", "{rep.warnings.len()}" }
                        }
                        div { class: "warnings-list",
                            for warning in rep.warnings.iter().cloned() {
                                FindingCard { finding: warning }
                            }
                        }
                    }
                }

                if rep.findings.is_empty() && rep.warnings.is_empty() {
                    p { class: "no-issues", "No findings or warnings." }
                }
            } else {
                p { class: "no-issues", "No report available." }
            }
        }
    }
}
