use dioxus::prelude::*;
use verso_core::report::Report;

#[component]
pub fn SummaryBar(report: Report) -> Element {
    rsx! {
        div { class: "summary-bar",
            div { class: "stat-card stat-findings",
                span { class: "stat-number", "{report.findings.len()}" }
                span { class: "stat-label", "Findings" }
            }
            div { class: "stat-card stat-warnings",
                span { class: "stat-number", "{report.warnings.len()}" }
                span { class: "stat-label", "Warnings" }
            }
            div { class: "stat-card stat-txs",
                span { class: "stat-number", "{report.stats.transactions_analyzed}" }
                span { class: "stat-label", "Transactions" }
            }
        }
    }
}
