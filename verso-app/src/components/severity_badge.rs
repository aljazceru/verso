use dioxus::prelude::*;
use verso_core::report::{FindingType, Severity};

#[component]
pub fn SeverityBadge(finding_type: FindingType, severity: Severity) -> Element {
    let label = badge_label(&finding_type);
    let sev_class = match severity {
        Severity::Low => "badge severity-low",
        Severity::Medium => "badge severity-medium",
        Severity::High => "badge severity-high",
        Severity::Critical => "badge severity-critical",
    };
    rsx! {
        span { class: "{sev_class}", "{label}" }
    }
}

fn badge_label(ft: &FindingType) -> &'static str {
    match ft {
        FindingType::AddressReuse => "Addr Reuse",
        FindingType::Cioh => "CIOH",
        FindingType::Dust => "Dust",
        FindingType::DustSpending => "Dust Spending",
        FindingType::ChangeDetection => "Change",
        FindingType::Consolidation => "Consolidation",
        FindingType::ScriptTypeMixing => "Script Mix",
        FindingType::ClusterMerge => "Cluster Merge",
        FindingType::UtxoAgeSpread => "UTXO Age",
        FindingType::DormantUtxos => "Dormant",
        FindingType::ExchangeOrigin => "Exchange",
        FindingType::TaintedUtxoMerge => "Tainted",
        FindingType::DirectTaint => "Direct Taint",
        FindingType::BehavioralFingerprint => "Behavioral",
    }
}
