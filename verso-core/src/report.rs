use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub warnings: Vec<Finding>,
    pub stats: Stats,
    pub summary: Summary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stats {
    pub total_txs: usize,
    pub total_addresses: usize,
    pub total_utxos: usize,
    pub finding_count: usize,
    pub warning_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub clean: bool,
    pub risk_level: Severity,
    pub top_issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub finding_type: FindingType,
    pub severity: Severity,
    pub description: String,
    pub details: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correction: Option<String>,
    #[serde(skip)]
    pub category: FindingCategory,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingType {
    AddressReuse,
    Cioh,
    Dust,
    DustSpending,
    ChangeDetection,
    Consolidation,
    ScriptTypeMixing,
    ClusterMerge,
    UtxoAgeSpread,
    DormantUtxos,
    ExchangeOrigin,
    TaintedUtxoMerge,
    DirectTaint,
    BehavioralFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum FindingCategory {
    #[default]
    Finding,
    Warning,
}
