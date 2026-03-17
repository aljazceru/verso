use crate::config::ScanConfig;
use crate::graph::GraphView;
use crate::report::Finding;

pub mod address_reuse;
pub mod behavioral;
pub mod change_detection;
pub mod cioh;
pub mod cluster_merge;
pub mod consolidation;
pub mod dust;
pub mod dust_spending;
pub mod exchange_origin;
pub mod script_mixing;
pub mod tainted;
pub mod utxo_age;

pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn index(&self) -> u8;
    fn detect(&self, graph: &dyn GraphView, config: &ScanConfig) -> Vec<Finding>;
}

pub fn all_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(address_reuse::AddressReuseDetector),
        Box::new(cioh::CiohDetector),
        Box::new(dust::DustDetector),
        Box::new(dust_spending::DustSpendingDetector),
        Box::new(change_detection::ChangeDetectionDetector),
        Box::new(consolidation::ConsolidationDetector),
        Box::new(script_mixing::ScriptMixingDetector),
        Box::new(cluster_merge::ClusterMergeDetector),
        Box::new(utxo_age::UtxoAgeDetector),
        Box::new(exchange_origin::ExchangeOriginDetector),
        Box::new(tainted::TaintedDetector),
        Box::new(behavioral::BehavioralDetector),
    ]
}

pub fn run_all(
    detectors: &[Box<dyn Detector>],
    graph: &dyn GraphView,
    config: &ScanConfig,
) -> Vec<Finding> {
    detectors
        .iter()
        .flat_map(|d| d.detect(graph, config))
        .collect()
}
