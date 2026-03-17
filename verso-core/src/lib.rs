pub mod backend;
pub mod config;
pub mod detectors;
pub mod error;
pub mod graph;
pub mod report;
pub mod storage;
pub(crate) mod scanner;

pub use backend::ChainBackend;
pub use config::ScanConfig;
pub use error::VersoError;
pub use graph::{GraphView, InputInfo, MockGraphBuilder, MockWalletGraph, OutputInfo, ScriptType, WalletGraph};
pub use report::Report;

pub async fn scan(_config: ScanConfig) -> Result<Report, VersoError> {
    todo!("scan not yet implemented")
}
