pub mod config;
pub mod error;
pub mod report;
pub mod storage;
pub(crate) mod scanner;

pub use config::ScanConfig;
pub use error::VersoError;
pub use report::Report;

pub async fn scan(_config: ScanConfig) -> Result<Report, VersoError> {
    todo!("scan not yet implemented")
}
