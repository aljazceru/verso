use async_trait::async_trait;
use bdk_wallet::Wallet;
use bitcoin::{Transaction, Txid};

use crate::config::ScanProgress;
use crate::error::VersoError;

pub mod bitcoind;
pub mod esplora;

pub use bitcoind::BitcoindBackend;
pub use esplora::EsploraBackend;

#[async_trait]
pub trait ChainBackend: Send + Sync {
    async fn full_sync(
        &self,
        wallet: &mut Wallet,
        progress_tx: Option<&tokio::sync::mpsc::UnboundedSender<ScanProgress>>,
    ) -> Result<(), VersoError>;

    async fn get_tx(&self, txid: Txid) -> Result<Option<Transaction>, VersoError>;
}
