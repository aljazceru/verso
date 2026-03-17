use async_trait::async_trait;
use bdk_bitcoind_rpc::{Emitter, NO_EXPECTED_MEMPOOL_TXS};
use bdk_wallet::Wallet;
use bitcoin::{Network, Transaction, Txid};
use bitcoincore_rpc::RpcApi;

use crate::config::{BitcoindAuth, ScanProgress};
use crate::error::VersoError;

use super::ChainBackend;

pub struct BitcoindBackend {
    client: bitcoincore_rpc::Client,
    #[allow(dead_code)]
    network: Network,
}

impl BitcoindBackend {
    pub fn new(url: &str, auth: &BitcoindAuth, network: Network) -> Result<Self, VersoError> {
        let rpc_auth = match auth {
            BitcoindAuth::Cookie(path) => bitcoincore_rpc::Auth::CookieFile(path.clone()),
            BitcoindAuth::UserPass { user, pass } => {
                bitcoincore_rpc::Auth::UserPass(user.clone(), pass.clone())
            }
        };
        let client = bitcoincore_rpc::Client::new(url, rpc_auth)
            .map_err(|e| VersoError::BackendConnection(e.to_string()))?;
        Ok(Self { client, network })
    }
}

#[async_trait]
impl ChainBackend for BitcoindBackend {
    async fn full_sync(
        &self,
        wallet: &mut Wallet,
        progress_tx: Option<&tokio::sync::mpsc::UnboundedSender<ScanProgress>>,
    ) -> Result<(), VersoError> {
        let checkpoint = wallet.latest_checkpoint();
        let start_height = checkpoint.height().saturating_sub(1);
        let mut emitter = Emitter::new(&self.client, checkpoint, start_height, NO_EXPECTED_MEMPOOL_TXS);

        let mut blocks_processed: u64 = 0;
        while let Some(block_event) = emitter
            .next_block()
            .map_err(|e| VersoError::Rpc(e.to_string()))?
        {
            wallet
                .apply_block(&block_event.block, block_event.block_height())
                .map_err(|e| VersoError::Wallet(e.to_string()))?;
            blocks_processed += 1;

            if let Some(tx) = progress_tx {
                let _ = tx.send(ScanProgress {
                    phase: "sync".to_string(),
                    message: format!(
                        "Applied block at height {}",
                        block_event.block_height()
                    ),
                    percent: None,
                });
            }
        }

        log::debug!("BitcoindBackend: synced {} blocks", blocks_processed);

        // Apply mempool transactions
        let mempool_event = emitter
            .mempool()
            .map_err(|e| VersoError::Rpc(e.to_string()))?;
        wallet.apply_unconfirmed_txs(
            mempool_event
                .update
                .iter()
                .map(|(tx, time)| (tx.clone(), *time)),
        );

        if let Some(tx) = progress_tx {
            let _ = tx.send(ScanProgress {
                phase: "sync".to_string(),
                message: format!(
                    "Mempool: {} transactions",
                    mempool_event.update.len()
                ),
                percent: Some(100.0),
            });
        }

        Ok(())
    }

    async fn get_tx(&self, txid: Txid) -> Result<Option<Transaction>, VersoError> {
        match self.client.get_raw_transaction(&txid, None) {
            Ok(tx) => Ok(Some(tx)),
            Err(_) => Ok(None),
        }
    }
}
