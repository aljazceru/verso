use async_trait::async_trait;
use bdk_bitcoind_rpc::{Emitter, NO_EXPECTED_MEMPOOL_TXS};
use bdk_wallet::Wallet;
use bitcoin::{Network, Transaction, Txid};
use bitcoincore_rpc::RpcApi;

use crate::config::{BitcoindAuth, ScanProgress};
use crate::error::VersoError;

use super::ChainBackend;

const BLOCK_PROGRESS_INTERVAL: u64 = 100;

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

pub fn test_bitcoind_connection(url: &str, auth: &BitcoindAuth) -> Result<String, VersoError> {
    let rpc_auth = match auth {
        BitcoindAuth::Cookie(path) => bitcoincore_rpc::Auth::CookieFile(path.clone()),
        BitcoindAuth::UserPass { user, pass } => {
            bitcoincore_rpc::Auth::UserPass(user.clone(), pass.clone())
        }
    };

    let client = bitcoincore_rpc::Client::new(url, rpc_auth)
        .map_err(|e| VersoError::BackendConnection(e.to_string()))?;
    client
        .get_blockchain_info()
        .map_err(|e| VersoError::Rpc(e.to_string()))?;

    Ok("Connected to Bitcoin RPC".to_string())
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
        let tip_height = self
            .client
            .get_block_count()
            .map_err(|e| VersoError::Rpc(e.to_string()))?;
        let mut emitter = Emitter::new(
            &self.client,
            checkpoint,
            start_height,
            NO_EXPECTED_MEMPOOL_TXS,
        );

        if let Some(tx) = progress_tx {
            let _ = tx.send(ScanProgress {
                phase: "sync".to_string(),
                message: format!(
                    "Scanning Bitcoin Core blocks from height {} to {}",
                    start_height.saturating_add(1),
                    tip_height
                ),
                percent: Some(0.0),
            });
        }

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
                let current_height = block_event.block_height() as u64;
                let blocks_total = tip_height
                    .saturating_sub(start_height as u64)
                    .max(1);
                let blocks_done = current_height
                    .saturating_sub(start_height as u64)
                    .min(blocks_total);
                let should_report = blocks_processed == 1
                    || blocks_processed % BLOCK_PROGRESS_INTERVAL == 0
                    || current_height >= tip_height;

                if should_report {
                    let percent = ((blocks_done as f32 / blocks_total as f32) * 100.0).min(100.0);
                    let _ = tx.send(ScanProgress {
                        phase: "sync".to_string(),
                        message: format!(
                            "Processed {} blocks, at height {}/{}",
                            blocks_processed, current_height, tip_height
                        ),
                        percent: Some(percent),
                    });
                }
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
                message: format!("Mempool: {} transactions", mempool_event.update.len()),
                percent: Some(100.0),
            });
        }

        Ok(())
    }

    async fn get_tx(&self, txid: Txid) -> Result<Option<Transaction>, VersoError> {
        match self.client.get_raw_transaction(&txid, None) {
            Ok(tx) => Ok(Some(tx)),
            Err(err) => {
                let msg = err.to_string().to_lowercase();
                if msg.contains("no such mempool transaction")
                    || msg.contains("no such transaction")
                    || msg.contains("not found")
                {
                    Ok(None)
                } else {
                    Err(VersoError::Rpc(err.to_string()))
                }
            }
        }
    }
}
