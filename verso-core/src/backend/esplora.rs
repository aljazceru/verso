use async_trait::async_trait;
use bdk_esplora::EsploraAsyncExt;
use bdk_wallet::Wallet;
use bitcoin::{Network, Transaction, Txid};

use crate::config::ScanProgress;
use crate::error::VersoError;

use super::ChainBackend;

pub struct EsploraBackend {
    client: bdk_esplora::esplora_client::AsyncClient,
    #[allow(dead_code)]
    network: Network,
    derivation_limit: u32,
}

impl EsploraBackend {
    pub fn new(url: &str, network: Network, derivation_limit: u32) -> Result<Self, VersoError> {
        let client = bdk_esplora::esplora_client::Builder::new(url)
            .build_async()
            .map_err(|e| VersoError::BackendConnection(e.to_string()))?;
        Ok(Self {
            client,
            network,
            derivation_limit,
        })
    }
}

#[async_trait]
impl ChainBackend for EsploraBackend {
    async fn full_sync(
        &self,
        wallet: &mut Wallet,
        progress_tx: Option<&tokio::sync::mpsc::UnboundedSender<ScanProgress>>,
    ) -> Result<(), VersoError> {
        if let Some(tx) = progress_tx {
            let _ = tx.send(ScanProgress {
                phase: "sync".to_string(),
                message: "Starting Esplora full scan".to_string(),
                percent: Some(0.0),
            });
        }

        let stop_gap = self.derivation_limit as usize;
        let request = wallet.start_full_scan().build();
        let update = self
            .client
            .full_scan(request, stop_gap, 4)
            .await
            .map_err(|e| VersoError::Esplora(e.to_string()))?;

        wallet
            .apply_update(update)
            .map_err(|e| VersoError::Wallet(e.to_string()))?;

        if let Some(tx) = progress_tx {
            let _ = tx.send(ScanProgress {
                phase: "sync".to_string(),
                message: "Esplora full scan complete".to_string(),
                percent: Some(100.0),
            });
        }

        Ok(())
    }

    async fn get_tx(&self, txid: Txid) -> Result<Option<Transaction>, VersoError> {
        match self.client.get_tx(&txid).await {
            Ok(tx) => Ok(tx),
            Err(_) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    #[test]
    fn test_esplora_backend_new_valid_url() {
        let backend = EsploraBackend::new(
            "https://blockstream.info/api",
            Network::Bitcoin,
            20,
        );
        assert!(
            backend.is_ok(),
            "EsploraBackend::new should succeed with a valid URL"
        );
    }

    #[test]
    fn test_esplora_backend_stores_derivation_limit() {
        let backend =
            EsploraBackend::new("https://mempool.space/testnet/api", Network::Testnet, 50)
                .expect("should construct");
        assert_eq!(
            backend.derivation_limit, 50,
            "derivation_limit should be stored"
        );
    }

    #[test]
    fn test_esplora_backend_stores_network() {
        let backend =
            EsploraBackend::new("https://mempool.space/testnet/api", Network::Testnet, 20)
                .expect("should construct");
        assert_eq!(backend.network, Network::Testnet);
    }
}
