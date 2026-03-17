use async_trait::async_trait;
use bdk_esplora::EsploraAsyncExt;
use bdk_wallet::Wallet;
use bitcoin::{Network, Transaction, Txid};

use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;

use crate::config::ScanProgress;
use crate::error::VersoError;

use super::ChainBackend;

const ESPLORA_MAX_RETRIES: usize = 3;
const ESPLORA_INITIAL_RETRY_DELAY_MS: u64 = 500;
const ESPLORA_MAX_RETRY_DELAY_MS: u64 = 4_000;

pub struct EsploraBackend {
    client: esplora_client::AsyncClient,
    #[allow(dead_code)]
    network: Network,
    derivation_limit: u32,
}

impl EsploraBackend {
    pub fn new(url: &str, network: Network, derivation_limit: u32) -> Result<Self, VersoError> {
        let client = esplora_client::Builder::new(url)
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

        // Addresses are pre-revealed to derivation_limit in Scanner::new.
        // A small stop_gap terminates scanning promptly past the revealed range.
        let stop_gap = self.derivation_limit.max(20) as usize;

        let update = retry_esplora_request(
            "full_scan",
            || {
                let request = wallet.start_full_scan().build();
                async move { self.client.full_scan(request, stop_gap, 4).await.map_err(|e| e.to_string()) }
            },
        )
        .await
        .map_err(VersoError::Esplora)?;

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
        let response = retry_esplora_request(
            "get_tx",
            || async { self.client.get_tx(&txid).await.map_err(|e| e.to_string()) },
        )
        .await;

        match response {
            Ok(tx) => Ok(tx),
            Err(msg) => {
                let msg_lower = msg.to_lowercase();
                if msg_lower.contains("not found") || msg_lower.contains("not in") {
                    Ok(None)
                } else {
                    Err(VersoError::Esplora(msg))
                }
            }
        }
    }
}

fn format_esplora_error_message(message: &str) -> String {
    let message_lower = message.to_lowercase();
    let endpoint = extract_esplora_url(message);

    if message_lower.contains("timed out") || message_lower.contains("timeout") {
        return format!(
            "Esplora request timed out while contacting {}. Check network connectivity or try another endpoint.",
            endpoint
        );
    }

    if message_lower.contains("connection refused")
        || message_lower.contains("connection reset")
        || message_lower.contains("connection aborted")
        || message_lower.contains("could not connect")
        || message_lower.contains("connection closed")
        || message_lower.contains("connection error")
    {
        return format!(
            "Could not connect to {}. Verify the URL and that outbound connections are allowed.",
            endpoint
        );
    }

    if message_lower.contains("failed to resolve") || message_lower.contains("name or service not known") {
        return format!(
            "DNS resolution failed for {}. Verify the Esplora URL and your network/DNS settings.",
            endpoint
        );
    }

    if message_lower.contains("certificate") || message_lower.contains("x509") || message_lower.contains("tls") {
        return format!(
            "TLS handshake failed when contacting {}. Check certificate and HTTPS settings.",
            endpoint
        );
    }

    if message_lower.contains("429")
        || message_lower.contains("too many requests")
        || message_lower.contains("service unavailable")
        || message_lower.contains("temporarily unavailable")
        || message_lower.contains("bad gateway")
        || message_lower.contains("gateway timeout")
        || message_lower.contains("internal server error")
    {
        return format!(
            "Esplora temporarily failed while contacting {}. Request may be retried automatically.",
            endpoint
        );
    }

    message.to_string()
}

fn is_retryable_esplora_error(message: &str) -> bool {
    let message_lower = message.to_lowercase();

    if message_lower.contains("not found") || message_lower.contains("not in") {
        return false;
    }

    message_lower.contains("timed out")
        || message_lower.contains("timeout")
        || message_lower.contains("connection refused")
        || message_lower.contains("connection reset")
        || message_lower.contains("connection aborted")
        || message_lower.contains("could not connect")
        || message_lower.contains("connection closed")
        || message_lower.contains("connection error")
        || message_lower.contains("connection reset by peer")
        || message_lower.contains("failed to resolve")
        || message_lower.contains("temporarily unavailable")
        || message_lower.contains("service unavailable")
        || message_lower.contains("gateway timeout")
        || message_lower.contains("bad gateway")
        || message_lower.contains("internal server error")
        || message_lower.contains("too many requests")
        || message_lower.contains("429")
        || message_lower.contains("408")
        || message_lower.contains("500")
        || message_lower.contains("502")
        || message_lower.contains("503")
        || message_lower.contains("504")
}

fn extract_esplora_url(message: &str) -> String {
    const URL_MARKER: &str = "url: \"";

    if let Some(start) = message.find(URL_MARKER) {
        let rest = &message[start + URL_MARKER.len()..];
        if let Some(end) = rest.find('"') {
            return rest[..end].to_string();
        }
    }

    "the configured Esplora endpoint".to_string()
}

async fn retry_esplora_request<T, E, F, Fut>(op_name: &str, mut op: F) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut attempt = 0usize;
    let mut delay = Duration::from_millis(ESPLORA_INITIAL_RETRY_DELAY_MS);

    loop {
        let result = op().await;
        match result {
            Ok(value) => return Ok(value),
            Err(err) => {
                let message = err.to_string();
                if !is_retryable_esplora_error(&message) || attempt + 1 >= ESPLORA_MAX_RETRIES {
                    return Err(format_esplora_error_message(&message));
                }

                let wait_ms = delay.as_millis();
                log::warn!(
                    "Esplora request '{}' failed (attempt {} of {}): {}. Retrying in {}ms",
                    op_name,
                    attempt + 1,
                    ESPLORA_MAX_RETRIES,
                    message,
                    wait_ms
                );

                attempt += 1;
                sleep(delay).await;
                delay = std::cmp::min(
                    delay.saturating_mul(2),
                    Duration::from_millis(ESPLORA_MAX_RETRY_DELAY_MS),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    #[test]
    fn test_esplora_backend_new_valid_url() {
        let backend = EsploraBackend::new("https://blockstream.info/api", Network::Bitcoin, 20);
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

    #[test]
    fn test_retry_classifies_timeout_message_as_retryable() {
        assert!(is_retryable_esplora_error(
            "Reqwest(reqwest::Error { kind: Request, source: timed out })"
        ));
    }

    #[test]
    fn test_retry_classifies_not_found_message_as_non_retryable() {
        assert!(!is_retryable_esplora_error("transaction not found"));
    }

    #[test]
    fn test_esplora_error_formatting_includes_timeout_hint() {
        let err = "Reqwest(reqwest::Error { kind: Request, url: \"https://mempool.space/api/scripthash/foo/txs\", source: timed out })";
        let friendly = format_esplora_error_message(err);
        assert!(friendly.contains("timed out"));
        assert!(friendly.contains("mempool.space/api/scripthash/foo/txs"));
    }
}
