use std::collections::HashSet;

use serde_json::json;

use crate::config::ScanConfig;
use crate::graph::GraphView;
use crate::report::{Finding, FindingCategory, FindingType, Severity};

use super::Detector;

pub struct ExchangeOriginDetector;

const BATCH_THRESHOLD: usize = 5;

impl Detector for ExchangeOriginDetector {
    fn name(&self) -> &'static str {
        "exchange_origin"
    }

    fn index(&self) -> u8 {
        10
    }

    fn detect(&self, graph: &dyn GraphView, config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        for txid in graph.our_txids() {
            let tx = match graph.fetch_tx(txid) {
                Some(t) => t,
                None => continue,
            };

            if tx.input.is_empty() || tx.input.iter().all(|inp| inp.previous_output.is_null()) {
                continue;
            }

            // Check if we receive in this tx (have outputs, no inputs that are ours)
            let inputs = graph.input_addresses(txid);
            let our_inputs: Vec<_> = inputs.iter().filter(|i| i.is_ours).collect();
            if !our_inputs.is_empty() {
                // We are a sender here — skip
                continue;
            }

            let outputs = graph.output_addresses(txid);
            let our_outputs: Vec<_> = outputs.iter().filter(|o| o.is_ours).collect();
            if our_outputs.is_empty() {
                continue;
            }

            // Now evaluate signals on this receive tx
            let mut signals: Vec<String> = Vec::new();

            // Signal 1: Output count >= 5
            if tx.output.len() >= BATCH_THRESHOLD {
                signals.push("high_output_count".to_string());
            }

            // Signal 2: Unique recipient address count >= 5
            let unique_addrs: HashSet<_> =
                outputs.iter().filter_map(|o| o.address.as_ref()).collect();
            if unique_addrs.len() >= BATCH_THRESHOLD {
                signals.push("many_recipients".to_string());
            }

            // Signal 3: large batch payment (>= 10 outputs)
            let n_outputs = tx.output.len();
            if n_outputs >= 10 {
                signals.push("batch_payment".to_string());
            }

            // Signal 4: Known exchange txid
            if let Some(known) = &config.known_exchange_txids {
                if known.contains(&txid) {
                    signals.push("known_exchange_txid".to_string());
                }
            }

            if signals.len() >= 2 {
                findings.push(Finding {
                    finding_type: FindingType::ExchangeOrigin,
                    severity: Severity::Medium,
                    description: format!(
                        "TX {} looks like an exchange batch withdrawal ({} signal(s))",
                        txid,
                        signals.len()
                    ),
                    details: json!({
                        "txid": txid.to_string(),
                        "signals": signals,
                    }),
                    correction: Some(
                        "Withdraw via Lightning Network instead of on-chain to avoid the \
                         exchange-origin fingerprint entirely. If an on-chain withdrawal is \
                         required, request it at a non-standard time or amount to reduce \
                         correlation with a specific batch. After withdrawal, pass the UTXO \
                         through a CoinJoin before using it for other payments, so the exchange \
                         link is severed from your subsequent spending history."
                            .to_string(),
                    ),
                    category: FindingCategory::Finding,
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        hashes::Hash,
        key::{Secp256k1, UntweakedKeypair},
        secp256k1::rand,
        Address, Network, Txid, XOnlyPublicKey,
    };

    use super::*;
    use crate::config::{BackendConfig, ScanConfig};
    use crate::graph::MockGraphBuilder;
    use crate::report::FindingType;

    fn test_config() -> ScanConfig {
        ScanConfig {
            descriptors: vec![],
            network: Network::Regtest,
            backend: BackendConfig::Esplora {
                url: "http://localhost".to_string(),
            },
            known_risky_txids: None,
            known_exchange_txids: None,
            derivation_limit: 1000,
            data_dir: None,
            ephemeral: true,
            progress_tx: None,
        }
    }

    fn make_txid(n: u8) -> Txid {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        Txid::from_byte_array(bytes)
    }

    fn p2tr_addr() -> Address {
        let secp = Secp256k1::new();
        let kp = UntweakedKeypair::new(&secp, &mut rand::thread_rng());
        let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
        Address::p2tr(&secp, xonly, None, Network::Regtest)
    }

    #[test]
    fn test_no_finding_when_no_txs() {
        let graph = MockGraphBuilder::new().build();
        let config = test_config();
        let findings = ExchangeOriginDetector.detect(&graph, &config);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_simple_receive() {
        // Simple receive with only 1 output — not an exchange batch
        let our_addr = p2tr_addr();
        let txid = make_txid(1);
        let graph = MockGraphBuilder::new()
            .with_address(our_addr.clone())
            .with_receive_tx(txid, our_addr.clone(), 100_000)
            .build();
        let config = test_config();
        let findings = ExchangeOriginDetector.detect(&graph, &config);
        // Only 1 output, 1 recipient => 0 signals => no finding
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_if_we_are_sender() {
        // If we have our own inputs, we're the sender, not the receiver
        let our_addr = p2tr_addr();
        let ext_addr = p2tr_addr();
        let recv_txid = make_txid(1);
        let spend_txid = make_txid(2);
        let graph = MockGraphBuilder::new()
            .with_address(our_addr.clone())
            .with_receive_tx(recv_txid, our_addr.clone(), 500_000)
            .with_spend_tx(
                spend_txid,
                vec![(recv_txid, 0, 500_000)],
                // Many outputs but we're the sender
                vec![
                    (ext_addr.clone(), 100_000, false),
                    (p2tr_addr(), 100_000, false),
                    (p2tr_addr(), 100_000, false),
                    (p2tr_addr(), 100_000, false),
                    (p2tr_addr(), 100_000, false),
                ],
            )
            .build();
        let config = test_config();
        let findings = ExchangeOriginDetector.detect(&graph, &config);
        // spend_txid: we have our input => skip it
        // recv_txid: only 1 output => 0 signals
        assert!(findings.is_empty());
    }

    #[test]
    fn test_known_exchange_txid_contributes_signal() {
        use std::collections::HashSet;
        // 1 known exchange txid signal + we need 1 more. Let's add high output count signal.
        // We'll build a receive tx with 5+ outputs manually.
        let our_addr = p2tr_addr();
        let txid = make_txid(42);

        // Build a receive tx that has our addr as output 0, plus 4 more outputs
        let ext_addrs: Vec<Address> = (0..4).map(|_| p2tr_addr()).collect();
        let all_outputs: Vec<(Address, u64, bool)> =
            std::iter::once((our_addr.clone(), 100_000, false))
                .chain(ext_addrs.iter().map(|a| (a.clone(), 100_000, false)))
                .collect();

        // Use with_spend_tx but with empty inputs to simulate a pure receive from exchange
        // (no "ours" in inputs since we don't register the ext input addr)
        let graph = MockGraphBuilder::new()
            .with_address(our_addr.clone())
            .with_spend_tx(txid, vec![], all_outputs)
            .build();

        let mut known = HashSet::new();
        known.insert(txid);
        let config = ScanConfig {
            known_exchange_txids: Some(known),
            ..test_config()
        };

        let findings = ExchangeOriginDetector.detect(&graph, &config);
        // Signals: high_output_count (5 outputs) + known_exchange_txid + many_recipients (5 unique)
        // => >= 2 signals => finding
        assert!(!findings.is_empty(), "Expected exchange origin finding");
        assert_eq!(findings[0].finding_type, FindingType::ExchangeOrigin);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].category, FindingCategory::Finding);
        assert!(findings[0].correction.is_some());
    }

    #[test]
    fn test_exchange_finding_with_high_output_count() {
        // Build a tx: 6 outputs + many unique recipients — triggers high_output_count and many_recipients
        let our_addr = p2tr_addr();
        let txid = make_txid(10);

        let ext_addrs: Vec<Address> = (0..5).map(|_| p2tr_addr()).collect();
        let all_outputs: Vec<(Address, u64, bool)> =
            std::iter::once((our_addr.clone(), 100_000, false))
                .chain(ext_addrs.iter().map(|a| (a.clone(), 100_000, false)))
                .collect();

        // Empty input list means our_inputs is empty (we are receiver, not sender).
        let graph = MockGraphBuilder::new()
            .with_address(our_addr.clone())
            .with_spend_tx(txid, vec![], all_outputs)
            .build();

        let config = test_config();
        let findings = ExchangeOriginDetector.detect(&graph, &config);
        // Signals: high_output_count (6 >= 5), many_recipients (6 unique >= 5) => 2 signals => finding
        assert!(!findings.is_empty(), "Expected exchange origin finding");
        let f = &findings[0];
        assert_eq!(f.finding_type, FindingType::ExchangeOrigin);
        let signals = f.details["signals"].as_array().unwrap();
        assert!(signals.len() >= 2);
    }
}
