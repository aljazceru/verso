use serde_json::json;

use crate::config::ScanConfig;
use crate::graph::GraphView;
use crate::report::{Finding, FindingCategory, FindingType, Severity};

use super::Detector;

/// Minimum number of inputs for a transaction to be considered a consolidation.
const CONSOLIDATION_INPUT_THRESHOLD: usize = 3;
/// Maximum number of outputs for a transaction to still be considered a consolidation.
const CONSOLIDATION_OUTPUT_THRESHOLD: usize = 2;

pub struct ConsolidationDetector;

impl Detector for ConsolidationDetector {
    fn name(&self) -> &'static str {
        "consolidation"
    }

    fn index(&self) -> u8 {
        6
    }

    fn detect(&self, graph: &dyn GraphView, _config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();
        // Track which txids we've already reported to avoid duplicates
        let mut seen: std::collections::HashSet<bitcoin::Txid> = std::collections::HashSet::new();

        for utxo in graph.utxos() {
            let parent_txid = utxo.txid;

            // Fetch the transaction that created this UTXO
            let tx = match graph.fetch_tx(parent_txid) {
                Some(t) => t,
                None => continue,
            };

            let n_in = tx.input.len();
            let n_out = tx.output.len();

            if n_in >= CONSOLIDATION_INPUT_THRESHOLD && n_out <= CONSOLIDATION_OUTPUT_THRESHOLD {
                if !seen.insert(parent_txid) {
                    continue; // already reported this consolidation tx
                }

                let inputs = graph.input_addresses(parent_txid);
                let our_inputs_count = inputs.iter().filter(|i| i.is_ours).count();

                findings.push(Finding {
                    finding_type: FindingType::Consolidation,
                    severity: Severity::Medium,
                    description: "Wallet performed consolidation transaction".to_string(),
                    details: json!({
                        "txid": parent_txid.to_string(),
                        "input_count": n_in,
                        "output_count": n_out,
                        "our_inputs_in_consolidation": our_inputs_count,
                    }),
                    correction: Some(
                        "Avoid consolidating many UTXOs into one in a single transaction, as it \
                         permanently links all those addresses under CIOH. If fee savings require \
                         consolidation, do it during a period of low fees and through a CoinJoin \
                         (e.g., Whirlpool or JoinMarket) so the link between inputs is \
                         indistinguishable from other participants. Consider keeping UTXOs separate \
                         and using coin selection strategies that minimize on-chain footprint."
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
    use bitcoin::Network;

    use super::*;
    use crate::config::{BackendConfig, ScanConfig};
    use crate::graph::MockGraphBuilder;

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

    fn make_txid(n: u8) -> bitcoin::Txid {
        use bitcoin::hashes::Hash;
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        bitcoin::Txid::from_byte_array(bytes)
    }

    fn regtest_p2tr_address() -> bitcoin::Address {
        use bitcoin::{
            key::{Secp256k1, UntweakedKeypair},
            secp256k1::rand,
            XOnlyPublicKey,
        };
        let secp = Secp256k1::new();
        let keypair = UntweakedKeypair::new(&secp, &mut rand::thread_rng());
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        bitcoin::Address::p2tr(&secp, xonly, None, Network::Regtest)
    }

    #[test]
    fn test_detects_consolidation_3_inputs_1_output() {
        let addr1 = regtest_p2tr_address();
        let addr2 = regtest_p2tr_address();
        let addr3 = regtest_p2tr_address();
        let out_addr = regtest_p2tr_address();

        let recv1 = make_txid(1);
        let recv2 = make_txid(2);
        let recv3 = make_txid(3);
        let consolidation_txid = make_txid(4);

        let graph = MockGraphBuilder::new()
            .with_address(addr1.clone())
            .with_address(addr2.clone())
            .with_address(addr3.clone())
            .with_address(out_addr.clone())
            .with_receive_tx(recv1, addr1.clone(), 100_000)
            .with_receive_tx(recv2, addr2.clone(), 200_000)
            .with_receive_tx(recv3, addr3.clone(), 300_000)
            .with_spend_tx(
                consolidation_txid,
                vec![
                    (recv1, 0, 100_000),
                    (recv2, 0, 200_000),
                    (recv3, 0, 300_000),
                ],
                vec![(out_addr.clone(), 595_000, false)],
            )
            // UTXO created by the consolidation tx
            .with_utxo(consolidation_txid, 0, out_addr.clone(), 595_000, 6)
            .build();

        let config = test_config();
        let findings = ConsolidationDetector.detect(&graph, &config);

        assert!(!findings.is_empty(), "Expected consolidation finding");
        assert_eq!(findings[0].finding_type, FindingType::Consolidation);
        assert_eq!(findings[0].severity, Severity::Medium);

        let details = &findings[0].details;
        assert_eq!(details["input_count"].as_u64().unwrap(), 3);
        assert_eq!(details["output_count"].as_u64().unwrap(), 1);
    }

    #[test]
    fn test_no_consolidation_when_only_2_inputs() {
        let addr1 = regtest_p2tr_address();
        let addr2 = regtest_p2tr_address();
        let out_addr = regtest_p2tr_address();

        let recv1 = make_txid(1);
        let recv2 = make_txid(2);
        let spend_txid = make_txid(3);

        let graph = MockGraphBuilder::new()
            .with_address(addr1.clone())
            .with_address(addr2.clone())
            .with_address(out_addr.clone())
            .with_receive_tx(recv1, addr1.clone(), 100_000)
            .with_receive_tx(recv2, addr2.clone(), 200_000)
            .with_spend_tx(
                spend_txid,
                vec![(recv1, 0, 100_000), (recv2, 0, 200_000)],
                vec![(out_addr.clone(), 295_000, false)],
            )
            .with_utxo(spend_txid, 0, out_addr.clone(), 295_000, 3)
            .build();

        let config = test_config();
        let findings = ConsolidationDetector.detect(&graph, &config);
        assert!(findings.is_empty(), "2 inputs is not a consolidation");
    }

    #[test]
    fn test_no_consolidation_when_many_outputs() {
        let addr1 = regtest_p2tr_address();
        let addr2 = regtest_p2tr_address();
        let addr3 = regtest_p2tr_address();
        let out1 = regtest_p2tr_address();
        let out2 = regtest_p2tr_address();
        let out3 = regtest_p2tr_address();

        let recv1 = make_txid(1);
        let recv2 = make_txid(2);
        let recv3 = make_txid(3);
        let spend_txid = make_txid(4);

        let graph = MockGraphBuilder::new()
            .with_address(addr1.clone())
            .with_address(addr2.clone())
            .with_address(addr3.clone())
            .with_address(out1.clone())
            .with_receive_tx(recv1, addr1.clone(), 100_000)
            .with_receive_tx(recv2, addr2.clone(), 200_000)
            .with_receive_tx(recv3, addr3.clone(), 300_000)
            .with_spend_tx(
                spend_txid,
                vec![(recv1, 0, 100_000), (recv2, 0, 200_000), (recv3, 0, 300_000)],
                vec![
                    (out1.clone(), 200_000, false),
                    (out2.clone(), 200_000, false),
                    (out3.clone(), 195_000, false),
                ],
            )
            .with_utxo(spend_txid, 0, out1.clone(), 200_000, 3)
            .build();

        let config = test_config();
        let findings = ConsolidationDetector.detect(&graph, &config);
        assert!(findings.is_empty(), "3 outputs → not a consolidation");
    }

    #[test]
    fn test_no_duplicate_findings_for_same_consolidation_tx() {
        // Two UTXOs both from the same consolidation tx → only one finding
        let addr1 = regtest_p2tr_address();
        let addr2 = regtest_p2tr_address();
        let addr3 = regtest_p2tr_address();
        let out1 = regtest_p2tr_address();
        let out2 = regtest_p2tr_address();

        let recv1 = make_txid(1);
        let recv2 = make_txid(2);
        let recv3 = make_txid(3);
        let consolidation_txid = make_txid(4);

        let graph = MockGraphBuilder::new()
            .with_address(addr1.clone())
            .with_address(addr2.clone())
            .with_address(addr3.clone())
            .with_address(out1.clone())
            .with_address(out2.clone())
            .with_receive_tx(recv1, addr1.clone(), 100_000)
            .with_receive_tx(recv2, addr2.clone(), 200_000)
            .with_receive_tx(recv3, addr3.clone(), 300_000)
            .with_spend_tx(
                consolidation_txid,
                vec![(recv1, 0, 100_000), (recv2, 0, 200_000), (recv3, 0, 300_000)],
                vec![
                    (out1.clone(), 297_000, false),
                    (out2.clone(), 298_000, false),
                ],
            )
            // Two UTXOs from the same consolidation tx
            .with_utxo(consolidation_txid, 0, out1.clone(), 297_000, 6)
            .with_utxo(consolidation_txid, 1, out2.clone(), 298_000, 6)
            .build();

        let config = test_config();
        let findings = ConsolidationDetector.detect(&graph, &config);

        // 3 inputs, 2 outputs → qualifies as consolidation; but only reported once
        assert_eq!(findings.len(), 1, "Should deduplicate findings for same txid");
    }
}
