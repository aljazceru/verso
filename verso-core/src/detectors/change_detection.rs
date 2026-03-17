use std::collections::HashSet;

use serde_json::json;

use crate::config::ScanConfig;
use crate::graph::GraphView;
use crate::report::{Finding, FindingCategory, FindingType, Severity};

use super::Detector;

pub struct ChangeDetectionDetector;

/// Returns true if `sats` is a "round" amount:
/// divisible by 100_000 (0.001 BTC) or by 1_000_000 (0.01 BTC).
fn is_round(sats: u64) -> bool {
    sats % 100_000 == 0 || sats % 1_000_000 == 0
}

impl Detector for ChangeDetectionDetector {
    fn name(&self) -> &'static str {
        "change_detection"
    }

    fn index(&self) -> u8 {
        5
    }

    fn detect(&self, graph: &dyn GraphView, _config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        for txid in graph.our_txids() {
            let inputs = graph.input_addresses(txid);
            let outputs = graph.output_addresses(txid);

            // Need at least 2 outputs to distinguish change from payment
            if outputs.len() < 2 {
                continue;
            }

            // Only care about sends (at least one of our inputs)
            let our_inputs: Vec<_> = inputs.iter().filter(|i| i.is_ours).collect();
            if our_inputs.is_empty() {
                continue;
            }

            // Change outputs = ours; payment outputs = not ours
            let our_outs: Vec<_> = outputs.iter().filter(|o| o.is_ours).collect();
            let ext_outs: Vec<_> = outputs.iter().filter(|o| !o.is_ours).collect();

            if our_outs.is_empty() || ext_outs.is_empty() {
                continue;
            }

            let mut heuristics: HashSet<&'static str> = HashSet::new();

            // Input script types
            let in_types: HashSet<_> = our_inputs
                .iter()
                .filter_map(|inp| inp.address.as_ref())
                .map(|addr| graph.script_type(addr))
                .collect();

            for change in &our_outs {
                let ch_sats = change.value_sats;
                let ch_round = is_round(ch_sats);

                // Heuristic 3: internal keychain
                if change.is_change {
                    heuristics.insert("internal_keychain");
                }

                let ch_type = change.address.as_ref().map(|a| graph.script_type(a));

                for payment in &ext_outs {
                    let pay_sats = payment.value_sats;
                    let pay_round = is_round(pay_sats);

                    // Heuristic 1: payment is round, change is not
                    if pay_round && !ch_round {
                        heuristics.insert("round_amount");
                    }

                    // Heuristic 2: change script type differs from payment script type
                    let pay_type = payment.address.as_ref().map(|a| graph.script_type(a));
                    if let (Some(ct), Some(pt)) = (&ch_type, &pay_type) {
                        if ct != pt && in_types.contains(ct) {
                            heuristics.insert("script_type_mismatch");
                        }
                    }
                }
            }

            if !heuristics.is_empty() {
                let mut heuristic_list: Vec<&str> = heuristics.into_iter().collect();
                heuristic_list.sort();

                let change_outputs: Vec<serde_json::Value> = our_outs
                    .iter()
                    .filter_map(|o| {
                        o.address.as_ref().map(|a| {
                            json!({
                                "address": a.to_string(),
                                "amount_sats": o.value_sats,
                            })
                        })
                    })
                    .collect();

                findings.push(Finding {
                    finding_type: FindingType::ChangeDetection,
                    severity: Severity::Medium,
                    description: "Change output identifiable via heuristics".to_string(),
                    details: json!({
                        "txid": txid.to_string(),
                        "change_outputs": change_outputs,
                        "heuristics": heuristic_list,
                    }),
                    correction: Some(
                        "Use PayJoin (BIP-78) so the receiver also contributes an input, breaking \
                         the payment/change heuristic. Alternatively, select a UTXO that exactly \
                         covers the payment amount (no change output needed). Ensure your change \
                         address uses the same script type as the payment address. Avoid sending \
                         round amounts so the change amount is not the obvious 'leftover'."
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

    // Build a P2WPKH address on regtest for script-type mixing tests
    fn regtest_p2wpkh_address() -> bitcoin::Address {
        use bitcoin::{
            key::{Secp256k1, UntweakedKeypair},
            secp256k1::rand,
            CompressedPublicKey,
        };
        let secp = Secp256k1::new();
        let keypair = UntweakedKeypair::new(&secp, &mut rand::thread_rng());
        let pk = CompressedPublicKey(keypair.public_key());
        bitcoin::Address::p2wpkh(&pk, Network::Regtest)
    }

    #[test]
    fn test_detects_round_amount_heuristic() {
        let our_addr = regtest_p2tr_address();
        let change_addr = regtest_p2tr_address();
        let ext_addr = regtest_p2tr_address();
        let recv_txid = make_txid(1);
        let spend_txid = make_txid(2);

        // Payment is round (1_000_000 sats = 0.01 BTC), change is non-round (49_123 sats)
        let graph = MockGraphBuilder::new()
            .with_address(our_addr.clone())
            .with_change_address(change_addr.clone())
            .with_receive_tx(recv_txid, our_addr.clone(), 2_000_000)
            .with_spend_tx(
                spend_txid,
                vec![(recv_txid, 0, 2_000_000)],
                vec![
                    (ext_addr.clone(), 1_000_000, false), // round payment
                    (change_addr.clone(), 49_123, true),  // non-round change
                ],
            )
            .build();

        let config = test_config();
        let findings = ChangeDetectionDetector.detect(&graph, &config);

        assert!(!findings.is_empty(), "Expected change detection finding");
        assert_eq!(findings[0].finding_type, FindingType::ChangeDetection);
        assert_eq!(findings[0].severity, Severity::Medium);

        let heuristics = findings[0].details["heuristics"].as_array().unwrap();
        let heuristic_strs: Vec<&str> = heuristics
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(
            heuristic_strs.contains(&"round_amount"),
            "Should detect round_amount heuristic"
        );
    }

    #[test]
    fn test_detects_internal_keychain_heuristic() {
        let our_addr = regtest_p2tr_address();
        let change_addr = regtest_p2tr_address();
        let ext_addr = regtest_p2tr_address();
        let recv_txid = make_txid(1);
        let spend_txid = make_txid(2);

        // Change output is on the internal keychain — is_change = true
        let graph = MockGraphBuilder::new()
            .with_address(our_addr.clone())
            .with_change_address(change_addr.clone())
            .with_receive_tx(recv_txid, our_addr.clone(), 500_000)
            .with_spend_tx(
                spend_txid,
                vec![(recv_txid, 0, 500_000)],
                vec![
                    (ext_addr.clone(), 333_333, false),   // non-round payment
                    (change_addr.clone(), 166_667, true),  // change on internal keychain
                ],
            )
            .build();

        let config = test_config();
        let findings = ChangeDetectionDetector.detect(&graph, &config);

        assert!(!findings.is_empty(), "Expected change detection finding");
        let heuristics = findings[0].details["heuristics"].as_array().unwrap();
        let heuristic_strs: Vec<&str> = heuristics
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(
            heuristic_strs.contains(&"internal_keychain"),
            "Should detect internal_keychain heuristic"
        );
    }

    #[test]
    fn test_no_finding_when_single_output() {
        let our_addr = regtest_p2tr_address();
        let recv_txid = make_txid(1);
        let spend_txid = make_txid(2);
        let ext_addr = regtest_p2tr_address();

        // Only one output — can't distinguish change from payment
        let graph = MockGraphBuilder::new()
            .with_address(our_addr.clone())
            .with_receive_tx(recv_txid, our_addr.clone(), 1_000_000)
            .with_spend_tx(
                spend_txid,
                vec![(recv_txid, 0, 1_000_000)],
                vec![(ext_addr.clone(), 999_000, false)],
            )
            .build();

        let config = test_config();
        let findings = ChangeDetectionDetector.detect(&graph, &config);
        assert!(findings.is_empty(), "Single output should not trigger change detection");
    }

    #[test]
    fn test_no_finding_when_all_outputs_ours() {
        let our_addr = regtest_p2tr_address();
        let change_addr = regtest_p2tr_address();
        let recv_txid = make_txid(1);
        let spend_txid = make_txid(2);

        // All outputs are ours — no external payment to compare with
        let graph = MockGraphBuilder::new()
            .with_address(our_addr.clone())
            .with_change_address(change_addr.clone())
            .with_receive_tx(recv_txid, our_addr.clone(), 500_000)
            .with_spend_tx(
                spend_txid,
                vec![(recv_txid, 0, 500_000)],
                vec![
                    (our_addr.clone(), 300_000, false),
                    (change_addr.clone(), 200_000, true),
                ],
            )
            .build();

        let config = test_config();
        let findings = ChangeDetectionDetector.detect(&graph, &config);
        assert!(findings.is_empty(), "All outputs ours should not trigger change detection");
    }

    #[test]
    fn test_detects_script_type_mismatch() {
        // Our inputs are P2TR; change output is P2TR; payment output is P2WPKH
        // → change script type matches input type but differs from payment → heuristic fires
        let our_addr = regtest_p2tr_address();       // P2TR
        let change_addr = regtest_p2tr_address();    // P2TR (same as input)
        let ext_addr = regtest_p2wpkh_address();     // P2WPKH (different)
        let recv_txid = make_txid(1);
        let spend_txid = make_txid(2);

        let graph = MockGraphBuilder::new()
            .with_address(our_addr.clone())
            .with_change_address(change_addr.clone())
            .with_receive_tx(recv_txid, our_addr.clone(), 500_000)
            .with_spend_tx(
                spend_txid,
                vec![(recv_txid, 0, 500_000)],
                vec![
                    (ext_addr.clone(), 333_333, false),
                    (change_addr.clone(), 166_667, true),
                ],
            )
            .build();

        let config = test_config();
        let findings = ChangeDetectionDetector.detect(&graph, &config);

        assert!(!findings.is_empty(), "Expected change detection from script_type_mismatch");
        let heuristics = findings[0].details["heuristics"].as_array().unwrap();
        let heuristic_strs: Vec<&str> = heuristics
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(
            heuristic_strs.contains(&"script_type_mismatch"),
            "Should detect script_type_mismatch heuristic, got: {:?}", heuristic_strs
        );
    }
}
