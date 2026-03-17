use std::collections::HashSet;

use serde_json::json;

use crate::config::ScanConfig;
use crate::graph::{GraphView, ScriptType};
use crate::report::{Finding, FindingCategory, FindingType, Severity};

use super::Detector;

pub struct ScriptMixingDetector;

impl Detector for ScriptMixingDetector {
    fn name(&self) -> &'static str {
        "script_mixing"
    }

    fn index(&self) -> u8 {
        7
    }

    fn detect(&self, graph: &dyn GraphView, _config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        for txid in graph.our_txids() {
            let inputs = graph.input_addresses(txid);

            // Need at least 2 inputs total
            if inputs.len() < 2 {
                continue;
            }

            // Need at least 2 of our inputs
            let our_inputs: Vec<_> = inputs.iter().filter(|i| i.is_ours).collect();
            if our_inputs.len() < 2 {
                continue;
            }

            // Collect distinct script types among our inputs, ignoring Unknown
            let mut types: HashSet<ScriptType> = HashSet::new();
            for inp in &our_inputs {
                if let Some(addr) = &inp.address {
                    let st = graph.script_type(addr);
                    if st != ScriptType::Unknown {
                        types.insert(st);
                    }
                }
            }

            if types.len() >= 2 {
                let mut type_strs: Vec<String> = types.iter().map(|t| format!("{:?}", t)).collect();
                type_strs.sort();

                findings.push(Finding {
                    finding_type: FindingType::ScriptTypeMixing,
                    severity: Severity::High,
                    description: "Transaction mixes different script types in inputs".to_string(),
                    details: json!({
                        "txid": txid.to_string(),
                        "script_types": type_strs,
                    }),
                    correction: Some(
                        "Migrate all funds to a single address type — preferably Taproot (P2TR / \
                         bc1p) which offers the largest anonymity set going forward. Never mix \
                         P2PKH, P2SH-P2WPKH, P2WPKH, and P2TR inputs in the same transaction; \
                         each type combination is a rare fingerprint. Sweep legacy-type UTXOs to \
                         a fresh Taproot wallet through a CoinJoin to avoid the cross-type link."
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
    fn test_detects_script_type_mixing_p2wpkh_and_p2tr() {
        let p2tr_addr = regtest_p2tr_address();
        let p2wpkh_addr = regtest_p2wpkh_address();
        let out_addr = regtest_p2tr_address();

        let recv1 = make_txid(1);
        let recv2 = make_txid(2);
        let spend_txid = make_txid(3);

        let graph = MockGraphBuilder::new()
            .with_address(p2tr_addr.clone())
            .with_address(p2wpkh_addr.clone())
            .with_address(out_addr.clone())
            .with_receive_tx(recv1, p2tr_addr.clone(), 100_000)
            .with_receive_tx(recv2, p2wpkh_addr.clone(), 200_000)
            .with_spend_tx(
                spend_txid,
                vec![(recv1, 0, 100_000), (recv2, 0, 200_000)],
                vec![(out_addr.clone(), 295_000, false)],
            )
            .build();

        let config = test_config();
        let findings = ScriptMixingDetector.detect(&graph, &config);

        assert!(!findings.is_empty(), "Expected script mixing finding");
        assert_eq!(findings[0].finding_type, FindingType::ScriptTypeMixing);
        assert_eq!(findings[0].severity, Severity::High);

        let types = findings[0].details["script_types"].as_array().unwrap();
        assert_eq!(types.len(), 2, "Should have 2 distinct script types");
    }

    #[test]
    fn test_no_finding_when_same_script_type() {
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
            .build();

        let config = test_config();
        let findings = ScriptMixingDetector.detect(&graph, &config);
        assert!(
            findings.is_empty(),
            "Same script type inputs should not trigger finding"
        );
    }

    #[test]
    fn test_no_finding_when_only_one_our_input() {
        let our_addr = regtest_p2tr_address();
        let ext_p2wpkh = regtest_p2wpkh_address();
        let out_addr = regtest_p2tr_address();

        let recv1 = make_txid(1);
        let recv2 = make_txid(2);
        let spend_txid = make_txid(3);

        // Only one of our inputs — the other is external
        let graph = MockGraphBuilder::new()
            .with_address(our_addr.clone())
            // ext_p2wpkh not registered as ours
            .with_receive_tx(recv1, our_addr.clone(), 100_000)
            .with_receive_tx(recv2, ext_p2wpkh.clone(), 200_000)
            .with_spend_tx(
                spend_txid,
                vec![(recv1, 0, 100_000), (recv2, 0, 200_000)],
                vec![(out_addr.clone(), 295_000, false)],
            )
            .build();

        let config = test_config();
        let findings = ScriptMixingDetector.detect(&graph, &config);

        // spend_txid has 2 inputs but only 1 is ours → no script mixing for spend_txid
        let relevant: Vec<_> = findings
            .iter()
            .filter(|f| f.details["txid"].as_str() == Some(&spend_txid.to_string()))
            .collect();
        assert!(relevant.is_empty(), "Only 1 our input → no script mixing");
    }

    #[test]
    fn test_no_finding_single_input() {
        let addr = regtest_p2tr_address();
        let out_addr = regtest_p2wpkh_address(); // different type but doesn't matter — only 1 input
        let recv = make_txid(1);
        let spend = make_txid(2);

        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_receive_tx(recv, addr.clone(), 100_000)
            .with_spend_tx(
                spend,
                vec![(recv, 0, 100_000)],
                vec![(out_addr.clone(), 99_000, false)],
            )
            .build();

        let config = test_config();
        let findings = ScriptMixingDetector.detect(&graph, &config);
        assert!(findings.is_empty(), "Single input cannot mix script types");
    }
}
