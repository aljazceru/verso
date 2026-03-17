use serde_json::json;

use crate::config::ScanConfig;
use crate::graph::GraphView;
use crate::report::{Finding, FindingCategory, FindingType, Severity};

use super::Detector;

pub struct CiohDetector;

impl Detector for CiohDetector {
    fn name(&self) -> &'static str {
        "cioh"
    }

    fn index(&self) -> u8 {
        2
    }

    fn detect(&self, graph: &dyn GraphView, _config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        for txid in graph.our_txids() {
            let inputs = graph.input_addresses(txid);

            // Need at least 2 inputs total
            if inputs.len() < 2 {
                continue;
            }

            let our_inputs: Vec<_> = inputs.iter().filter(|i| i.is_ours).collect();
            let total_inputs = inputs.len();
            let n_ours = our_inputs.len();

            // Only flag if >= 2 of our inputs are merged
            if n_ours < 2 {
                continue;
            }

            let severity = if n_ours == total_inputs {
                Severity::Critical
            } else {
                Severity::High
            };

            let external_inputs = total_inputs - n_ours;
            let ownership_pct = (n_ours as f64 / total_inputs as f64 * 100.0).round();

            let our_addresses: Vec<serde_json::Value> = our_inputs.iter().filter_map(|inp| {
                inp.address.as_ref().map(|a| {
                    let role = if graph.is_change(&a.script_pubkey()) { "change" } else { "receive" };
                    serde_json::json!({
                        "address": a.to_string(),
                        "role": role,
                        "amount_sats": inp.value_sats,
                    })
                })
            }).collect();

            findings.push(Finding {
                finding_type: FindingType::Cioh,
                severity,
                description: "Multiple wallet inputs merged in one transaction (CIOH)".to_string(),
                details: json!({
                    "txid": txid.to_string(),
                    "our_input_count": n_ours,
                    "total_input_count": total_inputs,
                    "external_inputs": external_inputs,
                    "ownership_pct": ownership_pct,
                    "our_addresses": our_addresses,
                }),
                correction: Some(
                    "Avoid spending multiple UTXOs in a single transaction. Use coin control to \
                     select only one UTXO per transaction when the payment amount allows it. If \
                     consolidation is unavoidable, do it privately via a CoinJoin round so the \
                     link between inputs is indistinguishable from other participants."
                        .to_string(),
                ),
                category: FindingCategory::Finding,
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{Network, Txid};

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

    fn make_txid(hex: &str) -> Txid {
        Txid::from_str(hex).unwrap()
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
    fn test_detects_cioh_all_our_inputs_critical() {
        let addr1 = regtest_p2tr_address();
        let addr2 = regtest_p2tr_address();
        let recv_txid1 =
            make_txid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let recv_txid2 =
            make_txid("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let spend_txid =
            make_txid("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

        let graph = MockGraphBuilder::new()
            .with_address(addr1.clone())
            .with_address(addr2.clone())
            .with_receive_tx(recv_txid1, addr1.clone(), 100_000)
            .with_receive_tx(recv_txid2, addr2.clone(), 200_000)
            .with_spend_tx(
                spend_txid,
                vec![(recv_txid1, 0, 100_000), (recv_txid2, 0, 200_000)],
                vec![(addr1.clone(), 295_000, false)],
            )
            .build();

        let config = test_config();
        let findings = CiohDetector.detect(&graph, &config);

        assert!(!findings.is_empty(), "Expected CIOH finding");
        assert_eq!(findings[0].finding_type, FindingType::Cioh);
        assert_eq!(findings[0].severity, Severity::Critical,
            "All inputs ours → Critical");

        let details = &findings[0].details;
        assert_eq!(details["our_input_count"].as_u64().unwrap(), 2);
        assert_eq!(details["total_input_count"].as_u64().unwrap(), 2);
    }

    #[test]
    fn test_detects_cioh_mixed_inputs_high() {
        let our_addr1 = regtest_p2tr_address();
        let our_addr2 = regtest_p2tr_address();
        // External address for the external input — we won't register it as ours
        let ext_recv_txid =
            make_txid("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
        let recv_txid1 =
            make_txid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let recv_txid2 =
            make_txid("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let spend_txid =
            make_txid("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

        // External address receives into ext_recv_txid, but we don't register it as ours
        let ext_addr = regtest_p2tr_address();

        let graph = MockGraphBuilder::new()
            .with_address(our_addr1.clone())
            .with_address(our_addr2.clone())
            .with_receive_tx(recv_txid1, our_addr1.clone(), 100_000)
            .with_receive_tx(recv_txid2, our_addr2.clone(), 200_000)
            // ext_recv_txid supplies the external input (not registered as ours)
            .with_receive_tx(ext_recv_txid, ext_addr.clone(), 50_000)
            .with_spend_tx(
                spend_txid,
                vec![
                    (recv_txid1, 0, 100_000),
                    (recv_txid2, 0, 200_000),
                    (ext_recv_txid, 0, 50_000), // external input
                ],
                vec![(our_addr1.clone(), 345_000, false)],
            )
            .build();

        let config = test_config();
        let findings = CiohDetector.detect(&graph, &config);

        // Filter to just the spend_txid finding (ext_recv_txid has only 1 input)
        let cioh_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.details["txid"].as_str() == Some(&spend_txid.to_string()))
            .collect();

        assert!(!cioh_findings.is_empty(), "Expected CIOH finding for spend_txid");
        assert_eq!(cioh_findings[0].severity, Severity::High,
            "Mixed inputs → High");

        let details = &cioh_findings[0].details;
        assert_eq!(details["our_input_count"].as_u64().unwrap(), 2);
        assert_eq!(details["total_input_count"].as_u64().unwrap(), 3);
    }

    #[test]
    fn test_no_cioh_single_input() {
        let addr = regtest_p2tr_address();
        let recv_txid =
            make_txid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let spend_txid =
            make_txid("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_receive_tx(recv_txid, addr.clone(), 100_000)
            .with_spend_tx(
                spend_txid,
                vec![(recv_txid, 0, 100_000)],
                vec![(addr.clone(), 99_000, false)],
            )
            .build();

        let config = test_config();
        let findings = CiohDetector.detect(&graph, &config);
        assert!(findings.is_empty(), "Single input should not trigger CIOH");
    }

    #[test]
    fn test_no_cioh_when_only_one_our_input() {
        let our_addr = regtest_p2tr_address();
        let ext_addr = regtest_p2tr_address();
        let recv_txid =
            make_txid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let ext_recv_txid =
            make_txid("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let spend_txid =
            make_txid("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

        let graph = MockGraphBuilder::new()
            .with_address(our_addr.clone())
            // ext_addr not registered as ours
            .with_receive_tx(recv_txid, our_addr.clone(), 100_000)
            .with_receive_tx(ext_recv_txid, ext_addr.clone(), 50_000)
            .with_spend_tx(
                spend_txid,
                vec![(recv_txid, 0, 100_000), (ext_recv_txid, 0, 50_000)],
                vec![(our_addr.clone(), 145_000, false)],
            )
            .build();

        let config = test_config();
        let findings = CiohDetector.detect(&graph, &config);

        // The spend_txid has 2 inputs but only 1 is ours → no CIOH
        let cioh: Vec<_> = findings
            .iter()
            .filter(|f| f.details["txid"].as_str() == Some(&spend_txid.to_string()))
            .collect();
        assert!(cioh.is_empty(), "Only 1 our input → no CIOH");
    }
}
