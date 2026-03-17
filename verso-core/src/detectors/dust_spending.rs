use serde_json::json;

use crate::config::ScanConfig;
use crate::graph::GraphView;
use crate::report::{Finding, FindingCategory, FindingType, Severity};

use super::Detector;

const DUST_SATS: u64 = 1000;
const NORMAL_SATS: u64 = 10_000;

pub struct DustSpendingDetector;

impl Detector for DustSpendingDetector {
    fn name(&self) -> &'static str {
        "dust_spending"
    }

    fn index(&self) -> u8 {
        4
    }

    fn detect(&self, graph: &dyn GraphView, _config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        for txid in graph.our_txids() {
            let inputs = graph.input_addresses(txid);

            // Need at least 2 inputs to co-spend
            if inputs.len() < 2 {
                continue;
            }

            let mut dust_inputs = Vec::new();
            let mut normal_input_infos: Vec<&crate::graph::InputInfo> = Vec::new();

            for inp in inputs {
                if !inp.is_ours {
                    continue;
                }
                if inp.value_sats <= DUST_SATS {
                    dust_inputs.push(inp);
                } else if inp.value_sats > NORMAL_SATS {
                    normal_input_infos.push(inp);
                }
            }

            if !dust_inputs.is_empty() && !normal_input_infos.is_empty() {
                let dust_details: Vec<serde_json::Value> = dust_inputs
                    .iter()
                    .map(|d| {
                        json!({
                            "address": d.address.as_ref().map(|a| a.to_string()),
                            "amount_sats": d.value_sats,
                        })
                    })
                    .collect();

                let normal_inputs: Vec<serde_json::Value> = normal_input_infos.iter().map(|inp| {
                    json!({
                        "address": inp.address.as_ref().map(|a| a.to_string()).unwrap_or_default(),
                        "amount_sats": inp.value_sats,
                    })
                }).collect();

                findings.push(Finding {
                    finding_type: FindingType::DustSpending,
                    severity: Severity::High,
                    description: "Dust UTXO co-spent with normal UTXO (potential tracking)"
                        .to_string(),
                    details: json!({
                        "txid": txid.to_string(),
                        "dust_inputs": dust_details,
                        "normal_inputs": normal_inputs,
                    }),
                    correction: Some(
                        "Never co-spend dust UTXOs with regular UTXOs. Freeze dust UTXOs in your \
                         wallet to prevent them from being automatically selected as inputs. If the \
                         dust must be reclaimed, do so in isolation via a dedicated CoinJoin or by \
                         sweeping only the dust in a separate, low-value transaction with no other \
                         inputs."
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
    fn test_detects_dust_co_spent_with_normal() {
        let addr1 = regtest_p2tr_address();
        let addr2 = regtest_p2tr_address();
        let recv_dust_txid =
            make_txid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let recv_normal_txid =
            make_txid("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let spend_txid =
            make_txid("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

        let graph = MockGraphBuilder::new()
            .with_address(addr1.clone())
            .with_address(addr2.clone())
            .with_receive_tx(recv_dust_txid, addr1.clone(), 546)      // dust
            .with_receive_tx(recv_normal_txid, addr2.clone(), 100_000) // normal
            .with_spend_tx(
                spend_txid,
                vec![
                    (recv_dust_txid, 0, 546),       // dust input
                    (recv_normal_txid, 0, 100_000), // normal input
                ],
                vec![(addr1.clone(), 100_000, false)],
            )
            .build();

        let config = test_config();
        let findings = DustSpendingDetector.detect(&graph, &config);

        let relevant: Vec<_> = findings
            .iter()
            .filter(|f| f.details["txid"].as_str() == Some(&spend_txid.to_string()))
            .collect();

        assert!(!relevant.is_empty(), "Expected DustSpending finding");
        assert_eq!(relevant[0].finding_type, FindingType::DustSpending);
        assert_eq!(relevant[0].severity, Severity::High);
        assert_eq!(relevant[0].details["normal_inputs"].as_array().unwrap().len(), 1);
        assert_eq!(relevant[0].details["dust_inputs"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_no_finding_when_only_dust_inputs() {
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
            .with_receive_tx(recv_txid1, addr1.clone(), 500) // dust
            .with_receive_tx(recv_txid2, addr2.clone(), 800) // dust
            .with_spend_tx(
                spend_txid,
                vec![(recv_txid1, 0, 500), (recv_txid2, 0, 800)],
                vec![(addr1.clone(), 1200, false)],
            )
            .build();

        let config = test_config();
        let findings = DustSpendingDetector.detect(&graph, &config);
        let relevant: Vec<_> = findings
            .iter()
            .filter(|f| f.details["txid"].as_str() == Some(&spend_txid.to_string()))
            .collect();
        assert!(relevant.is_empty(), "Only dust inputs → no DustSpending finding");
    }

    #[test]
    fn test_no_finding_when_only_normal_inputs() {
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
            .with_receive_tx(recv_txid1, addr1.clone(), 50_000)
            .with_receive_tx(recv_txid2, addr2.clone(), 100_000)
            .with_spend_tx(
                spend_txid,
                vec![(recv_txid1, 0, 50_000), (recv_txid2, 0, 100_000)],
                vec![(addr1.clone(), 145_000, false)],
            )
            .build();

        let config = test_config();
        let findings = DustSpendingDetector.detect(&graph, &config);
        let relevant: Vec<_> = findings
            .iter()
            .filter(|f| f.details["txid"].as_str() == Some(&spend_txid.to_string()))
            .collect();
        assert!(relevant.is_empty(), "Only normal inputs → no DustSpending finding");
    }

    #[test]
    fn test_no_finding_for_single_input_tx() {
        let addr = regtest_p2tr_address();
        let recv_txid =
            make_txid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let spend_txid =
            make_txid("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_receive_tx(recv_txid, addr.clone(), 546)
            .with_spend_tx(
                spend_txid,
                vec![(recv_txid, 0, 546)],
                vec![(addr.clone(), 500, false)],
            )
            .build();

        let config = test_config();
        let findings = DustSpendingDetector.detect(&graph, &config);
        let relevant: Vec<_> = findings
            .iter()
            .filter(|f| f.details["txid"].as_str() == Some(&spend_txid.to_string()))
            .collect();
        assert!(relevant.is_empty(), "Single input → no DustSpending finding");
    }
}
