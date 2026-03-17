use std::collections::{HashMap, HashSet};

use bitcoin::Txid;
use serde_json::json;

use crate::config::ScanConfig;
use crate::graph::GraphView;
use crate::report::{Finding, FindingCategory, FindingType, Severity};

use super::Detector;

pub struct AddressReuseDetector;

impl Detector for AddressReuseDetector {
    fn name(&self) -> &'static str {
        "address_reuse"
    }

    fn index(&self) -> u8 {
        1
    }

    fn detect(&self, graph: &dyn GraphView, _config: &ScanConfig) -> Vec<Finding> {
        // For each wallet address, collect the distinct txids where it received funds.
        // An address receives funds when it appears as an output in a transaction.
        let our_addrs = graph.our_addresses();
        let our_txids = graph.our_txids();

        // Build a map: address -> set of txids where that address received funds
        let mut addr_receive_txids: HashMap<String, HashSet<Txid>> = HashMap::new();

        for txid in &our_txids {
            let outputs = graph.output_addresses(*txid);
            for out in outputs {
                if out.is_ours {
                    if let Some(ref addr) = out.address {
                        addr_receive_txids
                            .entry(addr.to_string())
                            .or_default()
                            .insert(*txid);
                    }
                }
            }
        }

        let mut findings = Vec::new();

        for addr in &our_addrs {
            let addr_str = addr.to_string();
            if let Some(txids) = addr_receive_txids.get(&addr_str) {
                if txids.len() >= 2 {
                    let mut sorted_txids: Vec<Txid> = txids.iter().copied().collect();
                    sorted_txids.sort_by_key(|t| t.to_string());

                    let txid_objects: Vec<serde_json::Value> = sorted_txids
                        .iter()
                        .map(|txid| {
                            let confs = graph.confirmations(*txid).unwrap_or(0);
                            serde_json::json!({"txid": txid.to_string(), "confirmations": confs})
                        })
                        .collect();

                    let role = if graph.is_change(&addr.script_pubkey()) {
                        "change"
                    } else {
                        "receive"
                    };

                    findings.push(Finding {
                        finding_type: FindingType::AddressReuse,
                        severity: Severity::High,
                        description: "Address reused across multiple transactions".to_string(),
                        details: json!({
                            "address": addr_str,
                            "role": role,
                            "tx_count": txids.len(),
                            "txids": txid_objects,
                        }),
                        correction: Some(
                            "Use a new address for each transaction. Enable HD wallet derivation \
                             (BIP-32/44/84) so your wallet produces a new address automatically. \
                             If the address is a static donation or payment address, consider a \
                             Lightning invoice or a payment-code scheme (BIP-47) that hides the \
                             on-chain address."
                                .to_string(),
                        ),
                        category: FindingCategory::Finding,
                    });
                }
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
    fn test_detects_reuse_when_same_address_in_two_txids() {
        let addr = regtest_p2tr_address();
        let txid1 = make_txid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let txid2 = make_txid("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_receive_tx(txid1, addr.clone(), 50_000)
            .with_receive_tx(txid2, addr.clone(), 30_000)
            .build();

        let config = test_config();
        let findings = AddressReuseDetector.detect(&graph, &config);

        assert!(!findings.is_empty(), "Expected findings for reused address");
        assert_eq!(findings[0].finding_type, FindingType::AddressReuse);
        assert_eq!(findings[0].severity, Severity::High);

        let tx_count = findings[0].details["tx_count"].as_u64().unwrap();
        assert_eq!(tx_count, 2);
    }

    #[test]
    fn test_no_reuse_when_single_receive() {
        let addr = regtest_p2tr_address();
        let txid1 = make_txid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_receive_tx(txid1, addr.clone(), 50_000)
            .build();

        let config = test_config();
        let findings = AddressReuseDetector.detect(&graph, &config);
        assert!(findings.is_empty(), "No finding for single-use address");
    }

    #[test]
    fn test_no_reuse_when_different_addresses() {
        let addr1 = regtest_p2tr_address();
        let addr2 = regtest_p2tr_address();
        let txid1 = make_txid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let txid2 = make_txid("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

        let graph = MockGraphBuilder::new()
            .with_address(addr1.clone())
            .with_address(addr2.clone())
            .with_receive_tx(txid1, addr1.clone(), 50_000)
            .with_receive_tx(txid2, addr2.clone(), 30_000)
            .build();

        let config = test_config();
        let findings = AddressReuseDetector.detect(&graph, &config);
        assert!(
            findings.is_empty(),
            "Different addresses should not trigger reuse finding"
        );
    }

    #[test]
    fn test_reuse_details_contain_address_and_txids() {
        let addr = regtest_p2tr_address();
        let txid1 = make_txid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let txid2 = make_txid("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let txid3 = make_txid("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_receive_tx(txid1, addr.clone(), 50_000)
            .with_receive_tx(txid2, addr.clone(), 30_000)
            .with_receive_tx(txid3, addr.clone(), 10_000)
            .build();

        let config = test_config();
        let findings = AddressReuseDetector.detect(&graph, &config);
        assert_eq!(findings.len(), 1);

        let details = &findings[0].details;
        assert_eq!(details["tx_count"].as_u64().unwrap(), 3);
        let txid_arr = details["txids"].as_array().unwrap();
        assert_eq!(txid_arr.len(), 3);
        // Each txid entry is now an object with "txid" and "confirmations" fields
        assert!(txid_arr[0].get("txid").is_some());
        assert!(txid_arr[0].get("confirmations").is_some());
    }
}
