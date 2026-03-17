use serde_json::json;

use crate::config::ScanConfig;
use crate::graph::GraphView;
use crate::report::{Finding, FindingCategory, FindingType, Severity};

use super::Detector;

pub struct TaintedDetector;

impl Detector for TaintedDetector {
    fn name(&self) -> &'static str {
        "tainted"
    }

    fn index(&self) -> u8 {
        11
    }

    fn detect(&self, graph: &dyn GraphView, config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        // If no known risky txids configured, skip entirely
        let risky_txids = match &config.known_risky_txids {
            Some(set) => set,
            None => return findings,
        };

        if risky_txids.is_empty() {
            return findings;
        }

        // TAINTED_UTXO_MERGE: transactions that merge tainted + clean inputs
        for txid in graph.our_txids() {
            let inputs = graph.input_addresses(txid);

            // Need at least 2 inputs with at least one being ours
            let our_in: Vec<_> = inputs.iter().filter(|i| i.is_ours).collect();
            if our_in.is_empty() || inputs.len() < 2 {
                continue;
            }

            // Get the raw tx to inspect input previous_output txids
            let tx = match graph.fetch_tx(txid) {
                Some(t) => t,
                None => continue,
            };

            // Classify each input as tainted or clean based on its parent txid
            let mut tainted_inputs: Vec<serde_json::Value> = Vec::new();
            let mut clean_inputs: Vec<serde_json::Value> = Vec::new();

            for (inp_info, tx_in) in inputs.iter().zip(tx.input.iter()) {
                let parent_txid = tx_in.previous_output.txid;
                if risky_txids.contains(&parent_txid) {
                    tainted_inputs.push(json!({
                        "address": inp_info.address.as_ref().map(|a| a.to_string()),
                        "amount_sats": inp_info.value_sats,
                        "source_txid": parent_txid.to_string(),
                    }));
                } else {
                    clean_inputs.push(json!({
                        "address": inp_info.address.as_ref().map(|a| a.to_string()),
                        "amount_sats": inp_info.value_sats,
                    }));
                }
            }

            if !tainted_inputs.is_empty() && !clean_inputs.is_empty() {
                let taint_pct =
                    (tainted_inputs.len() as f64 / inputs.len() as f64 * 100.0).round() as u64;
                findings.push(Finding {
                    finding_type: FindingType::TaintedUtxoMerge,
                    severity: Severity::High,
                    description: format!(
                        "TX {} merges {} tainted + {} clean inputs ({}% taint)",
                        txid,
                        tainted_inputs.len(),
                        clean_inputs.len(),
                        taint_pct
                    ),
                    details: json!({
                        "txid": txid.to_string(),
                        "tainted_inputs": tainted_inputs,
                        "clean_inputs": clean_inputs,
                        "taint_pct": taint_pct,
                    }),
                    correction: Some(
                        "Immediately freeze tainted UTXOs in your wallet to prevent them from \
                         being spent alongside clean funds. Never merge inputs from known risky \
                         sources with unrelated UTXOs — this propagates the taint to all outputs. \
                         Seek legal/compliance guidance on whether the tainted funds can be \
                         returned or must be reported. If the funds are legitimately yours, process \
                         the tainted UTXO separately and consider disclosing its origin to any \
                         counterparty that may receive it downstream."
                            .to_string(),
                    ),
                    category: FindingCategory::Finding,
                });
            }
        }

        // DIRECT_TAINT: we directly received from a known risky transaction
        for txid in graph.our_txids() {
            if !risky_txids.contains(&txid) {
                continue;
            }

            let outputs = graph.output_addresses(txid);
            let our_outputs: Vec<_> = outputs.iter().filter(|o| o.is_ours).collect();
            if our_outputs.is_empty() {
                continue;
            }

            let received: Vec<serde_json::Value> = our_outputs
                .iter()
                .map(|o| {
                    json!({
                        "address": o.address.as_ref().map(|a| a.to_string()),
                        "amount_sats": o.value_sats,
                    })
                })
                .collect();

            findings.push(Finding {
                finding_type: FindingType::DirectTaint,
                severity: Severity::High,
                description: format!("TX {} is directly from a known risky source", txid),
                details: json!({
                    "txid": txid.to_string(),
                    "received_outputs": received,
                }),
                correction: None,
                category: FindingCategory::Warning,
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

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

    fn config_with_risky(txids: Vec<Txid>) -> ScanConfig {
        let mut set = HashSet::new();
        for t in txids {
            set.insert(t);
        }
        ScanConfig {
            descriptors: vec![],
            network: Network::Regtest,
            backend: BackendConfig::Esplora {
                url: "http://localhost".to_string(),
            },
            known_risky_txids: Some(set),
            known_exchange_txids: None,
            derivation_limit: 1000,
            data_dir: None,
            ephemeral: true,
            progress_tx: None,
        }
    }

    fn config_no_risky() -> ScanConfig {
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

    #[test]
    fn test_skips_when_no_risky_config() {
        let our_addr = p2tr_addr();
        let txid = make_txid(1);
        let graph = MockGraphBuilder::new()
            .with_address(our_addr.clone())
            .with_receive_tx(txid, our_addr.clone(), 100_000)
            .build();
        let config = config_no_risky();
        let findings = TaintedDetector.detect(&graph, &config);
        assert!(
            findings.is_empty(),
            "Should skip when known_risky_txids is None"
        );
    }

    #[test]
    fn test_direct_taint_warning() {
        let our_addr = p2tr_addr();
        let risky_txid = make_txid(1);

        let graph = MockGraphBuilder::new()
            .with_address(our_addr.clone())
            .with_receive_tx(risky_txid, our_addr.clone(), 50_000)
            .build();

        let config = config_with_risky(vec![risky_txid]);
        let findings = TaintedDetector.detect(&graph, &config);

        let direct = findings
            .iter()
            .find(|f| f.finding_type == FindingType::DirectTaint);
        assert!(direct.is_some(), "Should detect direct taint");
        let f = direct.unwrap();
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.category, FindingCategory::Warning);
        assert!(f.correction.is_none());
        assert_eq!(f.details["txid"].as_str().unwrap(), risky_txid.to_string());
    }

    #[test]
    fn test_tainted_utxo_merge_finding() {
        let our_addr = p2tr_addr();
        let clean_addr = p2tr_addr();
        let out_addr = p2tr_addr();

        let risky_source = make_txid(1); // This is the risky txid (parent of tainted input)
        let clean_source = make_txid(2);
        let merge_txid = make_txid(3);

        // risky_source → tainted UTXO → merged in merge_txid
        // clean_source → clean UTXO → merged in merge_txid
        let graph = MockGraphBuilder::new()
            .with_address(our_addr.clone())
            .with_address(clean_addr.clone())
            .with_receive_tx(risky_source, our_addr.clone(), 100_000)
            .with_receive_tx(clean_source, clean_addr.clone(), 100_000)
            .with_spend_tx(
                merge_txid,
                vec![
                    (risky_source, 0, 100_000), // input from risky source
                    (clean_source, 0, 100_000), // input from clean source
                ],
                vec![(out_addr.clone(), 195_000, false)],
            )
            .build();

        let config = config_with_risky(vec![risky_source]);
        let findings = TaintedDetector.detect(&graph, &config);

        let merge_finding = findings
            .iter()
            .find(|f| f.finding_type == FindingType::TaintedUtxoMerge);
        assert!(merge_finding.is_some(), "Should detect tainted UTXO merge");
        let f = merge_finding.unwrap();
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.category, FindingCategory::Finding);
        assert!(f.correction.is_some());

        let tainted = f.details["tainted_inputs"].as_array().unwrap();
        assert_eq!(tainted.len(), 1);
        let clean = f.details["clean_inputs"].as_array().unwrap();
        assert_eq!(clean.len(), 1);
    }

    #[test]
    fn test_no_finding_when_all_inputs_clean() {
        let our_addr = p2tr_addr();
        let clean_source1 = make_txid(1);
        let clean_source2 = make_txid(2);
        let merge_txid = make_txid(3);
        let out_addr = p2tr_addr();

        let graph = MockGraphBuilder::new()
            .with_address(our_addr.clone())
            .with_receive_tx(clean_source1, our_addr.clone(), 100_000)
            .with_receive_tx(clean_source2, our_addr.clone(), 100_000)
            .with_spend_tx(
                merge_txid,
                vec![(clean_source1, 0, 100_000), (clean_source2, 0, 100_000)],
                vec![(out_addr.clone(), 195_000, false)],
            )
            .build();

        // Mark unrelated txid as risky
        let config = config_with_risky(vec![make_txid(99)]);
        let findings = TaintedDetector.detect(&graph, &config);
        let merge_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.finding_type == FindingType::TaintedUtxoMerge)
            .collect();
        assert!(
            merge_findings.is_empty(),
            "No tainted inputs = no merge finding"
        );
    }

    #[test]
    fn test_no_direct_taint_when_txid_not_in_risky_set() {
        let our_addr = p2tr_addr();
        let txid = make_txid(1);
        let graph = MockGraphBuilder::new()
            .with_address(our_addr.clone())
            .with_receive_tx(txid, our_addr.clone(), 100_000)
            .build();
        let config = config_with_risky(vec![make_txid(99)]);
        let findings = TaintedDetector.detect(&graph, &config);
        let direct: Vec<_> = findings
            .iter()
            .filter(|f| f.finding_type == FindingType::DirectTaint)
            .collect();
        assert!(direct.is_empty());
    }
}
