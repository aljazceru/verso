use std::collections::{HashMap, HashSet};

use bitcoin::hashes::Hash;
use serde_json::json;

use crate::config::ScanConfig;
use crate::graph::GraphView;
use crate::report::{Finding, FindingCategory, FindingType, Severity};

use super::Detector;

pub struct ClusterMergeDetector;

impl Detector for ClusterMergeDetector {
    fn name(&self) -> &'static str {
        "cluster_merge"
    }

    fn index(&self) -> u8 {
        8
    }

    fn detect(&self, graph: &dyn GraphView, _config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        for txid in graph.our_txids() {
            let inputs = graph.input_addresses(txid);

            // Need at least 2 inputs
            if inputs.len() < 2 {
                continue;
            }

            // Need at least 2 of our inputs
            let our_input_count = inputs.iter().filter(|i| i.is_ours).count();
            if our_input_count < 2 {
                continue;
            }

            // Get the raw tx so we can read previous_output.txid for each input
            let tx = match graph.fetch_tx(txid) {
                Some(t) => t,
                None => continue,
            };

            // For each of our inputs (by position), find the parent txid.
            // inputs[i] corresponds to tx.input[i].
            // Group our inputs by their parent txid (= the "funding cluster").
            let mut cluster_map: HashMap<String, Vec<usize>> = HashMap::new();

            for (idx, (inp_info, tx_in)) in
                inputs.iter().zip(tx.input.iter()).enumerate()
            {
                if !inp_info.is_ours {
                    continue;
                }
                let parent_txid = tx_in.previous_output.txid.to_string();
                cluster_map.entry(parent_txid).or_default().push(idx);
            }

            // If there are >= 2 distinct parent txids, this is a cluster merge.
            // We use the full txid string as the map key to avoid collisions when
            // txids share the same prefix (which is common in little-endian display).
            if cluster_map.len() >= 2 {
                // Build the "grandparent sources" for each cluster (one-hop trace)
                // to match the Python reference's disjoint-set check.
                //
                // For each parent txid we trace one hop further to get grandparent txids.
                // If a parent tx has only null/coinbase grandparents we use the parent txid
                // itself as a unique sentinel — this keeps the disjoint check correct even
                // when grandparent data is unavailable (e.g. in unit tests).
                let null_txid = bitcoin::Txid::from_byte_array([0u8; 32]);

                let mut funding_sources: HashMap<String, HashSet<String>> = HashMap::new();
                for (parent_txid_str, _input_indices) in &cluster_map {
                    // Parse back to Txid to fetch the parent tx
                    let parent_txid: bitcoin::Txid = match parent_txid_str.parse() {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    // Use full txid as key (not truncated) to avoid collisions
                    let parent_key = parent_txid_str.clone();

                    let mut gp_sources: HashSet<String> = HashSet::new();
                    if let Some(parent_tx) = graph.fetch_tx(parent_txid) {
                        for p_inp in &parent_tx.input {
                            let gp_txid = p_inp.previous_output.txid;
                            if gp_txid == null_txid {
                                // Null txid: coinbase or unknown — use per-parent sentinel
                                // to distinguish different coinbase-funded parents
                                gp_sources.insert(format!("coinbase:{}", parent_key));
                            } else {
                                gp_sources.insert(gp_txid.to_string());
                            }
                        }
                    }
                    // If no grandparent sources were found, fall back to the parent txid
                    if gp_sources.is_empty() {
                        gp_sources.insert(parent_key.clone());
                    }
                    funding_sources.insert(parent_key, gp_sources);
                }

                // Check if any two source sets are disjoint (different clusters)
                let all_sources: Vec<&HashSet<String>> = funding_sources.values().collect();
                let mut merged_clusters = false;
                'outer: for i in 0..all_sources.len() {
                    for j in (i + 1)..all_sources.len() {
                        if all_sources[i].is_disjoint(all_sources[j]) {
                            merged_clusters = true;
                            break 'outer;
                        }
                    }
                }

                if merged_clusters {
                    let funding_sources_json: serde_json::Value = funding_sources
                        .iter()
                        .map(|(k, v)| {
                            let mut sorted: Vec<&String> = v.iter().collect();
                            sorted.sort();
                            let arr: Vec<serde_json::Value> =
                                sorted.iter().map(|s| json!(s)).collect();
                            (k.clone(), json!(arr))
                        })
                        .collect::<serde_json::Map<_, _>>()
                        .into();

                    findings.push(Finding {
                        finding_type: FindingType::ClusterMerge,
                        severity: Severity::High,
                        description: "Transaction merges inputs from different funding clusters"
                            .to_string(),
                        details: json!({
                            "txid": txid.to_string(),
                            "cluster_count": cluster_map.len(),
                            "funding_sources": funding_sources_json,
                        }),
                        correction: Some(
                            "Use coin control to spend UTXOs from only one funding source per \
                             transaction. Keep UTXOs received from different counterparties in \
                             separate wallets or accounts so they are never accidentally merged. \
                             If you must merge UTXOs from different origins, pass them through a \
                             CoinJoin first to break the chain-analysis link before combining them."
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
    fn test_detects_cluster_merge_different_parent_txids() {
        // Create a scenario with actual distinct funding sources:
        // gp1 -> recv1 -> spend_txid
        // gp2 -> recv2 -> spend_txid
        //
        // spend_txid merges inputs from recv1 and recv2, which have different
        // grandparent sources (gp1 vs gp2), so it should be flagged as a cluster merge.
        let addr1 = regtest_p2tr_address();
        let addr2 = regtest_p2tr_address();
        let out_addr = regtest_p2tr_address();

        let gp1 = make_txid(1);  // First grandparent
        let gp2 = make_txid(2);  // Second grandparent
        let recv1 = make_txid(3); // First receive tx (from gp1)
        let recv2 = make_txid(4); // Second receive tx (from gp2)
        let spend_txid = make_txid(5); // Spend tx merging both

        let graph = MockGraphBuilder::new()
            .with_address(addr1.clone())
            .with_address(addr2.clone())
            .with_address(out_addr.clone())
            // gp1 and gp2 are just dummy receive txs with coinbase inputs
            .with_receive_tx(gp1, addr1.clone(), 200_000)
            .with_receive_tx(gp2, addr2.clone(), 200_000)
            // recv1 spends from gp1, recv2 spends from gp2
            .with_spend_tx(
                recv1,
                vec![(gp1, 0, 200_000)],
                vec![(addr1.clone(), 199_000, false)],
            )
            .with_spend_tx(
                recv2,
                vec![(gp2, 0, 200_000)],
                vec![(addr2.clone(), 199_000, false)],
            )
            // spend_txid merges from recv1 and recv2 (different funding sources)
            .with_spend_tx(
                spend_txid,
                vec![(recv1, 0, 199_000), (recv2, 0, 199_000)],
                vec![(out_addr.clone(), 397_000, false)],
            )
            .build();

        let config = test_config();
        let findings = ClusterMergeDetector.detect(&graph, &config);

        assert!(!findings.is_empty(), "Expected cluster merge finding");
        assert_eq!(findings[0].finding_type, FindingType::ClusterMerge);
        assert_eq!(findings[0].severity, Severity::High);

        let cluster_count = findings[0].details["cluster_count"].as_u64().unwrap();
        assert_eq!(cluster_count, 2, "Should detect 2 distinct clusters");
    }

    #[test]
    fn test_no_finding_single_input() {
        let addr = regtest_p2tr_address();
        let out_addr = regtest_p2tr_address();
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
        let findings = ClusterMergeDetector.detect(&graph, &config);
        assert!(findings.is_empty(), "Single input cannot be a cluster merge");
    }

    #[test]
    fn test_no_finding_when_only_one_our_input() {
        let our_addr = regtest_p2tr_address();
        let ext_addr = regtest_p2tr_address();
        let out_addr = regtest_p2tr_address();

        let recv1 = make_txid(1);
        let recv2 = make_txid(2);
        let spend = make_txid(3);

        let graph = MockGraphBuilder::new()
            .with_address(our_addr.clone())
            // ext_addr not registered as ours
            .with_receive_tx(recv1, our_addr.clone(), 100_000)
            .with_receive_tx(recv2, ext_addr.clone(), 200_000)
            .with_spend_tx(
                spend,
                vec![(recv1, 0, 100_000), (recv2, 0, 200_000)],
                vec![(out_addr.clone(), 295_000, false)],
            )
            .build();

        let config = test_config();
        let findings = ClusterMergeDetector.detect(&graph, &config);
        let relevant: Vec<_> = findings
            .iter()
            .filter(|f| f.details["txid"].as_str() == Some(&spend.to_string()))
            .collect();
        assert!(relevant.is_empty(), "Only 1 our input → no cluster merge");
    }

    #[test]
    fn test_details_contain_funding_sources() {
        let addr1 = regtest_p2tr_address();
        let addr2 = regtest_p2tr_address();
        let out_addr = regtest_p2tr_address();

        let gp1 = make_txid(1);
        let gp2 = make_txid(2);
        let recv1 = make_txid(3);
        let recv2 = make_txid(4);
        let spend_txid = make_txid(5);

        let graph = MockGraphBuilder::new()
            .with_address(addr1.clone())
            .with_address(addr2.clone())
            .with_address(out_addr.clone())
            .with_receive_tx(gp1, addr1.clone(), 200_000)
            .with_receive_tx(gp2, addr2.clone(), 200_000)
            .with_spend_tx(
                recv1,
                vec![(gp1, 0, 200_000)],
                vec![(addr1.clone(), 199_000, false)],
            )
            .with_spend_tx(
                recv2,
                vec![(gp2, 0, 200_000)],
                vec![(addr2.clone(), 199_000, false)],
            )
            .with_spend_tx(
                spend_txid,
                vec![(recv1, 0, 199_000), (recv2, 0, 199_000)],
                vec![(out_addr.clone(), 397_000, false)],
            )
            .build();

        let config = test_config();
        let findings = ClusterMergeDetector.detect(&graph, &config);

        assert!(!findings.is_empty());
        let sources = &findings[0].details["funding_sources"];
        assert!(sources.is_object(), "funding_sources should be an object");
        assert_eq!(
            sources.as_object().unwrap().len(),
            2,
            "Should have 2 funding source keys"
        );
    }
}
