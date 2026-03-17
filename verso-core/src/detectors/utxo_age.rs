use serde_json::json;

use crate::config::ScanConfig;
use crate::graph::GraphView;
use crate::report::{Finding, FindingCategory, FindingType, Severity};

use super::Detector;

pub struct UtxoAgeDetector;

impl Detector for UtxoAgeDetector {
    fn name(&self) -> &'static str {
        "utxo_age"
    }

    fn index(&self) -> u8 {
        9
    }

    fn detect(&self, graph: &dyn GraphView, _config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        let utxos = graph.utxos();
        // Only consider confirmed UTXOs (confirmations > 0)
        let mut confirmed: Vec<_> = utxos.iter().filter(|u| u.confirmations > 0).collect();

        if confirmed.len() < 2 {
            return findings;
        }

        // Sort by confirmations descending: oldest (most confirmations) first
        confirmed.sort_by(|a, b| b.confirmations.cmp(&a.confirmations));

        let oldest = confirmed.first().unwrap();
        let newest = confirmed.last().unwrap();
        let spread = oldest.confirmations - newest.confirmations;

        if spread >= 10 {
            findings.push(Finding {
                finding_type: FindingType::UtxoAgeSpread,
                severity: Severity::Low,
                description: format!(
                    "UTXO age spread of {} blocks between oldest and newest confirmed UTXO",
                    spread
                ),
                details: json!({
                    "oldest_confs": oldest.confirmations,
                    "newest_confs": newest.confirmations,
                    "spread": spread,
                }),
                correction: Some(
                    "Prefer spending older UTXOs first (FIFO coin selection) to normalize the age \
                     distribution of your UTXO set and avoid leaving very old coins as obvious \
                     dormancy markers. Alternatively, route very old UTXOs through a CoinJoin to \
                     reset their history before spending. Avoid holding large numbers of \
                     long-dormant coins in the same wallet as freshly received funds."
                        .to_string(),
                ),
                category: FindingCategory::Finding,
            });
        }

        // DORMANT_UTXOS: any UTXO with >= 100 confirmations
        const DORMANT_THRESHOLD: u32 = 100;
        let dormant: Vec<_> = confirmed
            .iter()
            .filter(|u| u.confirmations >= DORMANT_THRESHOLD)
            .collect();

        if !dormant.is_empty() {
            let utxo_details: Vec<serde_json::Value> = dormant
                .iter()
                .map(|u| {
                    json!({
                        "txid": u.txid.to_string(),
                        "vout": u.vout,
                        "amount_sats": u.value_sats,
                        "confirmations": u.confirmations,
                    })
                })
                .collect();

            findings.push(Finding {
                finding_type: FindingType::DormantUtxos,
                severity: Severity::Low,
                description: format!(
                    "{} UTXO(s) have >= {} confirmations (dormant/hoarded coins pattern)",
                    dormant.len(),
                    DORMANT_THRESHOLD
                ),
                details: json!({ "utxos": utxo_details }),
                correction: None,
                category: FindingCategory::Warning,
            });
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
    fn test_no_findings_when_no_utxos() {
        let graph = MockGraphBuilder::new().build();
        let config = test_config();
        let findings = UtxoAgeDetector.detect(&graph, &config);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_findings_single_utxo() {
        let addr = p2tr_addr();
        let txid = make_txid(1);
        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_utxo(txid, 0, addr.clone(), 100_000, 50)
            .build();
        let config = test_config();
        let findings = UtxoAgeDetector.detect(&graph, &config);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_findings_small_spread() {
        let addr = p2tr_addr();
        let t1 = make_txid(1);
        let t2 = make_txid(2);
        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_utxo(t1, 0, addr.clone(), 100_000, 5)
            .with_utxo(t2, 0, addr.clone(), 100_000, 10)
            .build();
        let config = test_config();
        let findings = UtxoAgeDetector.detect(&graph, &config);
        // spread = 10 - 5 = 5, below threshold
        assert!(findings.is_empty());
    }

    #[test]
    fn test_utxo_age_spread_finding() {
        let addr = p2tr_addr();
        let t1 = make_txid(1);
        let t2 = make_txid(2);
        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_utxo(t1, 0, addr.clone(), 100_000, 5)
            .with_utxo(t2, 0, addr.clone(), 100_000, 50)
            .build();
        let config = test_config();
        let findings = UtxoAgeDetector.detect(&graph, &config);
        // spread = 50 - 5 = 45, >= 10
        let spread_finding = findings
            .iter()
            .find(|f| f.finding_type == FindingType::UtxoAgeSpread);
        assert!(spread_finding.is_some(), "Should detect UTXO age spread");
        let f = spread_finding.unwrap();
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(f.category, FindingCategory::Finding);
        assert!(f.correction.is_some());
        assert_eq!(f.details["spread"].as_u64().unwrap(), 45);
    }

    #[test]
    fn test_dormant_utxos_warning() {
        let addr = p2tr_addr();
        let t1 = make_txid(1);
        let t2 = make_txid(2);
        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_utxo(t1, 0, addr.clone(), 100_000, 5)
            .with_utxo(t2, 0, addr.clone(), 100_000, 150)
            .build();
        let config = test_config();
        let findings = UtxoAgeDetector.detect(&graph, &config);
        let dormant_finding = findings
            .iter()
            .find(|f| f.finding_type == FindingType::DormantUtxos);
        assert!(dormant_finding.is_some(), "Should detect dormant UTXOs");
        let f = dormant_finding.unwrap();
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(f.category, FindingCategory::Warning);
        assert!(f.correction.is_none());
        let utxos = f.details["utxos"].as_array().unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0]["confirmations"].as_u64().unwrap(), 150);
    }

    #[test]
    fn test_both_findings_emitted() {
        let addr = p2tr_addr();
        let t1 = make_txid(1);
        let t2 = make_txid(2);
        // spread=145 (>=10), oldest=150 (>=100)
        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_utxo(t1, 0, addr.clone(), 100_000, 5)
            .with_utxo(t2, 0, addr.clone(), 100_000, 150)
            .build();
        let config = test_config();
        let findings = UtxoAgeDetector.detect(&graph, &config);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_unconfirmed_utxos_excluded() {
        let addr = p2tr_addr();
        let t1 = make_txid(1);
        let t2 = make_txid(2);
        // t1 has 0 confirmations (unconfirmed), t2 has 1
        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_utxo(t1, 0, addr.clone(), 100_000, 0)
            .with_utxo(t2, 0, addr.clone(), 100_000, 1)
            .build();
        let config = test_config();
        let findings = UtxoAgeDetector.detect(&graph, &config);
        // Only 1 confirmed UTXO, so no age spread possible
        assert!(findings.is_empty());
    }
}
