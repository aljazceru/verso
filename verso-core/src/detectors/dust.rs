use std::collections::HashSet;

use serde_json::json;

use crate::config::ScanConfig;
use crate::graph::GraphView;
use crate::report::{Finding, FindingCategory, FindingType, Severity};

use super::Detector;

const STRICT_DUST_SATS: u64 = 546;
const DUST_SATS: u64 = 1000;

pub struct DustDetector;

impl Detector for DustDetector {
    fn name(&self) -> &'static str {
        "dust"
    }

    fn index(&self) -> u8 {
        3
    }

    fn detect(&self, graph: &dyn GraphView, _config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        // ── Current UTXOs ─────────────────────────────────────────────────────
        // Track (txid, address) pairs already reported as unspent dust so we
        // can skip them in the historical scan.
        let mut unspent_dust_keys: HashSet<(String, String)> = HashSet::new();

        for utxo in graph.utxos() {
            if utxo.value_sats <= DUST_SATS {
                let severity = if utxo.value_sats <= STRICT_DUST_SATS {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let txid_str = utxo.txid.to_string();
                let addr_str = utxo.address.as_ref().map(|a| a.to_string()).unwrap_or_default();
                unspent_dust_keys.insert((txid_str.clone(), addr_str));

                findings.push(Finding {
                    finding_type: FindingType::Dust,
                    severity,
                    description: "Wallet contains dust UTXO".to_string(),
                    details: json!({
                        "txid": txid_str,
                        "vout": utxo.vout,
                        "amount_sats": utxo.value_sats,
                        "status": "unspent",
                    }),
                    correction: Some(
                        "Do not spend this dust UTXO — doing so links your other inputs to this \
                         address via CIOH. Use your wallet's coin freeze / UTXO management \
                         feature to exclude it from future transactions. If the wallet does not \
                         support freezing, consider processing it through a CoinJoin round so the \
                         tracking token is obfuscated before it touches any of your real UTXOs."
                            .to_string(),
                    ),
                    category: FindingCategory::Finding,
                });
            }
        }

        // ── Historical outputs (already spent dust) ───────────────────────────
        // Deduplicate by (txid, address) to avoid double-reporting.
        let mut seen_hist: HashSet<(String, String)> = HashSet::new();

        for txid in graph.our_txids() {
            let outputs = graph.output_addresses(txid);
            for (vout_idx, out) in outputs.iter().enumerate() {
                if out.is_ours && out.value_sats <= DUST_SATS {
                    let txid_str = txid.to_string();
                    let addr_str = out.address.as_ref().map(|a| a.to_string()).unwrap_or_default();
                    let key = (txid_str.clone(), addr_str.clone());

                    // Skip if already reported as an unspent UTXO
                    if unspent_dust_keys.contains(&(txid_str.clone(), addr_str)) {
                        continue;
                    }

                    if seen_hist.insert(key) {
                        findings.push(Finding {
                            finding_type: FindingType::Dust,
                            severity: Severity::Low,
                            description: "Wallet received dust output (already spent)".to_string(),
                            details: json!({
                                "txid": txid_str,
                                "vout": vout_idx,
                                "amount_sats": out.value_sats,
                                "status": "spent",
                            }),
                            correction: Some(
                                "This dust has already been spent, so the tracking link is \
                                 already on-chain. Going forward, reject unsolicited dust by \
                                 enabling automatic dust rejection in your wallet, or use wallet \
                                 software that warns before spending dust-class UTXOs."
                                    .to_string(),
                            ),
                            category: FindingCategory::Finding,
                        });
                    }
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
    fn test_detects_strict_dust_utxo_as_high() {
        let addr = regtest_p2tr_address();
        let txid =
            make_txid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_utxo(txid, 0, addr.clone(), 546, 6)
            .build();

        let config = test_config();
        let findings = DustDetector.detect(&graph, &config);

        assert!(!findings.is_empty());
        let f = findings.iter().find(|f| f.severity == Severity::High).unwrap();
        assert_eq!(f.finding_type, FindingType::Dust);
        assert_eq!(f.details["amount_sats"].as_u64().unwrap(), 546);
    }

    #[test]
    fn test_detects_dust_class_utxo_as_medium() {
        let addr = regtest_p2tr_address();
        let txid =
            make_txid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_utxo(txid, 0, addr.clone(), 800, 6)
            .build();

        let config = test_config();
        let findings = DustDetector.detect(&graph, &config);

        assert!(!findings.is_empty());
        let f = findings.iter().find(|f| f.severity == Severity::Medium).unwrap();
        assert_eq!(f.finding_type, FindingType::Dust);
        assert_eq!(f.details["amount_sats"].as_u64().unwrap(), 800);
    }

    #[test]
    fn test_no_dust_finding_for_normal_utxo() {
        let addr = regtest_p2tr_address();
        let txid =
            make_txid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_utxo(txid, 0, addr.clone(), 100_000, 6)
            .build();

        let config = test_config();
        let findings = DustDetector.detect(&graph, &config);
        assert!(findings.is_empty(), "Normal UTXO should not be flagged");
    }

    #[test]
    fn test_detects_historical_dust_output_as_low() {
        let addr = regtest_p2tr_address();
        let txid =
            make_txid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        // Receive a dust amount in a tx but don't add it as a UTXO (simulates spent dust)
        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_receive_tx(txid, addr.clone(), 546)
            // No UTXO added → it's been spent
            .build();

        let config = test_config();
        let findings = DustDetector.detect(&graph, &config);

        assert!(!findings.is_empty(), "Expected historical dust finding");
        let low_findings: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Low).collect();
        assert!(!low_findings.is_empty(), "Historical dust should be Low severity");
        assert_eq!(low_findings[0].details["status"].as_str().unwrap(), "spent");
    }

    #[test]
    fn test_utxo_boundary_at_1000_included() {
        let addr = regtest_p2tr_address();
        let txid =
            make_txid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_utxo(txid, 0, addr.clone(), 1000, 6)
            .build();

        let config = test_config();
        let findings = DustDetector.detect(&graph, &config);
        assert!(!findings.is_empty(), "1000 sats is dust boundary — should be flagged");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_utxo_above_dust_not_flagged() {
        let addr = regtest_p2tr_address();
        let txid =
            make_txid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_utxo(txid, 0, addr.clone(), 1001, 6)
            .build();

        let config = test_config();
        let findings = DustDetector.detect(&graph, &config);
        assert!(findings.is_empty(), "1001 sats is above dust — should not be flagged");
    }
}
