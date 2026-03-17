pub mod backend;
pub mod config;
pub mod detectors;
pub mod error;
pub mod graph;
pub mod report;
pub mod storage;
pub(crate) mod scanner;

pub use backend::ChainBackend;
pub use config::ScanConfig;
pub use error::VersoError;
pub use graph::{GraphView, InputInfo, MockGraphBuilder, MockWalletGraph, OutputInfo, ScriptType, WalletGraph};
pub use report::Report;

use crate::scanner::Scanner;
use crate::backend::{BitcoindBackend, EsploraBackend};
use crate::graph::WalletGraph as WG;
use crate::config::{BackendConfig, ScanProgress};
use crate::report::{Stats, Summary, FindingCategory, Severity};

pub async fn scan(config: ScanConfig) -> Result<Report, VersoError> {
    // Progress helper closure
    let send_progress = |phase: &str, message: &str| {
        if let Some(tx) = &config.progress_tx {
            let _ = tx.send(ScanProgress {
                phase: phase.to_string(),
                message: message.to_string(),
                percent: None,
            });
        }
    };

    // 1. Create scanner (parse descriptors + create/load wallet)
    send_progress("init", "Parsing descriptors...");
    let scanner = Scanner::new(&config).await?;

    // 2. Create the chain backend
    send_progress("connect", "Connecting to backend...");
    let backend: Box<dyn ChainBackend> = match &config.backend {
        BackendConfig::Bitcoind { url, auth } => {
            Box::new(
                BitcoindBackend::new(url, auth, config.network)
                    .map_err(|e| VersoError::BackendConnection(e.to_string()))?,
            )
        }
        BackendConfig::Esplora { url } => {
            Box::new(
                EsploraBackend::new(url, config.network, config.derivation_limit)
                    .map_err(|e| VersoError::BackendConnection(e.to_string()))?,
            )
        }
    };

    // 3. Consume the scanner and extract the wallet kind so we can mutably sync
    //    it then move it into WalletGraph::build().
    let mut wallet_kind = scanner.into_wallet();

    // 4. Sync wallet via backend
    send_progress("sync", "Syncing with blockchain...");
    {
        let wallet_mut = wallet_kind.as_mut_wallet();
        backend
            .full_sync(wallet_mut, config.progress_tx.as_ref())
            .await?;
    }

    // 5. For persisted wallets, flush staged changes back to the SQLite store.
    //    Ephemeral wallets skip this step (no-op).
    wallet_kind.persist_if_needed().await?;

    // 6. Move the WalletKind into WalletGraph::build().  The graph holds it
    //    and uses as_wallet() / as_mut_wallet() for all subsequent access.
    send_progress("analyze", "Building transaction graph...");
    let graph = WG::build(wallet_kind, backend.as_ref(), config.network).await?;

    // 7. Run all 12 detectors
    send_progress("detect", "Running privacy analysis...");
    let all_detectors = detectors::all_detectors();
    let all_findings = detectors::run_all(&all_detectors, &graph, &config);

    // 8. Separate findings from warnings
    let (findings, warnings): (Vec<_>, Vec<_>) = all_findings
        .into_iter()
        .partition(|f| f.category == FindingCategory::Finding);

    // 9. Compute stats
    let stats = Stats {
        total_txs: graph.our_txids().len(),
        total_addresses: graph.our_addresses().len(),
        total_utxos: graph.utxos().len(),
        finding_count: findings.len(),
        warning_count: warnings.len(),
    };

    // 10. Compute summary
    let max_severity = findings.iter().chain(warnings.iter())
        .map(|f| f.severity.clone())
        .max()
        .unwrap_or(Severity::Low);
    let summary = Summary {
        clean: findings.is_empty() && warnings.is_empty(),
        risk_level: max_severity,
        top_issues: findings
            .iter()
            .take(3)
            .map(|f| f.description.clone())
            .collect(),
    };

    Ok(Report {
        findings,
        warnings,
        stats,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use crate::config::BackendConfig;

    // Standard BDK testnet extended public key (same one used in scanner tests).
    const TPUB: &str = "tpubD6NzVbkrYhZ4XHndKkuB8FifXm8r5FQHwrN6oZuWCz13qb93rtgKvD4PQsqC4HP4yhV3tA2fqr2RbY5mNXfM7RxXUoeABoDtsFUq2zJq6YK";

    fn ext_desc() -> String {
        format!("wpkh({}/0/*)", TPUB)
    }

    fn int_desc() -> String {
        format!("wpkh({}/1/*)", TPUB)
    }

    fn ephemeral_config() -> ScanConfig {
        ScanConfig {
            descriptors: vec![ext_desc(), int_desc()],
            network: Network::Testnet,
            backend: BackendConfig::Esplora {
                url: "https://mempool.space/testnet/api".to_string(),
            },
            known_risky_txids: None,
            known_exchange_txids: None,
            derivation_limit: 5,
            data_dir: None,
            ephemeral: true,
            progress_tx: None,
        }
    }

    /// Verify that scanner creation and wallet access work correctly for an
    /// ephemeral wallet (no network I/O required).
    #[tokio::test]
    async fn test_scanner_extract_ephemeral_wallet() {
        let config = ephemeral_config();
        let scanner = Scanner::new(&config).await.expect("Scanner::new failed");
        let wallet_kind = scanner.into_wallet();
        // as_wallet() must succeed without panicking.
        let _wallet = wallet_kind.as_wallet();
    }

    /// Verify the finding/warning partition logic independently.
    #[test]
    fn test_finding_warning_partition() {
        use crate::report::{Finding, FindingCategory, FindingType, Severity};

        let mut f1 = Finding {
            finding_type: FindingType::AddressReuse,
            severity: Severity::High,
            description: "addr reuse".to_string(),
            details: serde_json::Value::Null,
            correction: None,
            category: FindingCategory::Finding,
        };
        let mut f2 = Finding {
            finding_type: FindingType::Dust,
            severity: Severity::Low,
            description: "dust".to_string(),
            details: serde_json::Value::Null,
            correction: None,
            category: FindingCategory::Warning,
        };

        // Clone into a vec and partition.
        f1.category = FindingCategory::Finding;
        f2.category = FindingCategory::Warning;
        let all = vec![f1, f2];
        let (findings, warnings): (Vec<_>, Vec<_>) =
            all.into_iter().partition(|f| f.category == FindingCategory::Finding);

        assert_eq!(findings.len(), 1);
        assert_eq!(warnings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(warnings[0].severity, Severity::Low);
    }

    /// Verify that Stats and Summary are computed correctly for an empty wallet.
    #[test]
    fn test_empty_report_is_clean() {
        use crate::report::{Stats, Summary, Severity};

        let findings: Vec<crate::report::Finding> = vec![];
        let warnings: Vec<crate::report::Finding> = vec![];

        let stats = Stats {
            total_txs: 0,
            total_addresses: 0,
            total_utxos: 0,
            finding_count: findings.len(),
            warning_count: warnings.len(),
        };

        let max_severity = findings
            .iter()
            .map(|f| f.severity.clone())
            .max()
            .unwrap_or(Severity::Low);

        let summary = Summary {
            clean: findings.is_empty() && warnings.is_empty(),
            risk_level: max_severity,
            top_issues: findings.iter().take(3).map(|f| f.description.clone()).collect(),
        };

        assert!(summary.clean);
        assert_eq!(summary.risk_level, Severity::Low);
        assert!(summary.top_issues.is_empty());
        assert_eq!(stats.finding_count, 0);
        assert_eq!(stats.warning_count, 0);
    }
}
