use verso_tests::regtest_harness::RegtestHarness;
use verso_tests::scenarios;
use verso_core::report::FindingType;

#[tokio::test]
async fn test_11_tainted_regtest() {
    let h = RegtestHarness::new();
    h.create_wallet("alice");
    h.create_wallet("bob");
    h.create_wallet("carol");
    h.create_wallet("risky");
    let risky_txid = scenarios::scenario_11_tainted_utxos(&h);
    h.mine_blocks(1);

    // Use a custom scan config with the known risky txid
    let descriptors = h.get_descriptors("alice");
    let mut config = h.default_scan_config(descriptors);
    config.known_risky_txids = Some(std::collections::HashSet::from([risky_txid]));

    let report = verso_core::scan(config).await.unwrap();
    assert!(
        report.findings.iter().any(|f| f.finding_type == FindingType::TaintedUtxoMerge)
            || report.warnings.iter().any(|f| f.finding_type == FindingType::DirectTaint)
            || report.findings.iter().any(|f| f.finding_type == FindingType::DirectTaint),
        "Expected TaintedUtxoMerge or DirectTaint but got findings: {:?}, warnings: {:?}",
        report.findings.iter().map(|f| &f.finding_type).collect::<Vec<_>>(),
        report.warnings.iter().map(|f| &f.finding_type).collect::<Vec<_>>()
    );
}
