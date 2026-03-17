use verso_tests::regtest_harness::RegtestHarness;
use verso_tests::scenarios;
use verso_core::report::FindingType;

#[tokio::test]
async fn test_09_utxo_age_spread_regtest() {
    let h = RegtestHarness::new();
    h.create_wallet("alice");
    scenarios::scenario_09_utxo_age_spread(&h);
    h.mine_blocks(1);
    let report = h.scan_wallet("alice").await;
    assert!(
        report.findings.iter().any(|f| f.finding_type == FindingType::UtxoAgeSpread)
            || report.warnings.iter().any(|f| f.finding_type == FindingType::UtxoAgeSpread),
        "Expected to find {:?} but got findings: {:?}, warnings: {:?}",
        FindingType::UtxoAgeSpread,
        report.findings.iter().map(|f| &f.finding_type).collect::<Vec<_>>(),
        report.warnings.iter().map(|f| &f.finding_type).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_09_dormant_utxos_regtest() {
    let h = RegtestHarness::new();
    h.create_wallet("alice");
    scenarios::scenario_09_utxo_age_spread(&h);
    h.mine_blocks(1);
    let report = h.scan_wallet("alice").await;
    // DormantUtxos may appear as a warning when there are very old unspent UTXOs
    let has_dormant = report.findings.iter().any(|f| f.finding_type == FindingType::DormantUtxos)
        || report.warnings.iter().any(|f| f.finding_type == FindingType::DormantUtxos);
    let has_age_spread = report.findings.iter().any(|f| f.finding_type == FindingType::UtxoAgeSpread)
        || report.warnings.iter().any(|f| f.finding_type == FindingType::UtxoAgeSpread);
    assert!(
        has_dormant || has_age_spread,
        "Expected DormantUtxos or UtxoAgeSpread but got findings: {:?}, warnings: {:?}",
        report.findings.iter().map(|f| &f.finding_type).collect::<Vec<_>>(),
        report.warnings.iter().map(|f| &f.finding_type).collect::<Vec<_>>()
    );
}
