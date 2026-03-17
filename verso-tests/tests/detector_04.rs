use verso_tests::regtest_harness::RegtestHarness;
use verso_tests::scenarios;
use verso_core::report::FindingType;

#[tokio::test]
async fn test_04_dust_spending_regtest() {
    let h = RegtestHarness::new();
    h.create_wallet("alice");
    h.create_wallet("bob");
    scenarios::scenario_04_dust_spending(&h);
    h.mine_blocks(1);
    let report = h.scan_wallet("alice").await;
    assert!(
        report.findings.iter().any(|f| f.finding_type == FindingType::DustSpending)
            || report.warnings.iter().any(|f| f.finding_type == FindingType::DustSpending),
        "Expected to find {:?} but got findings: {:?}, warnings: {:?}",
        FindingType::DustSpending,
        report.findings.iter().map(|f| &f.finding_type).collect::<Vec<_>>(),
        report.warnings.iter().map(|f| &f.finding_type).collect::<Vec<_>>()
    );
}
