use verso_tests::regtest_harness::RegtestHarness;
use verso_tests::scenarios;
use verso_core::report::FindingType;

#[tokio::test]
async fn test_10_exchange_origin_regtest() {
    let h = RegtestHarness::new();
    h.create_wallet("alice");
    h.create_wallet("bob");
    h.create_wallet("carol");
    h.create_wallet("exchange");
    scenarios::scenario_10_exchange_origin(&h);
    h.mine_blocks(1);
    let report = h.scan_wallet("alice").await;
    assert!(
        report.findings.iter().any(|f| f.finding_type == FindingType::ExchangeOrigin)
            || report.warnings.iter().any(|f| f.finding_type == FindingType::ExchangeOrigin),
        "Expected to find {:?} but got findings: {:?}, warnings: {:?}",
        FindingType::ExchangeOrigin,
        report.findings.iter().map(|f| &f.finding_type).collect::<Vec<_>>(),
        report.warnings.iter().map(|f| &f.finding_type).collect::<Vec<_>>()
    );
}
