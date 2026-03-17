use verso_core::report::FindingType;
use verso_tests::regtest_harness::RegtestHarness;
use verso_tests::scenarios;

#[tokio::test]
async fn test_02_cioh_regtest() {
    let h = RegtestHarness::new();
    h.create_wallet("alice");
    h.create_wallet("bob");
    scenarios::scenario_02_cioh(&h);
    h.mine_blocks(1);
    let report = h.scan_wallet("alice").await;
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.finding_type == FindingType::Cioh),
        "Expected to find {:?} but got findings: {:?}",
        FindingType::Cioh,
        report
            .findings
            .iter()
            .map(|f| &f.finding_type)
            .collect::<Vec<_>>()
    );
}
