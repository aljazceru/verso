use verso_core::report::FindingType;
use verso_tests::regtest_harness::RegtestHarness;
use verso_tests::scenarios;

#[tokio::test]
async fn test_05_change_detection_regtest() {
    let h = RegtestHarness::new();
    h.create_wallet("alice");
    h.create_wallet("bob");
    scenarios::scenario_05_change_detection(&h);
    h.mine_blocks(1);
    let report = h.scan_wallet("alice").await;
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.finding_type == FindingType::ChangeDetection)
            || report
                .warnings
                .iter()
                .any(|f| f.finding_type == FindingType::ChangeDetection),
        "Expected to find {:?} but got findings: {:?}, warnings: {:?}",
        FindingType::ChangeDetection,
        report
            .findings
            .iter()
            .map(|f| &f.finding_type)
            .collect::<Vec<_>>(),
        report
            .warnings
            .iter()
            .map(|f| &f.finding_type)
            .collect::<Vec<_>>()
    );
}
