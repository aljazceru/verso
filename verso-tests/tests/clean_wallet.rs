use verso_tests::regtest_harness::RegtestHarness;

#[tokio::test]
async fn test_clean_wallet_has_no_findings() {
    let h = RegtestHarness::new();
    h.create_wallet("alice");

    // Fund alice with one clean normal UTXO
    let alice_addr = h.new_address("alice");
    h.send_from("miner", &alice_addr, 0.1);
    h.mine_blocks(1);

    let report = h.scan_wallet("alice").await;
    assert!(
        report.summary.clean,
        "Expected clean wallet but got findings: {:?}, warnings: {:?}",
        report.findings, report.warnings
    );
    assert!(
        report.findings.is_empty(),
        "Expected no findings but got: {:?}",
        report.findings
    );
}
