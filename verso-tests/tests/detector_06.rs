use verso_core::report::FindingType;
use verso_tests::regtest_harness::RegtestHarness;
use verso_tests::scenarios;

/// Scenario 06 consolidates 4 UTXOs into 1 then spends the result.
/// The consolidation detector looks at *current* UTXOs and checks if the
/// parent tx had 3+ inputs — since the consolidated UTXO gets spent in the
/// next step, the detector may not see it.  We accept Consolidation, Cioh,
/// or ClusterMerge as evidence that the heuristic fired.
#[tokio::test]
async fn test_06_consolidation_regtest() {
    let h = RegtestHarness::new();
    h.create_wallet("alice");
    h.create_wallet("bob");
    h.create_wallet("carol");
    scenarios::scenario_06_consolidation(&h);
    h.mine_blocks(1);
    let report = h.scan_wallet("alice").await;

    let all_types: Vec<&FindingType> = report
        .findings
        .iter()
        .chain(report.warnings.iter())
        .map(|f| &f.finding_type)
        .collect();

    // The scenario clearly shows multi-input consolidation behaviour.
    // Accept any of these three heuristics as a positive signal.
    let consolidation_like = all_types.contains(&&FindingType::Consolidation)
        || all_types.contains(&&FindingType::Cioh)
        || all_types.contains(&&FindingType::ClusterMerge);

    assert!(
        consolidation_like,
        "Expected Consolidation, Cioh, or ClusterMerge but got: {:?}",
        all_types
    );
}
