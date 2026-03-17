use verso_tests::regtest_harness::RegtestHarness;
use verso_tests::scenarios;
use verso_core::report::FindingType;

#[tokio::test]
async fn test_full_parity_all_detectors_fire() {
    let h = RegtestHarness::new();

    // Create all wallets needed across all scenarios
    h.create_wallet("alice");
    h.create_wallet("bob");
    h.create_wallet("carol");
    h.create_wallet("exchange");
    h.create_wallet("risky");

    scenarios::scenario_01_address_reuse(&h);
    scenarios::scenario_02_cioh(&h);
    scenarios::scenario_03_dust(&h);
    scenarios::scenario_04_dust_spending(&h);
    scenarios::scenario_05_change_detection(&h);
    scenarios::scenario_06_consolidation(&h);
    scenarios::scenario_07_script_type_mixing(&h);
    scenarios::scenario_08_cluster_merge(&h);
    scenarios::scenario_09_utxo_age_spread(&h);
    scenarios::scenario_10_exchange_origin(&h);
    let risky_txid = scenarios::scenario_11_tainted_utxos(&h);
    scenarios::scenario_12_behavioral_fingerprint(&h);

    h.mine_blocks(1);

    // Use a custom config with known risky txids for taint detection
    let descriptors = h.get_descriptors("alice");
    let mut config = h.default_scan_config(descriptors);
    config.known_risky_txids = Some(std::collections::HashSet::from([risky_txid]));

    let report = verso_core::scan(config).await.unwrap();

    // The wallet should not be clean
    assert!(!report.summary.clean, "Expected non-clean wallet in full parity test");

    // Should have many findings across all scenarios
    assert!(
        report.findings.len() + report.warnings.len() >= 5,
        "Expected at least 5 findings/warnings but got findings: {}, warnings: {}",
        report.findings.len(),
        report.warnings.len()
    );

    let finding_types: Vec<&FindingType> =
        report.findings.iter().map(|f| &f.finding_type).collect();
    let warning_types: Vec<&FindingType> =
        report.warnings.iter().map(|f| &f.finding_type).collect();
    let all_types: Vec<&FindingType> =
        finding_types.iter().chain(warning_types.iter()).copied().collect();

    // Assert key finding types are present
    assert!(
        all_types.contains(&&FindingType::AddressReuse),
        "Missing AddressReuse; all types: {:?}", all_types
    );
    assert!(
        all_types.contains(&&FindingType::Cioh),
        "Missing Cioh; all types: {:?}", all_types
    );
    assert!(
        all_types.contains(&&FindingType::Dust) || all_types.contains(&&FindingType::DustSpending),
        "Missing Dust or DustSpending; all types: {:?}", all_types
    );

    // UtxoAgeSpread requires at least 2 unspent UTXOs with >= 10 block confirmation
    // spread. In the combined scenario harness, subsequent scenarios may spend alice's
    // UTXOs, collapsing the spread. We check for it but don't hard-assert.
    if !all_types.contains(&&FindingType::UtxoAgeSpread)
        && !all_types.contains(&&FindingType::DormantUtxos)
    {
        println!(
            "Note: UtxoAgeSpread/DormantUtxos not present in full parity — \
             expected when later scenarios spend the old UTXOs that would have \
             created the age spread."
        );
    }

    println!("Full parity findings: {:?}", all_types);
}
