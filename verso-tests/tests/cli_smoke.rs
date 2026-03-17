use verso_tests::regtest_harness::RegtestHarness;

/// Locate the verso-cli binary.  Cargo sets CARGO_BIN_EXE_verso-cli for
/// integration tests in the same crate that owns the binary; for tests in a
/// *sibling* crate we fall back to finding the binary in the Cargo target dir.
fn verso_cli_bin() -> std::path::PathBuf {
    // 1. Try the runtime env var set by Cargo for same-crate integration tests.
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_verso-cli") {
        return std::path::PathBuf::from(p);
    }

    // 2. Walk up from CARGO_MANIFEST_DIR to the workspace target directory.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR should be set when running under cargo test");
    let workspace_root = std::path::Path::new(&manifest_dir)
        .parent()
        .expect("verso-tests lives one level below the workspace root");

    // Check debug first, then release.
    for profile in &["debug", "release"] {
        let candidate = workspace_root
            .join("target")
            .join(profile)
            .join("verso-cli");
        if candidate.exists() {
            return candidate;
        }
    }

    panic!(
        "Could not find verso-cli binary. Run `cargo build -p verso-cli` first."
    );
}

#[tokio::test]
async fn test_cli_json_output_valid() {
    let h = RegtestHarness::new();
    h.create_wallet("alice");

    let alice_addr = h.new_address("alice");
    h.send_from("miner", &alice_addr, 0.1);
    h.mine_blocks(1);

    let descriptors = h.get_descriptors("alice");
    let rpc_url = h.bitcoind.rpc_url();
    let cookie = h
        .bitcoind
        .params
        .cookie_file
        .to_str()
        .unwrap()
        .to_string();

    let mut args = vec![
        "--network".to_string(),
        "regtest".to_string(),
        "--backend".to_string(),
        "bitcoind".to_string(),
        "--bitcoind-url".to_string(),
        rpc_url,
        "--bitcoind-cookie".to_string(),
        cookie,
        "--no-persist".to_string(),
    ];
    for desc in &descriptors {
        args.push(desc.clone());
    }

    let output = std::process::Command::new(verso_cli_bin())
        .args(&args)
        .output()
        .expect("Failed to run verso-cli");

    assert!(
        output.status.success(),
        "CLI failed with stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: verso_core::report::Report = serde_json::from_slice(&output.stdout)
        .expect("CLI output should be valid JSON Report");

    assert!(
        report.stats.addresses_derived > 0,
        "Expected at least one scanned address"
    );
}
