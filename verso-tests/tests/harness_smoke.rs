use bitcoincore_rpc::RpcApi;
use verso_tests::regtest_harness::RegtestHarness;

#[tokio::test]
async fn test_harness_boots() {
    let h = RegtestHarness::new();
    // Verify the chain is at height >= 110.
    let info = h.client.get_blockchain_info().unwrap();
    assert!(
        info.blocks >= 110,
        "Expected >= 110 blocks, got {}",
        info.blocks
    );
}

#[tokio::test]
async fn test_wallets_can_be_created_and_funded() {
    let h = RegtestHarness::new();
    h.create_wallet("alice");
    h.create_wallet("bob");

    h.ensure_funds("alice", 0.5);

    let utxos = h.list_utxos("alice");
    assert!(!utxos.is_empty(), "alice should have at least one UTXO");
}
