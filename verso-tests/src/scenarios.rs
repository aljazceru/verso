//! Ported from stealth/backend/script/reproduce.py.
//!
//! Each function creates the on-chain condition that triggers its corresponding
//! privacy detector.  The functions only *create* transactions; assertion
//! logic lives in the caller (integration tests).

use std::collections::HashMap;

use bitcoin::Amount;
use bitcoincore_rpc::json::CreateRawTransactionInput;

use crate::regtest_harness::RegtestHarness;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn sats(n: u64) -> Amount {
    Amount::from_sat(n)
}

fn btc(n: f64) -> Amount {
    Amount::from_btc(n).unwrap()
}

// ─── 1. Address Reuse ────────────────────────────────────────────────────────

/// Bob sends to the same alice address twice.
pub fn scenario_01_address_reuse(h: &RegtestHarness) {
    h.ensure_funds("bob", 1.0);
    let reused = h.new_address("alice");
    h.send_from("bob", &reused, 0.01);
    h.send_from("bob", &reused, 0.02);
    h.mine_blocks(1);
}

// ─── 2. CIOH — Common Input Ownership Heuristic ──────────────────────────────

/// Bob funds five small UTXOs to alice; alice consolidates them in one tx.
pub fn scenario_02_cioh(h: &RegtestHarness) {
    h.ensure_funds("bob", 2.0);

    for _ in 0..5 {
        let addr = h.new_address("alice");
        h.send_from("bob", &addr, 0.005);
    }
    h.mine_blocks(1);

    // Collect the small UTXOs.
    let utxos = h.list_utxos("alice");
    let small: Vec<_> = utxos
        .iter()
        .filter(|u| {
            u.amount >= btc(0.004) && u.amount <= btc(0.006)
        })
        .take(5)
        .collect();

    if small.len() < 2 {
        return;
    }

    let total: Amount = small.iter().map(|u| u.amount).sum();
    let fee = sats(10_000);
    let dest = h.new_address("bob");

    let inputs: Vec<CreateRawTransactionInput> = small
        .iter()
        .map(|u| CreateRawTransactionInput { txid: u.txid, vout: u.vout, sequence: None })
        .collect();

    let mut outputs = HashMap::new();
    outputs.insert(dest.to_string(), total - fee);

    h.create_and_send("alice", &inputs, &outputs);
    h.mine_blocks(1);
}

// ─── 3. Dust UTXO Detection ──────────────────────────────────────────────────

/// Bob creates 1000-sat and 546-sat dust outputs to alice.
pub fn scenario_03_dust(h: &RegtestHarness) {
    h.ensure_funds("bob", 1.0);
    let dust1 = h.new_address("alice");
    let dust2 = h.new_address("alice");

    let bob_utxos = h.list_utxos("bob");
    let big = bob_utxos.iter().max_by_key(|u| u.amount).unwrap();
    let change = h.new_address("bob");

    let fee = sats(10_000);
    let d1 = sats(1_000);
    let d2 = sats(546);
    let change_amt = big.amount - d1 - d2 - fee;

    let inputs = vec![CreateRawTransactionInput {
        txid: big.txid,
        vout: big.vout,
        sequence: None,
    }];
    let mut outputs = HashMap::new();
    outputs.insert(dust1.to_string(), d1);
    outputs.insert(dust2.to_string(), d2);
    outputs.insert(change.to_string(), change_amt);

    h.create_and_send("bob", &inputs, &outputs);
    h.mine_blocks(1);
}

// ─── 4. Dust Spending with Normal Inputs ─────────────────────────────────────

/// Alice co-spends a dust UTXO together with a normal UTXO.
pub fn scenario_04_dust_spending(h: &RegtestHarness) {
    // Make sure alice has a dust UTXO.
    scenario_03_dust(h);
    h.ensure_funds("alice", 0.5);
    // mine to confirm the new funds
    h.mine_blocks(1);

    let utxos = h.list_utxos("alice");
    let dust_utxo = utxos.iter().find(|u| u.amount <= sats(10_000));
    let normal_utxo = utxos.iter().find(|u| u.amount > btc(0.001));

    let (dust, normal) = match (dust_utxo, normal_utxo) {
        (Some(d), Some(n)) => (d, n),
        _ => return, // not enough UTXOs to demonstrate
    };

    let total = dust.amount + normal.amount;
    let dest = h.new_address("bob");
    let fee = sats(10_000);

    let inputs = vec![
        CreateRawTransactionInput { txid: dust.txid, vout: dust.vout, sequence: None },
        CreateRawTransactionInput { txid: normal.txid, vout: normal.vout, sequence: None },
    ];
    let mut outputs = HashMap::new();
    outputs.insert(dest.to_string(), total - fee);

    h.create_and_send("alice", &inputs, &outputs);
    h.mine_blocks(1);
}

// ─── 5. Change Detection — Round Payment ─────────────────────────────────────

/// Alice pays bob a round 0.05 BTC; the change output is obvious.
pub fn scenario_05_change_detection(h: &RegtestHarness) {
    h.ensure_funds("alice", 1.0);
    let bob_addr = h.new_address("bob");
    h.send_from("alice", &bob_addr, 0.05);
    h.mine_blocks(1);
}

// ─── 6. Consolidation Origin ─────────────────────────────────────────────────

/// Alice consolidates 4 UTXOs then spends the consolidated output.
pub fn scenario_06_consolidation(h: &RegtestHarness) {
    h.ensure_funds("bob", 2.0);

    for _ in 0..4 {
        let addr = h.new_address("alice");
        h.send_from("bob", &addr, 0.003);
    }
    h.mine_blocks(1);

    // Collect small UTXOs, retrying if we don't have enough.
    let utxos = h.list_utxos("alice");
    let initial_small: Vec<_> = utxos
        .iter()
        .filter(|u| u.amount >= btc(0.002) && u.amount <= btc(0.004))
        .take(4)
        .cloned()
        .collect();

    let small: Vec<_> = if initial_small.len() < 3 {
        for _ in 0..4 {
            let addr = h.new_address("alice");
            h.send_from("bob", &addr, 0.003);
        }
        h.mine_blocks(1);
        h.list_utxos("alice")
            .into_iter()
            .filter(|u| u.amount >= btc(0.002) && u.amount <= btc(0.004))
            .take(4)
            .collect()
    } else {
        initial_small
    };

    let total: Amount = small.iter().map(|u| u.amount).sum();
    let consol_addr = h.new_address("alice");
    let fee = sats(10_000);

    let inputs: Vec<CreateRawTransactionInput> = small
        .iter()
        .map(|u| CreateRawTransactionInput { txid: u.txid, vout: u.vout, sequence: None })
        .collect();
    let mut outputs = HashMap::new();
    outputs.insert(consol_addr.to_string(), total - fee);

    let consol_txid = h.create_and_send("alice", &inputs, &outputs);
    h.mine_blocks(1);

    // Spend the consolidated output.
    let utxos3 = h.list_utxos("alice");
    let cu = utxos3.iter().find(|u| u.txid == consol_txid);
    if let Some(cu) = cu {
        let carol_addr = h.new_address("carol");
        let inputs2 = vec![CreateRawTransactionInput {
            txid: cu.txid,
            vout: cu.vout,
            sequence: None,
        }];
        let mut out2 = HashMap::new();
        out2.insert(carol_addr.to_string(), cu.amount - fee);
        h.create_and_send("alice", &inputs2, &out2);
        h.mine_blocks(1);
    }
}

// ─── 7. Script Type Mixing ───────────────────────────────────────────────────

/// Alice receives one P2WPKH UTXO and one P2TR UTXO, then co-spends them.
pub fn scenario_07_script_type_mixing(h: &RegtestHarness) {
    h.ensure_funds("bob", 2.0);

    let wpkh_addr = h.new_address("alice");       // bech32 / P2WPKH
    let tr_addr = h.new_address_tr("alice");      // bech32m / P2TR

    h.send_from("bob", &wpkh_addr, 0.005);
    h.send_from("bob", &tr_addr, 0.005);
    h.mine_blocks(1);

    let utxos = h.list_utxos("alice");

    let wpkh_str = wpkh_addr.to_string();
    let tr_str = tr_addr.to_string();

    let wu = utxos.iter().find(|u| {
        u.address
            .as_ref()
            .and_then(|a| a.clone().require_network(bitcoin::Network::Regtest).ok())
            .map(|a| a.to_string() == wpkh_str)
            .unwrap_or(false)
    });
    let tu = utxos.iter().find(|u| {
        u.address
            .as_ref()
            .and_then(|a| a.clone().require_network(bitcoin::Network::Regtest).ok())
            .map(|a| a.to_string() == tr_str)
            .unwrap_or(false)
    });

    let (wu, tu) = match (wu, tu) {
        (Some(w), Some(t)) => (w, t),
        _ => return,
    };

    let total = wu.amount + tu.amount;
    let dest = h.new_address("bob");
    let fee = sats(20_000); // slightly higher fee for mixed-script tx

    let inputs = vec![
        CreateRawTransactionInput { txid: wu.txid, vout: wu.vout, sequence: None },
        CreateRawTransactionInput { txid: tu.txid, vout: tu.vout, sequence: None },
    ];
    let mut outputs = HashMap::new();
    outputs.insert(dest.to_string(), total - fee);

    h.create_and_send("alice", &inputs, &outputs);
    h.mine_blocks(1);
}

// ─── 8. Cluster Merge ────────────────────────────────────────────────────────

/// Bob-cluster UTXO and carol-cluster UTXO are merged into one tx by alice.
pub fn scenario_08_cluster_merge(h: &RegtestHarness) {
    h.ensure_funds("bob", 2.0);
    h.ensure_funds("carol", 2.0);

    let a_addr = h.new_address("alice");
    let b_addr = h.new_address("alice");

    let txid_a = h.send_from("bob", &a_addr, 0.004);
    let txid_b = h.send_from("carol", &b_addr, 0.004);
    h.mine_blocks(1);

    let utxos = h.list_utxos("alice");
    let ua = utxos.iter().find(|u| u.txid == txid_a);
    let ub = utxos.iter().find(|u| u.txid == txid_b);

    let (ua, ub) = match (ua, ub) {
        (Some(a), Some(b)) => (a, b),
        _ => return,
    };

    let total = ua.amount + ub.amount;
    let dest = h.new_address("bob");
    let fee = sats(20_000);

    let inputs = vec![
        CreateRawTransactionInput { txid: ua.txid, vout: ua.vout, sequence: None },
        CreateRawTransactionInput { txid: ub.txid, vout: ub.vout, sequence: None },
    ];
    let mut outputs = HashMap::new();
    outputs.insert(dest.to_string(), total - fee);

    h.create_and_send("alice", &inputs, &outputs);
    h.mine_blocks(1);
}

// ─── 9. UTXO Age Spread ──────────────────────────────────────────────────────

/// Alice receives an "old" UTXO (20 blocks ago) and a "new" UTXO (just now).
pub fn scenario_09_utxo_age_spread(h: &RegtestHarness) {
    h.ensure_funds("miner", 1.0);

    let old_addr = h.new_address("alice");
    h.send_from("miner", &old_addr, 0.01);
    h.mine_blocks(20);

    let new_addr = h.new_address("alice");
    h.send_from("miner", &new_addr, 0.01);
    h.mine_blocks(1);
}

// ─── 10. Exchange Origin — Batch Withdrawal ──────────────────────────────────

/// Exchange sends to 8 recipients in a single sendmany tx.
pub fn scenario_10_exchange_origin(h: &RegtestHarness) {
    h.ensure_funds("exchange", 5.0);

    let wallets = ["alice", "bob", "carol", "alice", "bob", "carol", "alice", "bob"];
    let mut batch: HashMap<String, f64> = HashMap::new();

    for (i, wallet) in wallets.iter().enumerate() {
        let addr = h.new_address(wallet);
        // Amounts: 0.01, 0.02, 0.03, ... 0.08 BTC (round exchange-like payouts)
        let amount = (i + 1) as f64 * 0.01;
        batch.insert(addr.to_string(), amount);
    }

    h.send_many("exchange", &batch);
    h.mine_blocks(1);
}

// ─── 11. Tainted UTXOs / Dirty Money ─────────────────────────────────────────

/// Alice receives a tainted UTXO (from "risky") and a clean UTXO (from bob),
/// then merges them.  Returns the tainted txid so callers can configure
/// `known_risky_txids` in the scan config.
pub fn scenario_11_tainted_utxos(h: &RegtestHarness) -> bitcoin::Txid {
    h.ensure_funds("risky", 2.0);
    h.ensure_funds("bob", 1.0);

    let ta = h.new_address("alice");
    let ca = h.new_address("alice");

    let taint_txid = h.send_from("risky", &ta, 0.01);
    let clean_txid = h.send_from("bob", &ca, 0.01);
    h.mine_blocks(1);

    let utxos = h.list_utxos("alice");
    let tu = utxos.iter().find(|u| u.txid == taint_txid);
    let cu = utxos.iter().find(|u| u.txid == clean_txid);

    let (tu, cu) = match (tu, cu) {
        (Some(t), Some(c)) => (t, c),
        _ => return taint_txid,
    };

    let total = tu.amount + cu.amount;
    let dest = h.new_address("carol");
    let fee = sats(20_000);

    let inputs = vec![
        CreateRawTransactionInput { txid: tu.txid, vout: tu.vout, sequence: None },
        CreateRawTransactionInput { txid: cu.txid, vout: cu.vout, sequence: None },
    ];
    let mut outputs = HashMap::new();
    outputs.insert(dest.to_string(), total - fee);

    h.create_and_send("alice", &inputs, &outputs);
    h.mine_blocks(1);

    taint_txid
}

// ─── 12. Behavioral Fingerprinting ───────────────────────────────────────────

/// Alice sends 5 round amounts to carol (distinguishable behavioral pattern).
pub fn scenario_12_behavioral_fingerprint(h: &RegtestHarness) {
    h.ensure_funds("alice", 3.0);

    for i in 1..=5u64 {
        let dest = h.new_address("carol");
        // Round amounts: 0.01, 0.02, 0.03, 0.04, 0.05
        h.send_from("alice", &dest, 0.01 * i as f64);
    }
    h.mine_blocks(1);
}

// ─── Setup helper ────────────────────────────────────────────────────────────

/// Create all the wallets used across all scenarios.
pub fn setup_wallets(h: &RegtestHarness) {
    for name in &["alice", "bob", "carol", "exchange", "risky"] {
        h.create_wallet(name);
    }
}
