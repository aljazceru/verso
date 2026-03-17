//! RegtestHarness — spins up an embedded bitcoind in regtest mode for
//! integration tests.  Each test gets its own harness instance with a fresh
//! chain state.

use std::collections::HashMap;
use std::path::PathBuf;

use bitcoin::{Address, Amount, Network, Txid};
use bitcoincore_rpc::json::{AddressType, CreateRawTransactionInput};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoind::{BitcoinD, Conf};

use verso_core::config::{BackendConfig, BitcoindAuth, ScanConfig};
use verso_core::report::Report;

// ─── Harness ─────────────────────────────────────────────────────────────────

pub struct RegtestHarness {
    /// The embedded bitcoind process (kept alive for the lifetime of the
    /// harness; dropped — and therefore killed — when the harness is dropped).
    pub bitcoind: BitcoinD,
    /// Default RPC client connected to the node (no wallet context).
    pub client: Client,
    /// Cookie file path, shared across per-wallet clients.
    cookie: PathBuf,
}

impl RegtestHarness {
    /// Launch bitcoind in regtest mode and mine 110 blocks so that coinbase
    /// outputs are spendable.
    pub fn new() -> Self {
        let mut conf = Conf::default();
        // Enable descriptor wallets (Bitcoin Core >= 22).
        conf.args = vec![
            "-regtest",
            "-fallbackfee=0.0001",
            "-deprecatedrpc=create_bdb",
            "-txindex=1",
        ];

        let bitcoind = BitcoinD::with_conf(bitcoind::exe_path().unwrap(), &conf).unwrap();

        let cookie = bitcoind.params.cookie_file.clone();

        let client = Client::new(&bitcoind.rpc_url(), Auth::CookieFile(cookie.clone())).unwrap();

        let harness = RegtestHarness {
            bitcoind,
            client,
            cookie,
        };

        // Create the default "miner" wallet that will fund everything.
        harness.create_wallet("miner");
        harness.mine_blocks_to_wallet(110, "miner");

        harness
    }

    // ─── Wallet management ───────────────────────────────────────────────────

    /// Create a new named descriptor wallet on the node.
    pub fn create_wallet(&self, name: &str) {
        // createwallet <name> [disable_private_keys=false] [blank=false]
        //              [passphrase=""] [avoid_reuse=false] [descriptors=true]
        self.client
            .call::<serde_json::Value>(
                "createwallet",
                &[
                    serde_json::json!(name),
                    serde_json::json!(false), // disable_private_keys
                    serde_json::json!(false), // blank
                    serde_json::json!(""),    // passphrase
                    serde_json::json!(false), // avoid_reuse
                    serde_json::json!(true),  // descriptors
                ],
            )
            .unwrap();
    }

    /// Return an RPC client scoped to a specific wallet.
    pub fn wallet_client(&self, wallet_name: &str) -> Client {
        Client::new(
            &self.bitcoind.rpc_url_with_wallet(wallet_name),
            Auth::CookieFile(self.cookie.clone()),
        )
        .unwrap()
    }

    // ─── Block mining ────────────────────────────────────────────────────────

    /// Mine `count` blocks, crediting the coinbase to a fresh address in
    /// `wallet_name`.
    pub fn mine_blocks_to_wallet(&self, count: u64, wallet_name: &str) {
        let wc = self.wallet_client(wallet_name);
        let addr = wc
            .get_new_address(None, Some(AddressType::Bech32))
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap();
        wc.generate_to_address(count, &addr).unwrap();
    }

    /// Mine `count` blocks (coinbase goes to miner wallet).
    pub fn mine_blocks(&self, count: u64) {
        self.mine_blocks_to_wallet(count, "miner");
    }

    // ─── Address helpers ─────────────────────────────────────────────────────

    /// Get a fresh bech32 (P2WPKH) address from `wallet_name`.
    pub fn new_address(&self, wallet_name: &str) -> Address {
        self.wallet_client(wallet_name)
            .get_new_address(None, Some(AddressType::Bech32))
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap()
    }

    /// Get a fresh bech32m (P2TR) address from `wallet_name`.
    pub fn new_address_tr(&self, wallet_name: &str) -> Address {
        self.wallet_client(wallet_name)
            .get_new_address(None, Some(AddressType::Bech32m))
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap()
    }

    // ─── Fund helpers ────────────────────────────────────────────────────────

    /// Ensure `wallet_name` has at least `min_btc` spendable (confirmed).
    /// Tops up from the miner wallet if needed.
    pub fn ensure_funds(&self, wallet_name: &str, min_btc: f64) {
        let wc = self.wallet_client(wallet_name);
        let info = wc.call::<serde_json::Value>("getbalances", &[]).unwrap();
        let bal = info["mine"]["trusted"].as_f64().unwrap_or(0.0);
        if bal < min_btc {
            let addr = self.new_address(wallet_name);
            self.send_from("miner", &addr, min_btc + 0.5);
            self.mine_blocks(1);
        }
    }

    // ─── Send helpers ────────────────────────────────────────────────────────

    /// Send `amount_btc` from `from_wallet` to `to_addr`.
    pub fn send_from(&self, from_wallet: &str, to_addr: &Address, amount_btc: f64) -> Txid {
        self.wallet_client(from_wallet)
            .send_to_address(
                to_addr,
                Amount::from_btc(amount_btc).unwrap(),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap()
    }

    /// sendmany from `from_wallet`: map of address → amount_btc.
    pub fn send_many(&self, from_wallet: &str, outputs: &HashMap<String, f64>) -> Txid {
        // Build a JSON object {addr: amount, …}
        let amounts: serde_json::Value = outputs
            .iter()
            .map(|(addr, btc)| (addr.clone(), serde_json::json!(btc)))
            .collect::<serde_json::Map<_, _>>()
            .into();
        self.wallet_client(from_wallet)
            .call::<String>("sendmany", &[serde_json::json!(""), amounts])
            .unwrap()
            .parse()
            .unwrap()
    }

    /// List confirmed UTXOs in `wallet_name` (minconf = 1).
    pub fn list_utxos(
        &self,
        wallet_name: &str,
    ) -> Vec<bitcoincore_rpc::json::ListUnspentResultEntry> {
        self.wallet_client(wallet_name)
            .list_unspent(Some(1), None, None, None, None)
            .unwrap()
    }

    /// Build, sign, and broadcast a raw transaction spending `inputs` from
    /// `signing_wallet`, sending to `outputs` (addr → Amount).
    pub fn create_and_send(
        &self,
        signing_wallet: &str,
        inputs: &[CreateRawTransactionInput],
        outputs: &HashMap<String, Amount>,
    ) -> Txid {
        let wc = self.wallet_client(signing_wallet);
        let raw_hex = wc
            .create_raw_transaction_hex(inputs, outputs, None, None)
            .unwrap();
        let signed = wc
            .sign_raw_transaction_with_wallet(raw_hex, None, None)
            .unwrap();
        wc.send_raw_transaction(signed.hex.as_slice()).unwrap()
    }

    // ─── Descriptor extraction ───────────────────────────────────────────────

    /// Return the external and internal descriptor strings for `wallet_name`,
    /// including private keys (for use in ScanConfig).
    pub fn get_descriptors(&self, wallet_name: &str) -> Vec<String> {
        // Pass `false` to get xpub descriptors (no private keys).
        // BDK's scanner only needs public keys to derive addresses and track txs.
        let result = self
            .wallet_client(wallet_name)
            .call::<serde_json::Value>("listdescriptors", &[serde_json::json!(false)])
            .unwrap();

        let descs = result["descriptors"].as_array().unwrap();

        // We want the external (non-internal) and internal descriptor.
        // Each entry has "desc" and "internal" fields.
        let mut external: Option<String> = None;
        let mut internal: Option<String> = None;

        // First pass: prefer wpkh() descriptors (P2WPKH, matches Bech32 addresses).
        for entry in descs {
            let desc_str = entry["desc"].as_str().unwrap_or("").to_string();
            let is_internal = entry["internal"].as_bool().unwrap_or(false);
            if desc_str.starts_with("wpkh(") {
                if is_internal && internal.is_none() {
                    internal = Some(desc_str);
                } else if !is_internal && external.is_none() {
                    external = Some(desc_str);
                }
            }
        }

        // Second pass: fall back to tr() descriptors if no wpkh() found.
        if external.is_none() || internal.is_none() {
            for entry in descs {
                let desc_str = entry["desc"].as_str().unwrap_or("").to_string();
                let is_internal = entry["internal"].as_bool().unwrap_or(false);
                if desc_str.starts_with("tr(") {
                    if is_internal && internal.is_none() {
                        internal = Some(desc_str);
                    } else if !is_internal && external.is_none() {
                        external = Some(desc_str);
                    }
                }
            }
        }

        // Fall back to first two descriptors if specific ones not found.
        if external.is_none() || internal.is_none() {
            let mut result_vec = Vec::new();
            for entry in descs.iter().take(2) {
                if let Some(s) = entry["desc"].as_str() {
                    result_vec.push(s.to_string());
                }
            }
            return result_vec;
        }

        vec![external.unwrap(), internal.unwrap()]
    }

    // ─── Scan ────────────────────────────────────────────────────────────────

    /// Scan `wallet_name` using verso_core and return the Report.
    pub async fn scan_wallet(&self, wallet_name: &str) -> Report {
        let descriptors = self.get_descriptors(wallet_name);
        let config = self.default_scan_config(descriptors);
        verso_core::scan(config).await.unwrap()
    }

    /// Build a ScanConfig pointing at this regtest node.
    pub fn default_scan_config(&self, descriptors: Vec<String>) -> ScanConfig {
        ScanConfig {
            descriptors,
            network: Network::Regtest,
            backend: BackendConfig::Bitcoind {
                url: self.bitcoind.rpc_url(),
                auth: BitcoindAuth::Cookie(self.cookie.clone()),
            },
            known_risky_txids: None,
            known_exchange_txids: None,
            derivation_limit: 1000,
            data_dir: None,
            ephemeral: true,
            progress_tx: None,
        }
    }
}

impl Default for RegtestHarness {
    fn default() -> Self {
        Self::new()
    }
}
