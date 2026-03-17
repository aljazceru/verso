use std::collections::{HashMap, HashSet, VecDeque};

use bitcoin::{Address, AddressType, Amount, FeeRate, Network, Script, ScriptBuf, Transaction, Txid};
use bdk_chain::ChainPosition;
use bdk_wallet::{KeychainKind, Wallet};

use crate::backend::ChainBackend;
use crate::error::VersoError;

// ─── ScriptType ──────────────────────────────────────────────────────────────

/// Identifies the script type of an address/output.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScriptType {
    P2pkh,
    P2sh,
    P2shP2wpkh,
    P2wpkh,
    P2tr,
    Unknown,
}

// ─── InputInfo / OutputInfo ───────────────────────────────────────────────────

/// Info about one input in a transaction.
#[derive(Debug, Clone)]
pub struct InputInfo {
    pub address: Option<Address>,
    pub script: ScriptBuf,
    pub value_sats: u64,
    pub is_ours: bool,
}

/// Info about one output in a transaction.
#[derive(Debug, Clone)]
pub struct OutputInfo {
    pub address: Option<Address>,
    pub script: ScriptBuf,
    pub value_sats: u64,
    pub is_ours: bool,
    pub is_change: bool,
}

// ─── UtxoInfo ─────────────────────────────────────────────────────────────────

/// A portable UTXO descriptor returned by [`GraphView::utxos`].
///
/// Unlike `bdk_wallet::LocalOutput`, this type has a public constructor and
/// carries pre-computed convenience fields so callers don't need a `Wallet`
/// reference to interpret the data.
#[derive(Debug, Clone)]
pub struct UtxoInfo {
    pub txid: Txid,
    pub vout: u32,
    pub address: Option<Address>,
    pub script: ScriptBuf,
    pub value_sats: u64,
    pub confirmations: u32,
    pub is_change: bool,
}

// ─── free helper ─────────────────────────────────────────────────────────────

/// Map an [`Address`] to its [`ScriptType`].
///
/// This is a free function so both [`WalletGraph`] and [`MockWalletGraph`]
/// can share the same implementation without duplication.
fn script_type_from_address(addr: &Address) -> ScriptType {
    match addr.address_type() {
        Some(AddressType::P2pkh) => ScriptType::P2pkh,
        Some(AddressType::P2sh) => {
            // P2SH wrapping P2WPKH is a common pattern; we can't distinguish
            // purely from the address type alone, so map all P2SH to P2sh.
            ScriptType::P2sh
        }
        Some(AddressType::P2wpkh) => ScriptType::P2wpkh,
        Some(AddressType::P2tr) => ScriptType::P2tr,
        _ => ScriptType::Unknown,
    }
}

// ─── GraphView trait ──────────────────────────────────────────────────────────

/// A read-only view over a wallet transaction graph.
///
/// Both `WalletGraph` and `MockWalletGraph` implement this trait so detectors
/// can be tested with mock data without hitting a real chain backend.
pub trait GraphView: Send + Sync {
    /// All wallet addresses, sorted by derivation index (external first, then internal).
    fn our_addresses(&self) -> Vec<Address>;

    /// All wallet txids in canonical order (confirmed first, then unconfirmed).
    fn our_txids(&self) -> Vec<Txid>;

    /// Is this script owned by our wallet?
    fn is_ours(&self, script: &Script) -> bool;

    /// Is this script a change output (internal keychain)?
    fn is_change(&self, script: &Script) -> bool;

    /// Detect script type from an address.
    fn script_type(&self, address: &Address) -> ScriptType;

    /// Get a cached transaction by txid.
    fn fetch_tx(&self, txid: Txid) -> Option<&Transaction>;

    /// Get input infos for a transaction.
    fn input_addresses(&self, txid: Txid) -> &[InputInfo];

    /// Get output infos for a transaction.
    fn output_addresses(&self, txid: Txid) -> &[OutputInfo];

    /// All current UTXOs as portable [`UtxoInfo`] values.
    fn utxos(&self) -> Vec<UtxoInfo>;

    /// Number of confirmations for a transaction.
    fn confirmations(&self, txid: Txid) -> Option<u32>;

    /// Fee rate of a transaction (None if parent txs are missing).
    fn fee_rate(&self, tx: &Transaction) -> Option<FeeRate>;

    /// Iterate over all ancestor transactions (BFS) of the given txid.
    ///
    /// Only transactions present in the graph's local cache will be returned.
    fn ancestors<'a>(&'a self, txid: Txid) -> Box<dyn Iterator<Item = &'a Transaction> + 'a>;
}

// ─── WalletGraph ─────────────────────────────────────────────────────────────

/// Pre-fetched wallet transaction graph backed by a real BDK `Wallet`.
pub struct WalletGraph {
    wallet: Wallet,
    network: Network,
    tx_cache: HashMap<Txid, Transaction>,
    input_cache: HashMap<Txid, Vec<InputInfo>>,
    output_cache: HashMap<Txid, Vec<OutputInfo>>,
    /// Scripts belonging to the internal (change) keychain.
    internal_scripts: HashSet<ScriptBuf>,
}

impl WalletGraph {
    /// Build a `WalletGraph` by fetching all transactions through the given backend.
    pub async fn build(
        wallet: Wallet,
        backend: &dyn ChainBackend,
        network: Network,
    ) -> Result<Self, VersoError> {
        // Pre-build a set of internal-keychain scripts for fast is_change() look-ups.
        // Use all *revealed* addresses (not just unused ones) so active wallets
        // that have spent from the internal keychain are correctly identified.
        let internal_scripts: HashSet<ScriptBuf> =
            revealed_addresses(&wallet, KeychainKind::Internal, network)
                .map(|addr| addr.script_pubkey())
                .collect();

        // ── 1. Fetch full transactions ────────────────────────────────────────
        let mut tx_cache: HashMap<Txid, Transaction> = HashMap::new();

        for wallet_tx in wallet.transactions() {
            let txid = wallet_tx.tx_node.txid;
            if let Ok(Some(full_tx)) = backend.get_tx(txid).await {
                tx_cache.insert(txid, full_tx);
            }
        }

        // ── 2. Resolve inputs and outputs ────────────────────────────────────
        // We iterate over a collected snapshot so we can borrow tx_cache freely
        // inside the loop.
        let txids: Vec<Txid> = tx_cache.keys().copied().collect();

        let mut input_cache: HashMap<Txid, Vec<InputInfo>> = HashMap::new();
        let mut output_cache: HashMap<Txid, Vec<OutputInfo>> = HashMap::new();

        for txid in &txids {
            let tx = match tx_cache.get(txid) {
                Some(t) => t.clone(), // clone to free the borrow
                None => continue,
            };

            // Outputs
            let outputs: Vec<OutputInfo> = tx
                .output
                .iter()
                .map(|out| {
                    let addr = Address::from_script(&out.script_pubkey, network).ok();
                    let is_ours = wallet.is_mine(out.script_pubkey.clone());
                    let is_change =
                        is_ours && internal_scripts.contains(&out.script_pubkey);
                    OutputInfo {
                        address: addr,
                        script: out.script_pubkey.clone(),
                        value_sats: out.value.to_sat(),
                        is_ours,
                        is_change,
                    }
                })
                .collect();
            output_cache.insert(*txid, outputs);

            // Inputs — look up parent tx to get spending value
            let inputs: Vec<InputInfo> = tx
                .input
                .iter()
                .map(|inp| {
                    let parent_txid = inp.previous_output.txid;
                    let vout = inp.previous_output.vout as usize;
                    if let Some(parent_tx) = tx_cache.get(&parent_txid) {
                        if let Some(parent_out) = parent_tx.output.get(vout) {
                            let addr =
                                Address::from_script(&parent_out.script_pubkey, network).ok();
                            let is_ours = wallet.is_mine(parent_out.script_pubkey.clone());
                            return InputInfo {
                                address: addr,
                                script: parent_out.script_pubkey.clone(),
                                value_sats: parent_out.value.to_sat(),
                                is_ours,
                            };
                        }
                    }
                    // Coinbase or missing parent
                    InputInfo {
                        address: None,
                        script: ScriptBuf::default(),
                        value_sats: 0,
                        is_ours: false,
                    }
                })
                .collect();
            input_cache.insert(*txid, inputs);
        }

        Ok(WalletGraph {
            wallet,
            network,
            tx_cache,
            input_cache,
            output_cache,
            internal_scripts,
        })
    }

    /// Walk ancestors of a transaction using BFS through `tx_cache`.
    pub fn ancestors_owned(&self, txid: Txid) -> impl Iterator<Item = &Transaction> {
        let mut visited: HashSet<Txid> = HashSet::new();
        let mut queue: VecDeque<Txid> = VecDeque::new();
        let mut result: Vec<&Transaction> = Vec::new();

        if let Some(tx) = self.tx_cache.get(&txid) {
            for inp in &tx.input {
                let parent = inp.previous_output.txid;
                if visited.insert(parent) {
                    queue.push_back(parent);
                }
            }
        }

        while let Some(next_txid) = queue.pop_front() {
            if let Some(ancestor_tx) = self.tx_cache.get(&next_txid) {
                result.push(ancestor_tx);
                for inp in &ancestor_tx.input {
                    let parent = inp.previous_output.txid;
                    if visited.insert(parent) {
                        queue.push_back(parent);
                    }
                }
            }
        }

        result.into_iter()
    }
}

impl GraphView for WalletGraph {
    fn our_addresses(&self) -> Vec<Address> {
        let mut addrs: Vec<(u32, Address)> = Vec::new();

        for addr in revealed_addresses(&self.wallet, KeychainKind::External, self.network) {
            // We don't have index here directly; use position in the iterator as a
            // proxy. revealed_addresses yields in ascending derivation-index order.
            addrs.push((addrs.len() as u32, addr));
        }
        let ext_len = addrs.len() as u32;

        for addr in revealed_addresses(&self.wallet, KeychainKind::Internal, self.network) {
            addrs.push((ext_len + addrs.len() as u32 - ext_len, addr));
        }

        // Already in order (external first, then internal), no need to re-sort.
        addrs.into_iter().map(|(_, a)| a).collect()
    }

    fn our_txids(&self) -> Vec<Txid> {
        let mut txs: Vec<_> = self.wallet.transactions().collect();

        txs.sort_by(|a, b| {
            let key_a = match &a.chain_position {
                ChainPosition::Confirmed { anchor, .. } => (0u8, anchor.block_id.height, 0u32),
                ChainPosition::Unconfirmed { .. } => (1u8, u32::MAX, 0u32),
            };
            let key_b = match &b.chain_position {
                ChainPosition::Confirmed { anchor, .. } => (0u8, anchor.block_id.height, 0u32),
                ChainPosition::Unconfirmed { .. } => (1u8, u32::MAX, 0u32),
            };
            key_a.cmp(&key_b)
        });

        txs.iter().map(|t| t.tx_node.txid).collect()
    }

    fn is_ours(&self, script: &Script) -> bool {
        self.wallet.is_mine(script.to_owned().into())
    }

    fn is_change(&self, script: &Script) -> bool {
        let sbuf: ScriptBuf = script.to_owned().into();
        self.internal_scripts.contains(&sbuf)
    }

    fn script_type(&self, address: &Address) -> ScriptType {
        script_type_from_address(address)
    }

    fn fetch_tx(&self, txid: Txid) -> Option<&Transaction> {
        self.tx_cache.get(&txid)
    }

    fn input_addresses(&self, txid: Txid) -> &[InputInfo] {
        self.input_cache.get(&txid).map(Vec::as_slice).unwrap_or(&[])
    }

    fn output_addresses(&self, txid: Txid) -> &[OutputInfo] {
        self.output_cache.get(&txid).map(Vec::as_slice).unwrap_or(&[])
    }

    fn utxos(&self) -> Vec<UtxoInfo> {
        let tip = self.wallet.latest_checkpoint().height();
        self.wallet
            .list_unspent()
            .map(|utxo| {
                let addr = Address::from_script(&utxo.txout.script_pubkey, self.network).ok();
                let confs = match utxo.chain_position {
                    ChainPosition::Confirmed { anchor, .. } => {
                        tip.saturating_sub(anchor.block_id.height).saturating_add(1)
                    }
                    ChainPosition::Unconfirmed { .. } => 0,
                };
                UtxoInfo {
                    txid: utxo.outpoint.txid,
                    vout: utxo.outpoint.vout,
                    address: addr,
                    script: utxo.txout.script_pubkey.clone(),
                    value_sats: utxo.txout.value.to_sat(),
                    confirmations: confs,
                    is_change: utxo.keychain == KeychainKind::Internal,
                }
            })
            .collect()
    }

    fn confirmations(&self, txid: Txid) -> Option<u32> {
        let wallet_tx = self.wallet.get_tx(txid)?;
        let tip_height = self.wallet.latest_checkpoint().height();
        match wallet_tx.chain_position {
            ChainPosition::Confirmed { anchor, .. } => {
                let conf_height = anchor.block_id.height;
                Some(tip_height.saturating_sub(conf_height).saturating_add(1))
            }
            ChainPosition::Unconfirmed { .. } => None,
        }
    }

    fn fee_rate(&self, tx: &Transaction) -> Option<FeeRate> {
        // Sum inputs
        let mut in_total: u64 = 0;
        for inp in &tx.input {
            let parent_txid = inp.previous_output.txid;
            let vout = inp.previous_output.vout as usize;
            let parent_tx = self.tx_cache.get(&parent_txid)?;
            let out = parent_tx.output.get(vout)?;
            in_total = in_total.checked_add(out.value.to_sat())?;
        }
        // Sum outputs
        let out_total: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        let fee = in_total.checked_sub(out_total)?;
        let weight = tx.weight();
        // Amount / Weight yields FeeRate (sat/kwu)
        Some(Amount::from_sat(fee) / weight)
    }

    fn ancestors<'a>(&'a self, txid: Txid) -> Box<dyn Iterator<Item = &'a Transaction> + 'a> {
        Box::new(self.ancestors_owned(txid))
    }
}

// ─── Private helper ───────────────────────────────────────────────────────────

/// Iterate over **all revealed** addresses for `keychain` in ascending derivation-index order.
///
/// BDK 2.x exposes `derivation_index(keychain) -> Option<u32>` for the last
/// revealed index and `peek_address(keychain, index)` for non-mutating address
/// derivation.  Together they let us reconstruct the full revealed address set
/// without touching the mutable `next_unused_address` / `reveal_next_address`
/// APIs.
fn revealed_addresses(
    wallet: &Wallet,
    keychain: KeychainKind,
    network: Network,
) -> impl Iterator<Item = Address> + '_ {
    let last = wallet.derivation_index(keychain);
    // If nothing has been revealed yet, last == None → empty range.
    let count = last.map(|l| l + 1).unwrap_or(0);
    (0..count).map(move |idx| {
        wallet.peek_address(keychain, idx).address
    })
}

// ─── MockWalletGraph ─────────────────────────────────────────────────────────

/// A mock UTXO for testing.
#[derive(Debug, Clone)]
pub struct MockUtxo {
    pub txid: Txid,
    pub vout: u32,
    pub address: Address,
    pub value_sats: u64,
    pub confirmations: u32,
    pub is_change: bool,
}

/// A wallet graph backed entirely by in-memory data.  Used in unit tests.
pub struct MockWalletGraph {
    our_addrs: Vec<Address>,
    our_change_addrs: Vec<Address>,
    txids: Vec<Txid>,
    tx_map: HashMap<Txid, Transaction>,
    input_map: HashMap<Txid, Vec<InputInfo>>,
    output_map: HashMap<Txid, Vec<OutputInfo>>,
    utxo_list: Vec<MockUtxo>,
    confirmations_map: HashMap<Txid, u32>,
    network: Network,
}

static EMPTY_INPUTS: &[InputInfo] = &[];
static EMPTY_OUTPUTS: &[OutputInfo] = &[];

impl MockWalletGraph {
    /// Expose mock UTXOs for tests that need raw access.
    pub fn mock_utxos(&self) -> &[MockUtxo] {
        &self.utxo_list
    }
}

impl GraphView for MockWalletGraph {
    fn our_addresses(&self) -> Vec<Address> {
        self.our_addrs
            .iter()
            .chain(self.our_change_addrs.iter())
            .cloned()
            .collect()
    }

    fn our_txids(&self) -> Vec<Txid> {
        self.txids.clone()
    }

    fn is_ours(&self, script: &Script) -> bool {
        self.our_addrs
            .iter()
            .chain(self.our_change_addrs.iter())
            .any(|a| *a.script_pubkey() == *script)
    }

    fn is_change(&self, script: &Script) -> bool {
        self.our_change_addrs
            .iter()
            .any(|a| *a.script_pubkey() == *script)
    }

    fn script_type(&self, address: &Address) -> ScriptType {
        script_type_from_address(address)
    }

    fn fetch_tx(&self, txid: Txid) -> Option<&Transaction> {
        self.tx_map.get(&txid)
    }

    fn input_addresses(&self, txid: Txid) -> &[InputInfo] {
        self.input_map
            .get(&txid)
            .map(Vec::as_slice)
            .unwrap_or(EMPTY_INPUTS)
    }

    fn output_addresses(&self, txid: Txid) -> &[OutputInfo] {
        self.output_map
            .get(&txid)
            .map(Vec::as_slice)
            .unwrap_or(EMPTY_OUTPUTS)
    }

    fn utxos(&self) -> Vec<UtxoInfo> {
        self.utxo_list
            .iter()
            .map(|u| UtxoInfo {
                txid: u.txid,
                vout: u.vout,
                address: Some(u.address.clone()),
                script: u.address.script_pubkey(),
                value_sats: u.value_sats,
                confirmations: u.confirmations,
                is_change: u.is_change,
            })
            .collect()
    }

    fn confirmations(&self, txid: Txid) -> Option<u32> {
        self.confirmations_map.get(&txid).copied()
    }

    fn fee_rate(&self, tx: &Transaction) -> Option<FeeRate> {
        // Sum inputs from output_map of parent txids
        let mut in_total: u64 = 0;
        for inp in &tx.input {
            let parent_txid = inp.previous_output.txid;
            let vout = inp.previous_output.vout as usize;
            if let Some(outputs) = self.output_map.get(&parent_txid) {
                if let Some(out) = outputs.get(vout) {
                    in_total = in_total.checked_add(out.value_sats)?;
                    continue;
                }
            }
            return None;
        }
        let out_total: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        let fee = in_total.checked_sub(out_total)?;
        let weight = tx.weight();
        Some(Amount::from_sat(fee) / weight)
    }

    fn ancestors<'a>(&'a self, txid: Txid) -> Box<dyn Iterator<Item = &'a Transaction> + 'a> {
        // BFS through tx_map
        let mut visited: HashSet<Txid> = HashSet::new();
        let mut queue: VecDeque<Txid> = VecDeque::new();
        let mut result: Vec<&Transaction> = Vec::new();

        if let Some(tx) = self.tx_map.get(&txid) {
            for inp in &tx.input {
                let parent = inp.previous_output.txid;
                if visited.insert(parent) {
                    queue.push_back(parent);
                }
            }
        }

        while let Some(next_txid) = queue.pop_front() {
            if let Some(ancestor_tx) = self.tx_map.get(&next_txid) {
                result.push(ancestor_tx);
                for inp in &ancestor_tx.input {
                    let parent = inp.previous_output.txid;
                    if visited.insert(parent) {
                        queue.push_back(parent);
                    }
                }
            }
        }

        Box::new(result.into_iter())
    }
}

// ─── MockGraphBuilder ─────────────────────────────────────────────────────────

/// Builder for constructing [`MockWalletGraph`] instances in tests.
pub struct MockGraphBuilder {
    graph: MockWalletGraph,
}

impl MockGraphBuilder {
    pub fn new() -> Self {
        MockGraphBuilder {
            graph: MockWalletGraph {
                our_addrs: Vec::new(),
                our_change_addrs: Vec::new(),
                txids: Vec::new(),
                tx_map: HashMap::new(),
                input_map: HashMap::new(),
                output_map: HashMap::new(),
                utxo_list: Vec::new(),
                confirmations_map: HashMap::new(),
                network: Network::Regtest,
            },
        }
    }

    /// Set the network (default: Regtest).
    pub fn with_network(mut self, network: Network) -> Self {
        self.graph.network = network;
        self
    }

    /// Add a wallet receive address.
    pub fn with_address(mut self, addr: Address) -> Self {
        self.graph.our_addrs.push(addr);
        self
    }

    /// Add a wallet change address.
    pub fn with_change_address(mut self, addr: Address) -> Self {
        self.graph.our_change_addrs.push(addr);
        self
    }

    /// Add a simple receive transaction: one output to `to_addr` for `sats`.
    ///
    /// The transaction has no inputs tracked (simulates an external send to us).
    pub fn with_receive_tx(mut self, txid: Txid, to_addr: Address, sats: u64) -> Self {
        use bitcoin::{Amount, TxIn, TxOut};

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: to_addr.script_pubkey(),
            }],
        };

        let is_ours = self
            .graph
            .our_addrs
            .iter()
            .chain(self.graph.our_change_addrs.iter())
            .any(|a| *a == to_addr);
        let is_change = self.graph.our_change_addrs.iter().any(|a| *a == to_addr);

        let out_info = OutputInfo {
            address: Some(to_addr.clone()),
            script: to_addr.script_pubkey(),
            value_sats: sats,
            is_ours,
            is_change,
        };

        self.graph.txids.push(txid);
        self.graph.tx_map.insert(txid, tx);
        self.graph.input_map.insert(txid, Vec::new());
        self.graph.output_map.insert(txid, vec![out_info]);
        self
    }

    /// Add a spend transaction.
    ///
    /// `inputs` is a list of `(parent_txid, vout, value_sats)`.
    /// `outputs` is a list of `(address, value_sats, is_change)`.
    pub fn with_spend_tx(
        mut self,
        txid: Txid,
        inputs: Vec<(Txid, u32, u64)>,
        outputs: Vec<(Address, u64, bool)>,
    ) -> Self {
        use bitcoin::{Amount, OutPoint, TxIn, TxOut};

        let tx_inputs: Vec<TxIn> = inputs
            .iter()
            .map(|(parent_txid, vout, _)| TxIn {
                previous_output: OutPoint {
                    txid: *parent_txid,
                    vout: *vout,
                },
                ..TxIn::default()
            })
            .collect();

        let tx_outputs: Vec<TxOut> = outputs
            .iter()
            .map(|(addr, sats, _)| TxOut {
                value: Amount::from_sat(*sats),
                script_pubkey: addr.script_pubkey(),
            })
            .collect();

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: tx_inputs,
            output: tx_outputs,
        };

        // Build InputInfo entries
        let input_infos: Vec<InputInfo> = inputs
            .iter()
            .map(|(parent_txid, vout, value_sats)| {
                // Try to look up the parent output for address info
                let (addr, script) = self
                    .graph
                    .output_map
                    .get(parent_txid)
                    .and_then(|outs| outs.get(*vout as usize))
                    .map(|out_info| {
                        (out_info.address.clone(), out_info.script.clone())
                    })
                    .unwrap_or((None, ScriptBuf::default()));

                let is_ours = addr.as_ref().map(|a| {
                    self.graph
                        .our_addrs
                        .iter()
                        .chain(self.graph.our_change_addrs.iter())
                        .any(|o| o == a)
                }).unwrap_or(false);

                InputInfo {
                    address: addr,
                    script,
                    value_sats: *value_sats,
                    is_ours,
                }
            })
            .collect();

        // Build OutputInfo entries
        let output_infos: Vec<OutputInfo> = outputs
            .iter()
            .map(|(addr, sats, is_change_flag)| {
                let is_ours = self
                    .graph
                    .our_addrs
                    .iter()
                    .chain(self.graph.our_change_addrs.iter())
                    .any(|a| a == addr);
                OutputInfo {
                    address: Some(addr.clone()),
                    script: addr.script_pubkey(),
                    value_sats: *sats,
                    is_ours,
                    is_change: *is_change_flag,
                }
            })
            .collect();

        self.graph.txids.push(txid);
        self.graph.tx_map.insert(txid, tx);
        self.graph.input_map.insert(txid, input_infos);
        self.graph.output_map.insert(txid, output_infos);
        self
    }

    /// Add a UTXO to the mock graph.
    pub fn with_utxo(
        mut self,
        txid: Txid,
        vout: u32,
        addr: Address,
        sats: u64,
        confs: u32,
    ) -> Self {
        self.graph.utxo_list.push(MockUtxo {
            txid,
            vout,
            address: addr,
            value_sats: sats,
            confirmations: confs,
            is_change: false,
        });
        self
    }

    /// Add a change UTXO to the mock graph.
    pub fn with_change_utxo(
        mut self,
        txid: Txid,
        vout: u32,
        addr: Address,
        sats: u64,
        confs: u32,
    ) -> Self {
        self.graph.utxo_list.push(MockUtxo {
            txid,
            vout,
            address: addr,
            value_sats: sats,
            confirmations: confs,
            is_change: true,
        });
        self
    }

    /// Set the confirmation count for a transaction.
    pub fn with_confirmations(mut self, txid: Txid, confs: u32) -> Self {
        self.graph.confirmations_map.insert(txid, confs);
        self
    }

    /// Finalise and return the `MockWalletGraph`.
    pub fn build(self) -> MockWalletGraph {
        self.graph
    }
}

impl Default for MockGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        hashes::Hash,
        key::{Secp256k1, UntweakedKeypair},
        secp256k1::rand,
        Address, Network, Txid, XOnlyPublicKey,
    };

    fn regtest_p2tr_address() -> Address {
        let secp = Secp256k1::new();
        let keypair = UntweakedKeypair::new(&secp, &mut rand::thread_rng());
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        Address::p2tr(&secp, xonly, None, Network::Regtest)
    }

    fn make_txid(n: u8) -> Txid {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        Txid::from_byte_array(bytes)
    }

    #[test]
    fn test_our_addresses_contains_wallet_address() {
        let addr = regtest_p2tr_address();
        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .build();

        let addresses = graph.our_addresses();
        assert!(addresses.contains(&addr), "our_addresses should contain the wallet address");
    }

    #[test]
    fn test_our_addresses_change_included() {
        let addr = regtest_p2tr_address();
        let change = regtest_p2tr_address();
        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_change_address(change.clone())
            .build();

        let addresses = graph.our_addresses();
        assert!(addresses.contains(&addr));
        assert!(addresses.contains(&change));
        assert_eq!(addresses.len(), 2);
    }

    #[test]
    fn test_is_ours_receive_address() {
        let addr = regtest_p2tr_address();
        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .build();

        assert!(graph.is_ours(&addr.script_pubkey()));
    }

    #[test]
    fn test_is_ours_unknown_address() {
        let addr = regtest_p2tr_address();
        let other = regtest_p2tr_address();
        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .build();

        assert!(!graph.is_ours(&other.script_pubkey()));
    }

    #[test]
    fn test_is_change_internal_address() {
        let addr = regtest_p2tr_address();
        let change = regtest_p2tr_address();
        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_change_address(change.clone())
            .build();

        assert!(!graph.is_change(&addr.script_pubkey()), "receive addr should not be change");
        assert!(graph.is_change(&change.script_pubkey()), "change addr should be change");
    }

    #[test]
    fn test_script_type_p2tr() {
        let addr = regtest_p2tr_address();
        let graph = MockGraphBuilder::new().build();
        assert_eq!(graph.script_type(&addr), ScriptType::P2tr);
    }

    #[test]
    fn test_receive_tx_stored() {
        let addr = regtest_p2tr_address();
        let txid = make_txid(1);
        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_receive_tx(txid, addr.clone(), 100_000)
            .build();

        assert!(graph.fetch_tx(txid).is_some(), "receive tx should be in tx_map");
        let outs = graph.output_addresses(txid);
        assert_eq!(outs.len(), 1);
        assert_eq!(outs[0].value_sats, 100_000);
        assert!(outs[0].is_ours);
    }

    #[test]
    fn test_our_txids() {
        let addr = regtest_p2tr_address();
        let txid1 = make_txid(1);
        let txid2 = make_txid(2);
        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_receive_tx(txid1, addr.clone(), 50_000)
            .with_receive_tx(txid2, addr.clone(), 75_000)
            .build();

        let txids = graph.our_txids();
        assert_eq!(txids.len(), 2);
        assert!(txids.contains(&txid1));
        assert!(txids.contains(&txid2));
    }

    #[test]
    fn test_confirmations() {
        let addr = regtest_p2tr_address();
        let txid = make_txid(1);
        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_receive_tx(txid, addr.clone(), 10_000)
            .with_confirmations(txid, 6)
            .build();

        assert_eq!(graph.confirmations(txid), Some(6));
        assert_eq!(graph.confirmations(make_txid(99)), None);
    }

    #[test]
    fn test_spend_tx_input_output_info() {
        let addr = regtest_p2tr_address();
        let change = regtest_p2tr_address();
        let external = regtest_p2tr_address();
        let recv_txid = make_txid(1);
        let spend_txid = make_txid(2);

        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_change_address(change.clone())
            .with_receive_tx(recv_txid, addr.clone(), 200_000)
            .with_spend_tx(
                spend_txid,
                vec![(recv_txid, 0, 200_000)],
                vec![
                    (external.clone(), 150_000, false),
                    (change.clone(), 49_000, true),
                ],
            )
            .build();

        let inputs = graph.input_addresses(spend_txid);
        assert_eq!(inputs.len(), 1);
        assert!(inputs[0].is_ours, "input should be ours");

        let outputs = graph.output_addresses(spend_txid);
        assert_eq!(outputs.len(), 2);

        let change_out = outputs.iter().find(|o| o.is_change).expect("change output");
        assert_eq!(change_out.value_sats, 49_000);

        let ext_out = outputs.iter().find(|o| !o.is_change).expect("external output");
        assert_eq!(ext_out.value_sats, 150_000);
        assert!(!ext_out.is_ours);
    }

    #[test]
    fn test_utxo_builder() {
        let addr = regtest_p2tr_address();
        let txid = make_txid(1);
        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_utxo(txid, 0, addr.clone(), 500_000, 10)
            .build();

        assert_eq!(graph.mock_utxos().len(), 1);
        assert_eq!(graph.mock_utxos()[0].value_sats, 500_000);
        assert_eq!(graph.mock_utxos()[0].confirmations, 10);
    }

    #[test]
    fn test_utxos_via_trait() {
        let addr = regtest_p2tr_address();
        let change_addr = regtest_p2tr_address();
        let txid = make_txid(1);
        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_change_address(change_addr.clone())
            .with_utxo(txid, 0, addr.clone(), 500_000, 10)
            .with_change_utxo(txid, 1, change_addr.clone(), 50_000, 10)
            .build();

        let utxos = graph.utxos();
        assert_eq!(utxos.len(), 2);

        let receive = utxos.iter().find(|u| u.vout == 0).unwrap();
        assert_eq!(receive.value_sats, 500_000);
        assert!(!receive.is_change);

        let change = utxos.iter().find(|u| u.vout == 1).unwrap();
        assert_eq!(change.value_sats, 50_000);
        assert!(change.is_change);
    }

    #[test]
    fn test_ancestors_empty_for_unknown_txid() {
        let graph = MockGraphBuilder::new().build();
        let ancestors: Vec<_> = graph.ancestors(make_txid(99)).collect();
        assert!(ancestors.is_empty());
    }

    #[test]
    fn test_ancestors_finds_parent() {
        let addr = regtest_p2tr_address();
        let recv_txid = make_txid(1);
        let spend_txid = make_txid(2);

        let graph = MockGraphBuilder::new()
            .with_address(addr.clone())
            .with_receive_tx(recv_txid, addr.clone(), 100_000)
            .with_spend_tx(
                spend_txid,
                vec![(recv_txid, 0, 100_000)],
                vec![(addr.clone(), 99_000, false)],
            )
            .build();

        let ancestors: Vec<_> = graph.ancestors(spend_txid).collect();
        // The receive tx is the parent of the spend tx.
        // In MockWalletGraph the tx is stored under the synthetic recv_txid key;
        // compute_txid() returns the real Bitcoin txid which will differ, so we
        // just verify that exactly one ancestor is returned.
        assert_eq!(ancestors.len(), 1);
    }
}
