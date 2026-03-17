use std::collections::HashSet;
use std::path::PathBuf;

use bitcoin::{Network, Txid};

#[derive(Debug, Clone)]
pub enum BackendConfig {
    Bitcoind { url: String, auth: BitcoindAuth },
    Esplora { url: String },
}

#[derive(Debug, Clone)]
pub enum BitcoindAuth {
    Cookie(PathBuf),
    UserPass { user: String, pass: String },
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub descriptors: Vec<String>,
    pub network: Network,
    pub backend: BackendConfig,
    pub known_risky_txids: Option<HashSet<Txid>>,
    pub known_exchange_txids: Option<HashSet<Txid>>,
    pub derivation_limit: u32,
    pub data_dir: Option<PathBuf>,
    pub ephemeral: bool,
    pub progress_tx: Option<tokio::sync::mpsc::UnboundedSender<ScanProgress>>,
}

#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub phase: String,
    pub message: String,
    pub percent: Option<f32>,
}
