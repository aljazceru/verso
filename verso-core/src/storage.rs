use std::path::{Path, PathBuf};

use bdk_sqlite::Store;
use bdk_wallet::{CreateParams, KeychainKind, LoadParams, PersistedWallet};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::Network;

use crate::error::VersoError;

/// Open or create a persisted BDK wallet backed by SQLite.
///
/// If the database file already exists, attempts to load the existing wallet.
/// If the file does not exist (or the DB is empty), creates a fresh wallet.
///
/// Returns both the [`PersistedWallet`] and the [`Store`] so the caller can
/// call `wallet.persist_async(&mut store)` later to flush synced state to disk.
pub async fn open_wallet(
    external_desc: &str,
    internal_desc: &str,
    network: Network,
    db_path: &Path,
) -> Result<(PersistedWallet<Store>, Store), VersoError> {
    let path_str = db_path
        .to_str()
        .ok_or_else(|| VersoError::Storage("db_path is not valid UTF-8".into()))?;

    let mut store = Store::new(path_str)
        .await
        .map_err(|e| VersoError::Storage(e.to_string()))?;

    store
        .migrate()
        .await
        .map_err(|e| VersoError::Storage(e.to_string()))?;

    // First, try to load an existing wallet.
    // Clone to satisfy 'static bound required by IntoWalletDescriptor.
    let ext_owned = external_desc.to_owned();
    let int_owned = internal_desc.to_owned();
    let load_result = LoadParams::new()
        .descriptor(KeychainKind::External, Some(ext_owned.clone()))
        .descriptor(KeychainKind::Internal, Some(int_owned.clone()))
        .check_network(network)
        .load_wallet_async(&mut store)
        .await
        .map_err(|e| VersoError::Storage(e.to_string()))?;

    if let Some(wallet) = load_result {
        return Ok((wallet, store));
    }

    // No existing wallet — create a new one.
    let wallet = CreateParams::new(ext_owned, int_owned)
        .network(network)
        .create_wallet_async(&mut store)
        .await
        .map_err(|e| VersoError::Storage(e.to_string()))?;
    Ok((wallet, store))
}

/// Compute a deterministic DB path from both descriptors and network.
///
/// Uses the full descriptor set to avoid collisions between distinct wallet
/// configurations that share long common prefixes.
pub fn resolve_db_path(
    data_dir: &Path,
    external_desc: &str,
    internal_desc: &str,
    network: Network,
) -> PathBuf {
    let input = format!("{}:{}:{}", external_desc, internal_desc, network);
    let hash = sha256::Hash::hash(input.as_bytes());
    let hex = hash.to_string();
    let stem = &hex[..16];
    data_dir.join(format!("verso_{}.db", stem))
}
