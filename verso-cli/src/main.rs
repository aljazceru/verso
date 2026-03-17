use clap::Parser;
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "verso", about = "Bitcoin wallet privacy analyzer")]
struct Cli {
    /// Bitcoin wallet descriptors (1 or 2)
    #[arg(required = true, num_args = 1..=2)]
    descriptors: Vec<String>,

    /// Bitcoin network
    #[arg(long, default_value = "mainnet")]
    network: String, // "mainnet", "testnet4", "regtest"

    /// Backend type: "bitcoind" or "esplora"
    #[arg(long, default_value = "esplora")]
    backend: String,

    /// Bitcoind RPC URL (for bitcoind backend)
    #[arg(long)]
    bitcoind_url: Option<String>,

    /// Bitcoind cookie file path (for auth)
    #[arg(long)]
    bitcoind_cookie: Option<PathBuf>,

    /// Bitcoind RPC username
    #[arg(long)]
    bitcoind_user: Option<String>,

    /// Bitcoind RPC password
    #[arg(long)]
    bitcoind_pass: Option<String>,

    /// Esplora API URL (for esplora backend)
    #[arg(long, default_value = "https://blockstream.info/api")]
    esplora_url: String,

    /// Known risky txids (CSV of txids)
    #[arg(long)]
    known_risky_txids: Option<String>,

    /// Known exchange txids (CSV of txids)
    #[arg(long)]
    known_exchange_txids: Option<String>,

    /// Max addresses to scan per keychain
    #[arg(long, default_value = "1000")]
    derivation_limit: u32,

    /// Data directory for wallet persistence
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Don't persist wallet state (ephemeral scan)
    #[arg(long)]
    no_persist: bool,

    /// Pretty-print JSON output
    #[arg(long, short = 'p')]
    pretty: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Parse network
    let network = match cli.network.as_str() {
        "mainnet" | "bitcoin" => bitcoin::Network::Bitcoin,
        "testnet" | "testnet4" => bitcoin::Network::Testnet,
        "regtest" => bitcoin::Network::Regtest,
        other => {
            eprintln!("Unknown network: {}", other);
            std::process::exit(1);
        }
    };

    // Parse backend config
    let backend = match cli.backend.as_str() {
        "bitcoind" => {
            let url = cli
                .bitcoind_url
                .unwrap_or_else(|| "http://127.0.0.1:8332".to_string());
            let auth = if let Some(cookie) = cli.bitcoind_cookie {
                verso_core::config::BitcoindAuth::Cookie(cookie)
            } else if let (Some(user), Some(pass)) = (cli.bitcoind_user, cli.bitcoind_pass) {
                verso_core::config::BitcoindAuth::UserPass { user, pass }
            } else {
                eprintln!(
                    "Error: bitcoind backend requires --bitcoind-cookie or --bitcoind-user/pass"
                );
                std::process::exit(1);
            };
            verso_core::config::BackendConfig::Bitcoind { url, auth }
        }
        "esplora" => verso_core::config::BackendConfig::Esplora {
            url: cli.esplora_url,
        },
        other => {
            eprintln!("Unknown backend: {}. Use 'bitcoind' or 'esplora'", other);
            std::process::exit(1);
        }
    };

    // Parse known risky/exchange txids from CSV string.
    let known_risky_txids = match cli.known_risky_txids {
        Some(s) => match parse_txids(&s) {
            Ok(set) => Some(set),
            Err(err) => {
                eprintln!("Invalid --known-risky-txids value: {}", err);
                std::process::exit(1);
            }
        },
        None => None,
    };

    let known_exchange_txids = match cli.known_exchange_txids {
        Some(s) => match parse_txids(&s) {
            Ok(set) => Some(set),
            Err(err) => {
                eprintln!("Invalid --known-exchange-txids value: {}", err);
                std::process::exit(1);
            }
        },
        None => None,
    };

    // Set up progress reporting to stderr
    let (progress_tx, mut progress_rx) =
        tokio::sync::mpsc::unbounded_channel::<verso_core::config::ScanProgress>();
    tokio::spawn(async move {
        while let Some(p) = progress_rx.recv().await {
            eprintln!("[{}] {}", p.phase, p.message);
        }
    });

    // Ephemeral if --no-persist is set OR if no --data-dir is provided.
    let ephemeral = cli.no_persist || cli.data_dir.is_none();

    // Build ScanConfig
    let config = verso_core::config::ScanConfig {
        descriptors: cli.descriptors,
        network,
        backend,
        known_risky_txids,
        known_exchange_txids,
        derivation_limit: cli.derivation_limit,
        data_dir: cli.data_dir,
        ephemeral,
        progress_tx: Some(progress_tx),
    };

    // Run scan
    match verso_core::scan(config).await {
        Ok(report) => {
            let json = if cli.pretty {
                serde_json::to_string_pretty(&report).unwrap()
            } else {
                serde_json::to_string(&report).unwrap()
            };
            println!("{}", json);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn parse_txids(s: &str) -> Result<HashSet<bitcoin::Txid>, String> {
    let mut txids = HashSet::new();
    for raw in s.split(',') {
        let txid_str = raw.trim();
        if txid_str.is_empty() {
            continue;
        }
        let parsed: bitcoin::Txid = txid_str
            .parse()
            .map_err(|_| format!("invalid txid '{}'", txid_str))?;
        txids.insert(parsed);
    }
    Ok(txids)
}
