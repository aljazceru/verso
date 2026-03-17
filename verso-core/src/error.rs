use thiserror::Error;

#[derive(Debug, Error)]
pub enum VersoError {
    #[error("descriptor parse error: {0}")]
    DescriptorParse(String),

    #[error("backend connection error: {0}")]
    BackendConnection(String),

    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("Esplora error: {0}")]
    Esplora(String),

    #[error("wallet error: {0}")]
    Wallet(String),

    #[error("no transactions found for wallet")]
    NoTransactions,

    #[error("invalid config: {0}")]
    InvalidConfig(String),

    #[error("storage error: {0}")]
    Storage(String),
}
