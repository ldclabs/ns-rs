pub mod api;
pub mod bitcoin;
pub mod db;
pub mod envelope;
pub mod indexer;
pub mod router;
pub mod scanner;
pub mod utxo;

pub const APP_NAME: &str = env!("CARGO_PKG_NAME");
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
