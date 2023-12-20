use axum::extract::State;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use validator::{Validate, ValidationError};

use axum_web::erring::{HTTPError, SuccessResponse};
use axum_web::object::PackObject;
use ns_protocol::ns;

use crate::db::scylladb::ScyllaDB;
use crate::indexer::{Indexer, IndexerState};

mod inscription;
mod name;
mod service;
mod utxo;

pub use inscription::InscriptionAPI;
pub use name::NameAPI;
pub use service::ServiceAPI;
pub use utxo::UtxoAPI;

#[derive(Serialize, Deserialize)]
pub struct AppVersion {
    pub name: String,
    pub version: String,
}

#[derive(Serialize, Deserialize)]
pub struct AppHealth {
    pub block_height: u64,
    pub inscription_height: u64,
}

pub struct IndexerAPI {
    pub(crate) scylla: Arc<ScyllaDB>,
    pub(crate) state: Arc<IndexerState>,
}

impl IndexerAPI {
    pub fn new(indexer: Arc<Indexer>) -> Self {
        Self {
            scylla: indexer.scylla.clone(),
            state: indexer.state.clone(),
        }
    }
}

pub async fn version(
    to: PackObject<()>,
    State(_): State<Arc<IndexerAPI>>,
) -> PackObject<AppVersion> {
    to.with(AppVersion {
        name: crate::APP_NAME.to_string(),
        version: crate::APP_VERSION.to_string(),
    })
}

pub async fn healthz(
    to: PackObject<()>,
    State(api): State<Arc<IndexerAPI>>,
) -> Result<PackObject<SuccessResponse<AppHealth>>, HTTPError> {
    let last_accepted_state = api.state.last_accepted.read().await;
    let (block_height, height) = match *last_accepted_state {
        Some(ref last_accepted) => (last_accepted.block_height, last_accepted.height),
        None => (0, 0),
    };
    Ok(to.with(SuccessResponse::new(AppHealth {
        block_height,
        inscription_height: height,
    })))
}

#[derive(Debug, Deserialize, Validate)]
pub struct QueryName {
    #[validate(custom = "validate_name")]
    pub name: String,
    #[validate(range(min = 0))]
    pub sequence: Option<i64>,
    #[validate(range(min = 0))]
    pub code: Option<i64>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct QueryHeight {
    #[validate(range(min = 0))]
    pub height: i64,
}

#[derive(Debug, Deserialize, Validate)]
pub struct QueryNamePagination {
    #[validate(custom = "validate_name")]
    pub name: String,
    pub page_token: Option<i64>,
    #[validate(range(min = 2, max = 1000))]
    pub page_size: Option<u16>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct QueryPubkey {
    pub pubkey: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct QueryAddress {
    pub address: String,
}

fn validate_name(name: &str) -> Result<(), ValidationError> {
    if !ns::valid_name(name) {
        return Err(ValidationError::new("invalid name"));
    }

    Ok(())
}
