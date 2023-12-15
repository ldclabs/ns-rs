use axum::extract::State;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use axum_web::erring::{HTTPError, SuccessResponse};
use axum_web::object::PackObject;
use ns_protocol::index::Inscription;

use crate::indexer::Indexer;

pub const APP_NAME: &str = env!("CARGO_PKG_NAME");
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Serialize, Deserialize)]
pub struct AppVersion {
    pub name: String,
    pub version: String,
}

pub struct IndexerAPI {
    indexer: Arc<Indexer>,
}

impl IndexerAPI {
    pub fn new(indexer: Arc<Indexer>) -> Self {
        Self { indexer }
    }
}

pub async fn version(
    to: PackObject<()>,
    State(_): State<Arc<IndexerAPI>>,
) -> PackObject<AppVersion> {
    to.with(AppVersion {
        name: APP_NAME.to_string(),
        version: APP_VERSION.to_string(),
    })
}

pub async fn get_last_accepted(
    to: PackObject<()>,
    State(api): State<Arc<IndexerAPI>>,
) -> Result<PackObject<SuccessResponse<Option<Inscription>>>, HTTPError> {
    let last_accepted_state = api.indexer.state.last_accepted.read().await;

    Ok(to.with(SuccessResponse::new(last_accepted_state.clone())))
}
