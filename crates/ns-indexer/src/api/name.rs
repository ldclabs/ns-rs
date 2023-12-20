use axum::{
    extract::{Query, State},
    Extension,
};
use std::sync::Arc;
use validator::Validate;

use axum_web::{
    context::ReqContext,
    erring::{HTTPError, SuccessResponse},
    object::PackObject,
};
use ns_protocol::index::NameState;

use crate::api::{IndexerAPI, QueryName, QueryPubkey};
use crate::db;

pub struct NameAPI;

impl NameAPI {
    pub async fn get(
        State(app): State<Arc<IndexerAPI>>,
        Extension(ctx): Extension<Arc<ReqContext>>,
        to: PackObject<()>,
        input: Query<QueryName>,
    ) -> Result<PackObject<SuccessResponse<NameState>>, HTTPError> {
        input.validate()?;

        let name = input.name.clone();
        ctx.set_kvs(vec![
            ("action", "get_name_state".into()),
            ("name", name.clone().into()),
        ])
        .await;

        let mut name_state = db::NameState::with_pk(name);
        name_state.get_one(&app.scylla, vec![]).await?;

        Ok(to.with(SuccessResponse::new(name_state.to_index()?)))
    }

    pub async fn list_by_query(
        State(app): State<Arc<IndexerAPI>>,
        Extension(ctx): Extension<Arc<ReqContext>>,
        to: PackObject<()>,
        input: Query<QueryName>,
    ) -> Result<PackObject<SuccessResponse<Vec<String>>>, HTTPError> {
        input.validate()?;

        let query = input.name.clone();
        ctx.set_kvs(vec![
            ("action", "list_names_by_query".into()),
            ("query", query.clone().into()),
        ])
        .await;

        let names = db::NameState::list_by_query(&app.scylla, query).await?;

        Ok(to.with(SuccessResponse::new(names)))
    }

    pub async fn list_by_pubkey(
        State(app): State<Arc<IndexerAPI>>,
        Extension(ctx): Extension<Arc<ReqContext>>,
        to: PackObject<()>,
        input: Query<QueryPubkey>,
    ) -> Result<PackObject<SuccessResponse<Vec<String>>>, HTTPError> {
        input.validate()?;

        let key = if input.pubkey.starts_with("0x") {
            &input.pubkey[2..]
        } else {
            input.pubkey.as_str()
        };
        let pubkey = hex::decode(key)
            .map_err(|_| HTTPError::new(400, format!("Invalid pubkey: {}", input.pubkey)))?;
        ctx.set_kvs(vec![("action", "list_names_by_pubkey".into())])
            .await;

        let mut names = db::NameState::list_by_pubkey(&app.scylla, pubkey.to_vec()).await?;
        names.sort();
        Ok(to.with(SuccessResponse::new(names)))
    }
}
