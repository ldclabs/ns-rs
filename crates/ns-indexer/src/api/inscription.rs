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
use ns_protocol::index::{Inscription, InvalidInscription};

use crate::api::{IndexerAPI, QueryHeight, QueryName, QueryNamePagination};
use crate::db;

pub struct InscriptionAPI;

impl InscriptionAPI {
    pub async fn get_last_accepted(
        Extension(ctx): Extension<Arc<ReqContext>>,
        to: PackObject<()>,
        State(api): State<Arc<IndexerAPI>>,
    ) -> Result<PackObject<SuccessResponse<Option<Inscription>>>, HTTPError> {
        ctx.set("action", "get_last_accepted_inscription".into())
            .await;

        let last_accepted_state = api.state.last_accepted.read().await;

        Ok(to.with(SuccessResponse::new(last_accepted_state.clone())))
    }

    pub async fn get_best(
        Extension(ctx): Extension<Arc<ReqContext>>,
        to: PackObject<()>,
        State(api): State<Arc<IndexerAPI>>,
    ) -> Result<PackObject<SuccessResponse<Option<Inscription>>>, HTTPError> {
        ctx.set("action", "get_best_inscription".into()).await;

        let best_inscriptions_state = api.state.best_inscriptions.read().await;
        let mut inscription = best_inscriptions_state.last().cloned();
        if inscription.is_none() {
            let last_accepted_state = api.state.last_accepted.read().await;
            inscription = last_accepted_state.clone();
        }

        Ok(to.with(SuccessResponse::new(inscription)))
    }

    pub async fn get(
        State(app): State<Arc<IndexerAPI>>,
        Extension(ctx): Extension<Arc<ReqContext>>,
        to: PackObject<()>,
        input: Query<QueryName>,
    ) -> Result<PackObject<SuccessResponse<Inscription>>, HTTPError> {
        input.validate()?;
        if input.sequence.is_none() {
            return Err(HTTPError::new(400, "sequence is required".to_string()));
        }

        let name = input.name.clone();
        let sequence = input.sequence.unwrap();
        ctx.set_kvs(vec![
            ("action", "get_inscription".into()),
            ("name", name.clone().into()),
            ("sequence", sequence.into()),
        ])
        .await;

        let mut inscription = db::Inscription::with_pk(name, sequence);
        inscription.get_one(&app.scylla, vec![]).await?;

        Ok(to.with(SuccessResponse::new(inscription.to_index()?)))
    }

    pub async fn get_by_height(
        State(app): State<Arc<IndexerAPI>>,
        Extension(ctx): Extension<Arc<ReqContext>>,
        to: PackObject<()>,
        input: Query<QueryHeight>,
    ) -> Result<PackObject<SuccessResponse<Inscription>>, HTTPError> {
        input.validate()?;

        let height = input.height;
        ctx.set_kvs(vec![
            ("action", "get_inscription_by_height".into()),
            ("height", height.into()),
        ])
        .await;

        let inscription = db::Inscription::get_by_height(&app.scylla, height, vec![]).await?;

        Ok(to.with(SuccessResponse::new(inscription.to_index()?)))
    }

    pub async fn list_best(
        Extension(ctx): Extension<Arc<ReqContext>>,
        to: PackObject<()>,
        State(api): State<Arc<IndexerAPI>>,
    ) -> Result<PackObject<SuccessResponse<Vec<Inscription>>>, HTTPError> {
        ctx.set("action", "list_best_inscriptions".into()).await;
        let best_inscriptions_state = api.state.best_inscriptions.read().await;
        Ok(to.with(SuccessResponse::new(best_inscriptions_state.clone())))
    }

    pub async fn list_by_block_height(
        State(app): State<Arc<IndexerAPI>>,
        Extension(ctx): Extension<Arc<ReqContext>>,
        to: PackObject<()>,
        input: Query<QueryHeight>,
    ) -> Result<PackObject<SuccessResponse<Vec<Inscription>>>, HTTPError> {
        input.validate()?;

        let height = input.height;
        ctx.set_kvs(vec![
            ("action", "list_inscriptions_block_height".into()),
            ("height", height.into()),
        ])
        .await;

        let res = db::Inscription::list_by_block_height(&app.scylla, height, vec![]).await?;
        let mut inscriptions: Vec<Inscription> = Vec::with_capacity(res.len());
        for i in res {
            inscriptions.push(i.to_index()?);
        }
        Ok(to.with(SuccessResponse::new(inscriptions)))
    }

    pub async fn list_by_name(
        State(app): State<Arc<IndexerAPI>>,
        Extension(ctx): Extension<Arc<ReqContext>>,
        to: PackObject<()>,
        input: Query<QueryNamePagination>,
    ) -> Result<PackObject<SuccessResponse<Vec<Inscription>>>, HTTPError> {
        input.validate()?;

        let name = input.name.clone();
        ctx.set_kvs(vec![
            ("action", "list_inscriptions_by_name".into()),
            ("name", name.clone().into()),
        ])
        .await;

        let res = db::Inscription::list_by_name(
            &app.scylla,
            &name,
            vec![],
            input.page_size.unwrap_or(10),
            input.page_token,
        )
        .await?;
        let mut inscriptions: Vec<Inscription> = Vec::with_capacity(res.len());
        for i in res {
            inscriptions.push(i.to_index()?);
        }
        let next_sequence = if let Some(last) = inscriptions.last() {
            last.sequence
        } else {
            0
        };
        Ok(to.with(SuccessResponse {
            total_size: None,
            next_page_token: if next_sequence > 0 {
                Some(next_sequence.to_string())
            } else {
                None
            },
            result: inscriptions,
        }))
    }

    pub async fn list_invalid_by_name(
        State(app): State<Arc<IndexerAPI>>,
        Extension(ctx): Extension<Arc<ReqContext>>,
        to: PackObject<()>,
        input: Query<QueryName>,
    ) -> Result<PackObject<SuccessResponse<Vec<InvalidInscription>>>, HTTPError> {
        input.validate()?;

        let name = input.name.clone();
        ctx.set_kvs(vec![
            ("action", "list_invalid_inscriptions_by_name".into()),
            ("name", name.clone().into()),
        ])
        .await;

        let res = db::InvalidInscription::list_by_name(&app.scylla, &name).await?;
        let mut inscriptions: Vec<InvalidInscription> = Vec::with_capacity(res.len());
        for i in res {
            inscriptions.push(i.to_index()?);
        }

        Ok(to.with(SuccessResponse::new(inscriptions)))
    }
}
