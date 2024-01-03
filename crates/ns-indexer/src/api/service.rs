use axum::{
    extract::{Query, State},
    Extension,
};
use std::sync::Arc;
use validator::Validate;

use ns_axum_web::{
    context::ReqContext,
    erring::{HTTPError, SuccessResponse},
    object::PackObject,
};
use ns_protocol::state::ServiceState;

use crate::api::{IndexerAPI, QueryName};
use crate::db;

pub struct ServiceAPI;

impl ServiceAPI {
    pub async fn get(
        State(app): State<Arc<IndexerAPI>>,
        Extension(ctx): Extension<Arc<ReqContext>>,
        to: PackObject<()>,
        input: Query<QueryName>,
    ) -> Result<PackObject<SuccessResponse<ServiceState>>, HTTPError> {
        input.validate()?;
        if input.code.is_none() {
            return Err(HTTPError::new(400, "service code is required".to_string()));
        }

        let name = input.name.clone();
        let code = input.code.unwrap();
        ctx.set_kvs(vec![
            ("action", "get_service_state".into()),
            ("name", name.clone().into()),
            ("code", code.into()),
        ])
        .await;

        let mut service_state = db::ServiceState::with_pk(name, code);
        service_state.get_one(&app.scylla, vec![]).await?;

        Ok(to.with(SuccessResponse::new(service_state.to_index()?)))
    }

    pub async fn get_best(
        State(app): State<Arc<IndexerAPI>>,
        Extension(ctx): Extension<Arc<ReqContext>>,
        to: PackObject<()>,
        input: Query<QueryName>,
    ) -> Result<PackObject<SuccessResponse<ServiceState>>, HTTPError> {
        input.validate()?;
        if input.code.is_none() {
            return Err(HTTPError::new(400, "service code is required".to_string()));
        }

        let name = input.name.clone();
        let code = input.code.unwrap() as u64;
        ctx.set_kvs(vec![
            ("action", "get_best_service_state".into()),
            ("name", name.clone().into()),
            ("code", code.into()),
        ])
        .await;

        {
            let best_names_state = app.state.confirming_names.read().await;
            if let Some(states) = best_names_state.get(&name) {
                for ss in states.iter().rev() {
                    if ss.1.code == code {
                        return Ok(to.with(SuccessResponse::new(ss.1.clone())));
                    }
                }
            }
        }

        Err(HTTPError::new(404, "not found".to_string()))
    }

    pub async fn list_by_name(
        State(app): State<Arc<IndexerAPI>>,
        Extension(ctx): Extension<Arc<ReqContext>>,
        to: PackObject<()>,
        input: Query<QueryName>,
    ) -> Result<PackObject<SuccessResponse<Vec<ServiceState>>>, HTTPError> {
        input.validate()?;

        let name = input.name.clone();
        ctx.set_kvs(vec![
            ("action", "list_service_states_by_name".into()),
            ("name", name.clone().into()),
        ])
        .await;

        let res = db::ServiceState::list_by_name(&app.scylla, &name, vec![]).await?;
        let mut service_states: Vec<ServiceState> = Vec::with_capacity(res.len());
        for i in res {
            service_states.push(i.to_index()?);
        }
        Ok(to.with(SuccessResponse::new(service_states)))
    }
}
