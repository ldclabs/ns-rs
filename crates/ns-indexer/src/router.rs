use axum::{middleware, routing, Router};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    catch_panic::CatchPanicLayer,
    compression::{predicate::SizeAbove, CompressionLayer},
};

use axum_web::context;
use axum_web::encoding;

use crate::indexer_api;

pub fn new(state: Arc<indexer_api::IndexerAPI>) -> Router {
    let mds = ServiceBuilder::new()
        .layer(CatchPanicLayer::new())
        .layer(middleware::from_fn(context::middleware))
        .layer(CompressionLayer::new().compress_when(SizeAbove::new(encoding::MIN_ENCODING_SIZE)));

    Router::new()
        .route("/", routing::get(indexer_api::version))
        .route("/healthz", routing::get(indexer_api::version))
        .nest(
            "/v1/name",
            Router::new()
                .route("/", routing::get(indexer_api::version))
                .route("/list", routing::get(indexer_api::version))
                .route("/list_by_pubkey", routing::get(indexer_api::version)),
        )
        .nest(
            "/v1/service",
            Router::new()
                .route("/", routing::get(indexer_api::version))
                .route("/list", routing::get(indexer_api::version)),
        )
        .nest(
            "/v1/inscription",
            Router::new()
                .route("/", routing::get(indexer_api::version))
                .route(
                    "/get_last_accepted",
                    routing::get(indexer_api::get_last_accepted),
                )
                .route("/get_best", routing::get(indexer_api::version))
                .route("/get_by_height", routing::get(indexer_api::version))
                .route("/list_by_name", routing::get(indexer_api::version))
                .route("/list_by_block_height", routing::get(indexer_api::version)),
        )
        .nest(
            "/v1/invalid_inscription",
            Router::new().route("/list_by_name", routing::get(indexer_api::version)),
        )
        .nest(
            "/v1/service_protocol",
            Router::new()
                .route("/", routing::get(indexer_api::version))
                .route("/list", routing::get(indexer_api::version))
                .route("/list_by_code", routing::get(indexer_api::version))
                .route("/list_by_submitter", routing::get(indexer_api::version)),
        )
        .route_layer(mds)
        .with_state(state)
}
