use axum::{middleware, routing, Router};
use std::sync::Arc;
use std::time::Duration;
use tower_http::{
    catch_panic::CatchPanicLayer,
    compression::{predicate::SizeAbove, CompressionLayer},
    cors::CorsLayer,
    timeout::TimeoutLayer,
};

use ns_axum_web::context;
use ns_axum_web::encoding;

use crate::api;

pub fn new(state: Arc<api::IndexerAPI>) -> Router {
    Router::new()
        .route("/", routing::get(api::version))
        .route("/healthz", routing::get(api::healthz))
        .nest(
            "/best",
            Router::new()
                .route("/inscription", routing::get(api::InscriptionAPI::get_best))
                .route(
                    "/inscription/get_last",
                    routing::get(api::InscriptionAPI::get_last_best),
                )
                .route(
                    "/inscription/get_by_height",
                    routing::get(api::InscriptionAPI::get_best_by_height),
                )
                .route(
                    "/inscription/list",
                    routing::get(api::InscriptionAPI::list_best),
                )
                .route("/name", routing::get(api::NameAPI::get_best))
                .route("/service", routing::get(api::ServiceAPI::get_best))
                .route("/utxo/list", routing::get(api::UtxoAPI::list)),
        )
        .nest(
            "/v1/name",
            Router::new()
                .route("/", routing::get(api::NameAPI::get))
                .route("/list_by_query", routing::get(api::NameAPI::list_by_query))
                .route(
                    "/list_by_pubkey",
                    routing::get(api::NameAPI::list_by_pubkey),
                ),
        )
        .nest(
            "/v1/service",
            Router::new()
                .route("/", routing::get(api::ServiceAPI::get))
                .route("/list_by_name", routing::get(api::ServiceAPI::list_by_name)),
        )
        .nest(
            "/v1/inscription",
            Router::new()
                .route("/", routing::get(api::InscriptionAPI::get))
                .route(
                    "/get_last_accepted",
                    routing::get(api::InscriptionAPI::get_last_accepted),
                )
                .route(
                    "/get_by_height",
                    routing::get(api::InscriptionAPI::get_by_height),
                )
                .route(
                    "/list_by_block_height",
                    routing::get(api::InscriptionAPI::list_by_block_height),
                )
                .route(
                    "/list_by_name",
                    routing::get(api::InscriptionAPI::list_by_name),
                ),
        )
        .nest(
            "/v1/invalid_inscription",
            Router::new().route(
                "/list_by_name",
                routing::get(api::InscriptionAPI::list_invalid_by_name),
            ),
        )
        // .nest(
        //     "/v1/service_protocol",
        //     Router::new()
        //         .route("/", routing::get(api::ServiceAPI::get))
        //         .route("/list", routing::get(api::ServiceAPI::get))
        //         .route("/list_by_code", routing::get(api::ServiceAPI::get))
        //         .route("/list_by_submitter", routing::get(api::ServiceAPI::get)),
        // )
        .layer((
            CatchPanicLayer::new(),
            TimeoutLayer::new(Duration::from_secs(10)),
            CorsLayer::very_permissive(),
            middleware::from_fn(context::middleware),
            CompressionLayer::new().compress_when(SizeAbove::new(encoding::MIN_ENCODING_SIZE)),
        ))
        .with_state(state)
}
