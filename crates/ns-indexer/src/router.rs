use axum::{middleware, routing, Router};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    catch_panic::CatchPanicLayer,
    compression::{predicate::SizeAbove, CompressionLayer},
};

use ns_axum_web::context;
use ns_axum_web::encoding;

use crate::api;

pub fn new(state: Arc<api::IndexerAPI>) -> Router {
    let mds = ServiceBuilder::new()
        .layer(CatchPanicLayer::new())
        .layer(middleware::from_fn(context::middleware))
        .layer(CompressionLayer::new().compress_when(SizeAbove::new(encoding::MIN_ENCODING_SIZE)));

    Router::new()
        .route("/", routing::get(api::version))
        .route("/healthz", routing::get(api::healthz))
        .route("/best/utxo/list", routing::get(api::UtxoAPI::list))
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
            "/best/inscription",
            Router::new()
                .route("/", routing::get(api::InscriptionAPI::get_best))
                .route("/list", routing::get(api::InscriptionAPI::list_best)),
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
        .route_layer(mds)
        .with_state(state)
}
