use dotenvy::dotenv;
use futures::future::FutureExt;
use std::sync::Arc;
use structured_logger::{async_json::new_writer, get_env_level, Builder};
use tokio::signal;

use ns_indexer::api::IndexerAPI;
use ns_indexer::bitcoin::{BitcoinRPC, BitcoinRPCOptions};
use ns_indexer::db::scylladb::ScyllaDBOptions;
use ns_indexer::indexer::{Indexer, IndexerOptions};
use ns_indexer::router;
use ns_indexer::scanner::Scanner;

// #[tokio::main(flavor = "multi_thread", worker_threads = 2)]
fn main() -> anyhow::Result<()> {
    dotenv().expect(".env file not found");

    Builder::with_level(&get_env_level().to_string())
        .with_target_writer("*", new_writer(tokio::io::stdout()))
        .init();

    let worker_threads = std::env::var("INDEXER_SERVER_WORKER_THREADS")
        .unwrap_or("0".to_string())
        .parse::<usize>()
        .unwrap();

    let mut tokio_builder = tokio::runtime::Builder::new_multi_thread();
    if worker_threads > 0 {
        tokio_builder.worker_threads(worker_threads);
    }

    tokio_builder.enable_all().build().unwrap().block_on(async {
        let rpcurl = std::env::var("BITCOIN_RPC_URL").unwrap();
        let rpcuser = std::env::var("BITCOIN_RPC_USER").unwrap();
        let rpcpassword = std::env::var("BITCOIN_RPC_PASSWORD").unwrap();

        // 709632: This block marks the moment Taproot was activated on the Bitcoin network
        let start_height = std::env::var("INDEXER_START_HEIGHT")
            .unwrap_or("709632".to_string())
            .parse::<u64>()
            .unwrap();

        let scylla = ScyllaDBOptions {
            nodes: std::env::var("SCYLLA_NODES")
                .unwrap()
                .split(',')
                .map(|s| s.to_string())
                .collect(),
            username: std::env::var("SCYLLA_USERNAME").unwrap_or_default(),
            password: std::env::var("SCYLLA_PASSWORD").unwrap_or_default(),
            keyspace: std::env::var("SCYLLA_KEYSPACE").unwrap_or_default(),
        };

        let bitcoin = BitcoinRPC::new(&BitcoinRPCOptions {
            rpcurl,
            rpcuser,
            rpcpassword,
        })
        .await?;

        let indexer = Indexer::new(&IndexerOptions {
            scylla,
            index_utxo: std::env::var("INDEXER_UTXO")
                .unwrap_or("false".to_string())
                .parse::<bool>()
                .unwrap(),
        })
        .await?;

        let last_accepted_height = indexer.initialize().await?;
        let start_height = if last_accepted_height > 0 {
            last_accepted_height + 1
        } else {
            start_height
        };

        let indexer = Arc::new(indexer);
        let scanner = Scanner::new(Arc::new(bitcoin), indexer.clone());

        let indexer_api = IndexerAPI::new(indexer.clone());
        let app = router::new(Arc::new(indexer_api));
        let shutdown = shutdown_signal().shared();

        let api = async {
            let addr = std::env::var("INDEXER_SERVER_ADDR").unwrap_or("127.0.0.1:3000".to_string());
            log::info!(
                "{}@{} start at {}",
                ns_indexer::APP_NAME,
                ns_indexer::APP_VERSION,
                &addr
            );
            let listener = tokio::net::TcpListener::bind(&addr)
                .await
                .expect("failed to bind");

            match axum::serve(listener, app)
                .with_graceful_shutdown(shutdown.clone())
                .await
            {
                Ok(_) => log::info!(target: "server", "indexer api finished"),
                Err(err) => log::error!(target: "server", "indexer api error: {}", err),
            }

            Ok::<(), anyhow::Error>(())
        };

        let scanning = std::env::var("INDEXER_SERVER_NOSCAN").unwrap_or_default() != "true";
        let background_job = async {
            if scanning {
                match scanner.run(shutdown.clone(), start_height).await {
                    Ok(_) => log::info!(target: "server", "scanner finished"),
                    Err(err) => {
                        log::error!(target: "server", "scanner error: {}", err);
                        // should exit the process and restart
                        return Err(err);
                    }
                }
            }

            Ok::<(), anyhow::Error>(())
        };

        let _ = futures::future::try_join(api, background_job).await?;
        Ok(())
    })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    log::info!(target: "server", "signal received, starting graceful shutdown");
}
