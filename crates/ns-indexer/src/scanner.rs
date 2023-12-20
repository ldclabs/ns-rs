use bitcoin::BlockHash;
use futures::future::Shared;
use std::{future::Future, sync::Arc};
use tokio::time::{sleep, Duration};

use crate::bitcoin::BitcoinRPC;
use crate::indexer::Indexer;

pub struct Scanner {
    bitcoin: Arc<BitcoinRPC>,
    indexer: Arc<Indexer>,
}

impl Scanner {
    pub fn new(bitcoin: Arc<BitcoinRPC>, indexer: Arc<Indexer>) -> Self {
        Self { bitcoin, indexer }
    }

    pub async fn run<S>(&self, signal: Shared<S>, start_height: u64) -> anyhow::Result<()>
    where
        S: Future<Output = ()>,
    {
        self.scan_blocks(signal, start_height).await?;
        Ok(())
    }

    async fn scan_blocks<S>(&self, signal: Shared<S>, start_height: u64) -> anyhow::Result<()>
    where
        S: Future<Output = ()>,
    {
        let mut height = start_height;
        let mut bestblock = self.bitcoin.wait_for_new_block(1).await?;

        loop {
            tokio::select! {
                _ = signal.clone() => {
                    log::warn!(target: "ns-indexer", "Received signal to stop indexing");
                    return Ok(());
                },
                _ = async {
                    if height > bestblock.height {
                        sleep(Duration::from_secs(3)).await;
                    }
                } => {},
            };

            let blockhash = if height > bestblock.height {
                bestblock = self.bitcoin.wait_for_new_block(1).await?;
                if height > bestblock.height {
                    log::info!(target: "ns-indexer",
                        action = "waiting_block",
                        block_hash = bestblock.hash.to_string(),
                        block_height = bestblock.height;
                        "",
                    );
                    continue;
                }

                // find a new block
                bestblock.hash
            } else {
                self.bitcoin.get_blockhash(height).await?
            };

            self.index_block(&blockhash).await?;
            height += 1;
        }
    }

    async fn index_block(&self, blockhash: &BlockHash) -> anyhow::Result<()> {
        let block = self.bitcoin.get_block(blockhash).await?;
        let block_height = block.bip34_block_height().unwrap_or_default();
        if block_height == 0 {
            return Ok(());
        }

        log::info!(target: "ns-indexer",
            action = "index_block",
            block_hash = blockhash.to_string(),
            block_height = block_height;
            "",
        );

        for tx in block.txdata {
            self.indexer
                .index(blockhash, block_height, block.header.time as u64, tx)
                .await?;
        }
        Ok(())
    }
}
