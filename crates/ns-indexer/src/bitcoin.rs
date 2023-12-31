use base64::Engine;
use bitcoin::{
    consensus::{Decodable, ReadExt},
    hex::HexToBytesIter,
    Block, BlockHash,
};
use bitcoincore_rpc_json as json;
use reqwest::{header, Client, ClientBuilder, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{to_value, to_vec, Value};
use tokio::time::{sleep, Duration};

static APP_USER_AGENT: &str = concat!(
    "Mozilla/5.0 NS-Indexer ",
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
);

pub struct BitcoinRPC {
    client: Client,
    url: Url,
}

pub struct BitcoinRPCOptions {
    pub rpcurl: String,
    pub rpcuser: String,
    pub rpcpassword: String,
}

#[derive(Debug, Serialize)]
struct RPCRequest<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    params: &'a [Value],
    id: u64,
}

#[derive(Debug, Deserialize)]
struct RPCResponse<T> {
    result: Option<T>,
    error: Option<Value>,
    // id: u64,
}

impl BitcoinRPC {
    pub async fn new(opts: &BitcoinRPCOptions) -> anyhow::Result<Self> {
        let mut common_headers = header::HeaderMap::with_capacity(4);
        common_headers.insert(header::ACCEPT, "application/json".parse()?);
        common_headers.insert(header::CONTENT_TYPE, "application/json".parse()?);
        common_headers.insert(header::ACCEPT_ENCODING, "gzip".parse()?);

        let url = reqwest::Url::parse(&opts.rpcurl)?;
        if !opts.rpcuser.is_empty() {
            let auth = format!("{}:{}", opts.rpcuser, opts.rpcpassword);
            let auth = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(auth)
            );
            common_headers.insert(header::AUTHORIZATION, auth.parse()?);
        }

        let client = ClientBuilder::new()
            .use_rustls_tls()
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent(APP_USER_AGENT)
            .default_headers(common_headers)
            .gzip(true)
            .build()?;

        let rpc = Self { client, url };
        rpc.ping().await?;
        Ok(rpc)
    }

    pub async fn ping(&self) -> anyhow::Result<()> {
        self.call("ping", &[]).await
    }

    pub async fn get_network_info(&self) -> anyhow::Result<json::GetNetworkInfoResult> {
        self.call("getnetworkinfo", &[]).await
    }

    pub async fn get_index_info(&self) -> anyhow::Result<json::GetIndexInfoResult> {
        self.call("getindexinfo", &[]).await
    }

    pub async fn get_best_blockhash(&self) -> anyhow::Result<BlockHash> {
        self.call("getbestblockhash", &[]).await
    }

    pub async fn get_blockhash(&self, height: u64) -> anyhow::Result<BlockHash> {
        self.call("getblockhash", &[height.into()]).await
    }

    pub async fn get_block(&self, hash: &bitcoin::BlockHash) -> anyhow::Result<Block> {
        let hex: String = self.call("getblock", &[to_value(hash)?, 0.into()]).await?;
        decode_hex(&hex)
    }

    pub async fn wait_for_new_block(&self, timeout_ms: u64) -> anyhow::Result<json::BlockRef> {
        self.call("waitfornewblock", &[timeout_ms.into()]).await
    }

    pub async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: &[Value],
    ) -> anyhow::Result<T> {
        let input = RPCRequest {
            jsonrpc: "1.0",
            method,
            params,
            id: 0,
        };
        let input = to_vec(&input)?;

        // retry if server error
        let mut retry_secs = 0;
        let res = loop {
            match self
                .client
                .post(self.url.clone())
                .body(input.clone())
                .send()
                .await
            {
                Ok(res) => break res,
                Err(err) => {
                    retry_secs += 1;
                    if retry_secs <= 5 {
                        log::warn!(target: "ns-indexer",
                            action = "bitcoin_rpc_retry";
                            "{}", err.to_string(),
                        );
                        sleep(Duration::from_secs(retry_secs)).await;
                        continue;
                    } else {
                        anyhow::bail!("BitcoinRPC: {}", err.to_string());
                    }
                }
            }
        };

        let data = res.bytes().await?;
        let output: RPCResponse<T> = serde_json::from_slice(&data).map_err(|err| {
            anyhow::anyhow!(
                "BitcoinRPC: failed to parse response, {}, data: {}",
                err.to_string(),
                String::from_utf8_lossy(&data)
            )
        })?;

        if let Some(error) = output.error {
            anyhow::bail!("BitcoinRPC: {}", error);
        }

        match output.result {
            Some(result) => Ok(result),
            None => serde_json::from_value(Value::Null)
                .map_err(|err| anyhow::anyhow!("BitcoinRPC: no result, {}", err.to_string())),
        }
    }
}

pub fn decode_hex<T: Decodable>(hex: &str) -> anyhow::Result<T> {
    let mut reader = HexToBytesIter::new(hex)?;
    let object = Decodable::consensus_decode(&mut reader)?;
    if reader.read_u8().is_ok() {
        Err(anyhow::anyhow!("decode_hex: data not consumed entirely"))
    } else {
        Ok(object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dotenvy::dotenv;

    #[test]
    fn decode_hex_works() {
        let hstr = "010000007de867cc8adc5cc8fb6b898ca4462cf9fd667d7830a275277447e60800000000338f121232e169d3100edd82004dc2a1f0e1f030c6c488fa61eafa930b0528fe021f7449ffff001d36b4af9a0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d02fd04ffffffff0100f2052a01000000434104f5eeb2b10c944c6b9fbcfff94c35bdeecd93df977882babc7f3a2cf7f5c81d3b09a68db7f0e04f21de5d4230e75e6dbe7ad16eefe0d4325a62067dc6f369446aac00000000";

        let blockhash: BlockHash =
            decode_hex("09edf646d13d2a7e1da8bdad14d249b037eccd8af23aa704379837c900000000").unwrap();
        assert_eq!(
            blockhash.to_string(),
            "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"
        );

        let block: Block = decode_hex(hstr).unwrap();
        assert_eq!(blockhash, block.block_hash());
        println!("{:#?}", block.txdata);
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore]
    async fn rpc_works() {
        dotenv().expect(".env file not found");

        let rpcurl = std::env::var("BITCOIN_RPC_URL").unwrap();
        let rpcuser = std::env::var("BITCOIN_RPC_USER").unwrap();
        let rpcpassword = std::env::var("BITCOIN_RPC_PASSWORD").unwrap();

        let cli = BitcoinRPC::new(&BitcoinRPCOptions {
            rpcurl,
            rpcuser,
            rpcpassword,
        })
        .await
        .unwrap();

        let blockhash = cli.get_blockhash(99).await.unwrap();
        let block = cli.get_block(&blockhash).await.unwrap();
        assert_eq!(blockhash, block.block_hash());
        assert_eq!(99, block.bip34_block_height().unwrap_or(99));
    }
}
