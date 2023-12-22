use ciborium::from_reader;
use reqwest::{header, ClientBuilder, Url};
use serde::{de::DeserializeOwned, Deserialize};
use tokio::time::{sleep, Duration};

use ns_protocol::{
    index::{Inscription, NameState, ServiceState},
    ns::Value,
};

static APP_USER_AGENT: &str = concat!(
    "Mozilla/5.0 NS-Fetcher ",
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
);

pub struct Client {
    client: reqwest::Client,
    url: Url,
}

pub struct ClientOptions {
    pub endpoint: String,
}

#[derive(Debug, Deserialize)]
struct Response<T> {
    result: Option<T>,
    error: Option<Value>,
}

impl Client {
    pub async fn new(opts: &ClientOptions) -> anyhow::Result<Self> {
        let mut common_headers = header::HeaderMap::with_capacity(3);
        common_headers.insert(header::ACCEPT, "application/cbor".parse()?);
        common_headers.insert(header::CONTENT_TYPE, "application/cbor".parse()?);
        common_headers.insert(header::ACCEPT_ENCODING, "gzip".parse()?);

        let url = reqwest::Url::parse(&opts.endpoint)?;
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

    pub async fn ping(&self) -> anyhow::Result<Value> {
        self.call("/healthz", &[]).await
    }

    pub async fn get_last_accepted_inscription(&self) -> anyhow::Result<Inscription> {
        self.call("/v1/inscription/get_last_accepted", &[]).await
    }

    pub async fn get_inscription_by_height(&self, height: u64) -> anyhow::Result<Inscription> {
        self.call(
            "/v1/inscription/get_by_height",
            &[("height", height.to_string().as_str())],
        )
        .await
    }

    pub async fn get_name_state(&self, name: &str) -> anyhow::Result<NameState> {
        self.call("/v1/name", &[("name", name)]).await
    }

    pub async fn get_service_state(&self, name: &str, code: u64) -> anyhow::Result<ServiceState> {
        self.call(
            "/v1/service",
            &[("name", name), ("code", code.to_string().as_str())],
        )
        .await
    }

    pub async fn call<T: DeserializeOwned>(
        &self,
        path: &str,
        query_pairs: &[(&str, &str)],
    ) -> anyhow::Result<T> {
        let mut url = self.url.join(path)?;
        if !query_pairs.is_empty() {
            url.query_pairs_mut().extend_pairs(query_pairs);
        }

        // retry if server error
        let mut retry_secs = 0;
        let res = loop {
            match self.client.get(url.clone()).send().await {
                Ok(res) => break res,
                Err(err) => {
                    retry_secs += 1;
                    if retry_secs <= 5 {
                        sleep(Duration::from_secs(retry_secs)).await;
                        continue;
                    } else {
                        anyhow::bail!("Client: {}", err.to_string());
                    }
                }
            }
        };

        let data = res.bytes().await?;
        let output: Response<T> = from_reader(&data[..]).map_err(|err| {
            anyhow::anyhow!(
                "Client: failed to parse response, {}, data: {}",
                err.to_string(),
                String::from_utf8_lossy(&data)
            )
        })?;

        if let Some(error) = output.error {
            anyhow::bail!("Client: {:?}", error);
        }

        match output.result {
            Some(result) => Ok(result),
            None => Err(anyhow::anyhow!("Client: no result")),
        }
    }
}
