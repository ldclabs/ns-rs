use bitcoin::{
    address::NetworkChecked,
    secp256k1::{rand, Keypair, Secp256k1},
    Address, Network, ScriptBuf,
};
use dotenvy::dotenv;
use structured_logger::{async_json::new_writer, Builder};

use ns_inscriber::bitcoin::BitCoinRPCOptions;
use ns_inscriber::inscriber::{Inscriber, InscriberOptions};

#[tokio::main(flavor = "multi_thread", worker_threads = 1)]
async fn main() -> anyhow::Result<()> {
    dotenv().expect(".env file not found");

    Builder::with_level("info")
        .with_target_writer("*", new_writer(tokio::io::stdout()))
        .init();

    let rpcurl = std::env::var("BITCOIN_RPC_URL").unwrap();
    let rpcuser = std::env::var("BITCOIN_RPC_USER").unwrap();
    let rpcpassword = std::env::var("BITCOIN_RPC_PASSWORD").unwrap();

    let secp = Secp256k1::new();
    let key_pair = Keypair::new(&secp, &mut rand::thread_rng());
    let (public_key, _parity) = key_pair.x_only_public_key();
    let script_pubkey = ScriptBuf::new_p2tr(&secp, public_key, None);
    let address: Address<NetworkChecked> =
        Address::from_script(&script_pubkey, Network::Regtest).unwrap();

    println!("address: {}", address);

    let inscriber = Inscriber::new(&InscriberOptions {
        bitcoin: BitCoinRPCOptions {
            rpcurl,
            rpcuser,
            rpcpassword,
            network: Network::Regtest,
        },
    })
    .unwrap();

    inscriber.bitcoin.ping().await.unwrap();
    // ToDO
    Ok(())
}
