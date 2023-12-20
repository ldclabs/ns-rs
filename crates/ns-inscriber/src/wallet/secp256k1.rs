use bitcoin::Network;
// use bip32::{DerivationPath, XPrv};
use rand_core::OsRng;

pub use bitcoin::{
    bip32::{ChildNumber, DerivationPath, Xpriv, Xpub},
    secp256k1::{
        hashes::{sha256, Hash},
        schnorr::Signature,
        Keypair, Message, PublicKey, Secp256k1, SecretKey, Signing, Verification,
    },
    sign_message::{signed_msg_hash, MessageSignature},
    ScriptBuf,
};

pub fn derive_secp256k1<C>(
    secp: &Secp256k1<C>,
    network: Network,
    seed: &[u8],
    path: &DerivationPath,
) -> anyhow::Result<Keypair>
where
    C: Signing,
{
    let root = Xpriv::new_master(network, seed)?;
    let child = root.derive_priv(secp, &path)?;
    let key_pair = Keypair::from_seckey_slice(secp, child.to_priv().to_bytes().as_slice())?;
    Ok(key_pair)
}

pub fn new_secp256k1<C>(secp: &Secp256k1<C>) -> Keypair
where
    C: Signing,
{
    Keypair::new(secp, &mut OsRng)
}

// return (p2wpkh_pubkey, p2tr_pubkey)
pub fn as_script_pubkey<C>(secp: &Secp256k1<C>, keypair: &Keypair) -> (ScriptBuf, ScriptBuf)
where
    C: Verification,
{
    let (xpk, _parity) = keypair.x_only_public_key();
    (
        ScriptBuf::new_p2wpkh(
            &bitcoin::PublicKey::new(keypair.public_key())
                .wpubkey_hash()
                .expect("key is compressed"),
        ),
        ScriptBuf::new_p2tr(secp, xpk, None),
    )
}

pub fn sign_message<C>(secp: &Secp256k1<C>, sk: &SecretKey, message: &str) -> MessageSignature
where
    C: Signing,
{
    let msg: Message = signed_msg_hash(message).into();
    let sig = secp.sign_ecdsa_recoverable(&msg, sk);
    MessageSignature::new(sig, true)
}

pub fn verify_message<C>(
    secp: &Secp256k1<C>,
    pk: &PublicKey,
    message: &str,
    sig: &[u8],
) -> anyhow::Result<()>
where
    C: Verification,
{
    let msg = signed_msg_hash(message);
    let sig = MessageSignature::from_slice(sig)?;
    let pubkey = sig.recover_pubkey(secp, msg)?;
    if pk != &pubkey.inner {
        anyhow::bail!("invalid signature");
    }
    Ok(())
}
