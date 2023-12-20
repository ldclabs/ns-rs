use bitcoin::bip32::DerivationPath;
use rand_core::{OsRng, RngCore};
use slip10_ed25519::derive_ed25519_private_key;

pub use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub fn derive_ed25519(seed: &[u8], path: &DerivationPath) -> SigningKey {
    let secret = derive_ed25519_private_key(seed, &path.to_u32_vec());
    SigningKey::from_bytes(&secret)
}

pub fn new_ed25519() -> SigningKey {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    SigningKey::from_bytes(&secret)
}

pub fn sign_message(sk: &SigningKey, msg: &str) -> Signature {
    sk.sign(msg.as_bytes())
}

pub fn verify_message(pk: &VerifyingKey, msg: &str, sig: &[u8]) -> anyhow::Result<()> {
    let sig = Signature::from_slice(sig)?;
    pk.verify_strict(msg.as_bytes(), &sig)?;
    Ok(())
}
