use base64::{engine::general_purpose, Engine as _};
use rand_core::{OsRng, RngCore};
use sha3::{Digest, Sha3_256};

mod cose_key;
pub mod ed25519;
mod encrypt;
pub mod secp256k1;
mod sign;

pub use bitcoin::bip32::DerivationPath;
pub use cose_key::{new_sym, CoseSigner, CoseVerifier, KeyHelper};
pub use coset::iana;
pub use encrypt::Encrypt0;
pub use sign::{decode_sign1, encode_sign1};

// https://www.rfc-editor.org/rfc/rfc8949.html#name-self-described-cbor
pub const CBOR_TAG: [u8; 3] = [0xd9, 0xd9, 0xf7];
pub const ENCRYPT0_TAG: [u8; 1] = [0xd0];
pub const SIGN1_TAG: [u8; 1] = [0xd2];

pub fn base64url_encode(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

pub fn base64url_decode(data: &str) -> anyhow::Result<Vec<u8>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(data.trim_end_matches('='))
        .map_err(anyhow::Error::msg)
}

pub fn base64_decode(data: &str) -> anyhow::Result<Vec<u8>> {
    general_purpose::STANDARD_NO_PAD
        .decode(data.trim_end_matches('='))
        .map_err(anyhow::Error::msg)
}

pub fn with_tag(tag: &[u8], data: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(data.len() + tag.len());
    buf.extend_from_slice(tag);
    buf.extend_from_slice(data);
    buf
}

pub fn skip_tag<'a>(tag: &'a [u8], data: &'a [u8]) -> &'a [u8] {
    if data.starts_with(tag) {
        &data[tag.len()..]
    } else {
        data
    }
}

pub fn hash_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn random_bytes(dest: &mut [u8]) {
    OsRng.fill_bytes(dest);
}
