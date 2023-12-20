use aes_gcm::{
    aead::{AeadCore, KeyInit},
    AeadInPlace, Aes256Gcm, Key, Nonce,
};
use coset::{iana, CoseEncrypt0, CoseEncrypt0Builder, HeaderBuilder, TaggedCborSerializable};
use rand_core::OsRng;

pub struct Encrypt0 {
    cipher: Aes256Gcm,
}

impl Encrypt0 {
    pub fn new(key: [u8; 32]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(key);
        Self { cipher }
    }

    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8], kid: &[u8]) -> anyhow::Result<Vec<u8>> {
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::A256GCM)
            .build();
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let unprotected = HeaderBuilder::new()
            .key_id(kid.to_vec())
            .iv(nonce.to_vec())
            .build();

        let e0 = CoseEncrypt0Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .create_ciphertext(plaintext, aad, |plain, enc| {
                let mut buf: Vec<u8> = Vec::with_capacity(plain.len() + 16);
                buf.extend_from_slice(plain);
                self.cipher.encrypt_in_place(&nonce, enc, &mut buf).unwrap();
                buf
            })
            .build();
        e0.to_tagged_vec().map_err(anyhow::Error::msg)
    }

    pub fn decrypt(&self, encrypt0_data: &[u8], aad: &[u8]) -> anyhow::Result<Vec<u8>> {
        let e0 = CoseEncrypt0::from_tagged_slice(encrypt0_data).map_err(anyhow::Error::msg)?;
        if e0.unprotected.iv.len() != 12 {
            return Err(anyhow::Error::msg("invalid iv length"));
        }
        let nonce = Nonce::from_slice(&e0.unprotected.iv);
        e0.decrypt(aad, |cipher, enc| {
            let mut buf: Vec<u8> = Vec::with_capacity(cipher.len() + 16);
            buf.extend_from_slice(cipher);
            self.cipher
                .decrypt_in_place(nonce, enc, &mut buf)
                .map_err(anyhow::Error::msg)?;
            Ok(buf)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand_core::RngCore;

    #[test]
    fn encrypt0_works() {
        let mut key = [0u8; 32];

        OsRng.fill_bytes(&mut key);
        let encrypt0 = Encrypt0::new(key);

        let plaintext = b"hello world";
        let data = encrypt0.encrypt(plaintext, b"yiwen.ai", b"test").unwrap();
        // println!("{}", hex_string(&data));
        let res = encrypt0.decrypt(&data, b"yiwen.ai").unwrap();
        assert_eq!(res, plaintext);
        assert!(encrypt0.decrypt(&data[1..], b"yiwen.ai").is_err());
        assert!(encrypt0.decrypt(&data, b"yiwen").is_err());
    }
}
