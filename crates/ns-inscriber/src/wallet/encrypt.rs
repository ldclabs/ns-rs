use aes_gcm::{
    aead::{AeadCore, KeyInit},
    AeadInPlace, Aes256Gcm, Key, Nonce,
};
use coset::{iana, CborSerializable, CoseEncrypt0, CoseEncrypt0Builder, HeaderBuilder};
use rand_core::OsRng;

use ns_protocol::{ns::Value, state::to_bytes};

use super::{skip_tag, with_tag, ENCRYPT0_TAG};

pub struct Encrypt0 {
    kid: Option<Value>,
    cipher: Aes256Gcm,
}

impl Encrypt0 {
    pub fn new(key: [u8; 32], kid: Option<Value>) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(key);
        Self { kid, cipher }
    }

    pub fn encrypt(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        cid: Option<Value>,
    ) -> anyhow::Result<Vec<u8>> {
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::A256GCM)
            .build();
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let mut unprotected = HeaderBuilder::new()
            .key_id(to_bytes(&self.kid)?)
            .iv(nonce.to_vec());
        if let Some(kid) = self.kid.as_ref() {
            unprotected = unprotected.key_id(to_bytes(kid)?);
        }
        if let Some(cid) = cid {
            unprotected = unprotected.text_value("cid".to_string(), cid);
        }

        let e0 = CoseEncrypt0Builder::new()
            .protected(protected)
            .unprotected(unprotected.build())
            .create_ciphertext(plaintext, aad, |plain, enc| {
                let mut buf: Vec<u8> = Vec::with_capacity(plain.len() + 16);
                buf.extend_from_slice(plain);
                self.cipher.encrypt_in_place(&nonce, enc, &mut buf).unwrap();
                buf
            })
            .build();
        Ok(with_tag(
            &ENCRYPT0_TAG,
            e0.to_vec().map_err(anyhow::Error::msg)?.as_slice(),
        ))
    }

    pub fn decrypt(&self, encrypt0_data: &[u8], aad: &[u8]) -> anyhow::Result<Vec<u8>> {
        let e0 = CoseEncrypt0::from_slice(skip_tag(&ENCRYPT0_TAG, encrypt0_data))
            .map_err(anyhow::Error::msg)?;
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
        let encrypt0 = Encrypt0::new(key, None);

        let plaintext = b"hello world";
        let data = encrypt0
            .encrypt(plaintext, b"Name & Service Protocol", None)
            .unwrap();
        // println!("{}", hex_string(&data));
        let res = encrypt0.decrypt(&data, b"Name & Service Protocol").unwrap();
        assert_eq!(res, plaintext);
        assert!(encrypt0
            .decrypt(&data[2..], b"Name & Service Protocol")
            .is_err());
        assert!(encrypt0.decrypt(&data, b"NS").is_err());
    }
}
