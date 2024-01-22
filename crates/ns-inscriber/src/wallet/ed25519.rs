use bitcoin::bip32::DerivationPath;
use coset::{iana, CborSerializable, CoseKey, CoseKeyBuilder, Label};
use ns_protocol::ns::Value;
use rand_core::{OsRng, RngCore};
use slip10_ed25519::derive_ed25519_private_key;

pub use ed25519_dalek::{SecretKey, Signature, Signer, SigningKey, Verifier, VerifyingKey};

use super::{CoseSigner, CoseVerifier, KeyHelper};

const KEY_PARAM_X: Label = Label::Int(iana::OkpKeyParameter::X as i64);
const KEY_PARAM_D: Label = Label::Int(iana::OkpKeyParameter::D as i64);

pub fn derive_ed25519(seed: &[u8], path: &DerivationPath) -> SigningKey {
    let secret = derive_ed25519_private_key(seed, &path.to_u32_vec());
    SigningKey::from_bytes(&secret)
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Ed25519Key(pub CoseKey);

impl Ed25519Key {
    pub fn new(kid: Option<Value>) -> anyhow::Result<Self> {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Self::from_secret(&secret, kid)
    }

    pub fn from_secret(secret: &[u8; 32], kid: Option<Value>) -> anyhow::Result<Self> {
        let mut key = CoseKeyBuilder::new_okp_key()
            .algorithm(iana::Algorithm::EdDSA)
            .param(
                iana::OkpKeyParameter::Crv as i64,
                Value::from(iana::EllipticCurve::Ed25519 as i64),
            )
            .param(
                iana::OkpKeyParameter::D as i64,
                Value::Bytes(secret.to_vec()),
            )
            .build();

        if let Some(kid) = kid {
            key.set_kid(kid)?;
        }
        Ok(Self(key))
    }

    pub fn from_public(public: &[u8; 32], kid: Option<Value>) -> anyhow::Result<Self> {
        let mut key = CoseKeyBuilder::new_okp_key()
            .algorithm(iana::Algorithm::EdDSA)
            .param(
                iana::OkpKeyParameter::Crv as i64,
                Value::from(iana::EllipticCurve::Ed25519 as i64),
            )
            .param(
                iana::OkpKeyParameter::X as i64,
                Value::Bytes(public.to_vec()),
            )
            .build();

        if let Some(kid) = kid {
            key.set_kid(kid)?;
        }
        Ok(Self(key))
    }

    pub fn from_slice(data: &[u8]) -> anyhow::Result<Self> {
        let key = CoseKey::from_slice(data).map_err(anyhow::Error::msg)?;
        if key.kty() != iana::KeyType::OKP {
            return Err(anyhow::Error::msg("invalid key type"));
        }
        if key.alg() != iana::Algorithm::EdDSA {
            return Err(anyhow::Error::msg("invalid algorithm"));
        }
        if !key.is_crv(iana::EllipticCurve::Ed25519) {
            return Err(anyhow::Error::msg("invalid ed25519 curve"));
        }

        // TODO: more checks
        Ok(Self(key))
    }

    pub fn to_slice(self) -> anyhow::Result<Vec<u8>> {
        self.0.to_slice()
    }

    pub fn public(&self) -> anyhow::Result<Self> {
        let mut key = self.0.clone();
        if !self.0.has_param(&KEY_PARAM_X) {
            if let Some(val) = self
                .0
                .get_param(&KEY_PARAM_D)?
                .as_bytes()
                .filter(|v| v.len() == 32)
            {
                let mut secret: SecretKey = [0u8; 32];
                secret.copy_from_slice(val);
                let public = &SigningKey::from_bytes(&secret).verifying_key();
                key.params
                    .push((KEY_PARAM_X, Value::Bytes(public.to_bytes().to_vec())));
            }
        }

        key.params.retain(|(label, _)| label != &KEY_PARAM_D);
        // TODO: more checks
        Ok(Self(key))
    }

    pub fn get_secret(&self) -> anyhow::Result<SecretKey> {
        let val = self
            .0
            .get_param(&KEY_PARAM_D)?
            .as_bytes()
            .filter(|v| v.len() == 32)
            .ok_or_else(|| anyhow::Error::msg("invalid ed25519 secret key"))?;
        let mut key: SecretKey = [0u8; 32];
        key.copy_from_slice(val);
        Ok(key)
    }

    pub fn get_public(&self) -> anyhow::Result<[u8; 32]> {
        if let Ok(Some(val)) = self
            .0
            .get_param(&KEY_PARAM_X)
            .map(|v| v.as_bytes().filter(|v| v.len() == 32))
        {
            let mut key: [u8; 32] = [0u8; 32];
            key.copy_from_slice(val);
            return Ok(key);
        }

        let secret: SecretKey = self
            .get_secret()
            .map_err(|_e| anyhow::Error::msg("invalid ed25519 public key"))?;
        Ok(SigningKey::from_bytes(&secret).verifying_key().to_bytes())
    }

    pub fn signer(&self) -> anyhow::Result<Ed25519Signer> {
        let key = self.get_secret()?;
        Ok(Ed25519Signer(self.0.key_id.clone(), key))
    }

    pub fn verifier(&self) -> anyhow::Result<Ed25519Verifier> {
        let key = self.get_public()?;
        Ok(Ed25519Verifier(key))
    }
}

pub struct Ed25519Signer(Vec<u8>, SecretKey);

impl CoseSigner for Ed25519Signer {
    fn alg(&self) -> iana::Algorithm {
        iana::Algorithm::EdDSA
    }

    fn kid(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let sk = SigningKey::from_bytes(&self.1);
        sk.sign(data).to_vec()
    }
}

pub struct Ed25519Verifier([u8; 32]);

impl CoseVerifier for Ed25519Verifier {
    fn alg(&self) -> iana::Algorithm {
        iana::Algorithm::EdDSA
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<(), anyhow::Error> {
        let pk = VerifyingKey::from_bytes(&self.0)?;
        let sig = Signature::from_slice(sig)?;
        pk.verify_strict(data, &sig)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_key_works() {
        let msg = b"This is the content.";
        let key = Ed25519Key::new(None).unwrap();
        let signer = key.signer().unwrap();
        let sig = signer.sign(msg);
        let verifier = key.verifier().unwrap();
        assert!(verifier.verify(msg, &sig).is_ok());

        let key2 = Ed25519Key::from_secret(&key.get_secret().unwrap(), None).unwrap();
        assert_eq!(key2.signer().unwrap().sign(msg), sig);
        assert!(key2.verifier().is_ok());

        let key2 = Ed25519Key::from_public(&key.get_public().unwrap(), None).unwrap();
        assert!(key2.verifier().unwrap().verify(msg, &sig).is_ok());
        assert!(key2.signer().is_err());

        let key2 = Ed25519Key::from_slice(&key.to_slice().unwrap()).unwrap();
        assert_eq!(key2.signer().unwrap().sign(msg), sig);
        assert!(key2.verifier().is_ok());

        let key2 = key2.public().unwrap();
        assert!(key2.verifier().unwrap().verify(msg, &sig).is_ok());
        assert!(key2.signer().is_err());
    }
}
