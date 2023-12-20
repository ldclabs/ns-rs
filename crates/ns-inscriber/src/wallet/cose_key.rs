use ciborium::Value;
use coset::{
    iana, CborSerializable, CoseKey, CoseKeyBuilder, KeyType, Label, RegisteredLabelWithPrivate,
};
use rand_core::{OsRng, RngCore};

use super::secp256k1::Keypair;

const KEY_PARAM_K: Label = Label::Int(iana::SymmetricKeyParameter::K as i64);
const KEY_PARAM_D: Label = Label::Int(iana::OkpKeyParameter::D as i64);

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Key(pub CoseKey);

impl Key {
    pub fn new_sym(alg: iana::Algorithm, kid: &[u8]) -> anyhow::Result<Self> {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        let mut key = CoseKeyBuilder::new_symmetric_key(key.to_vec()).algorithm(alg);
        if !kid.is_empty() {
            key = key.key_id(kid.to_vec());
        }
        Ok(Self(key.build()))
    }

    pub fn ed25519_from_secret(secret: &[u8; 32], kid: &[u8]) -> anyhow::Result<Self> {
        let mut key = CoseKeyBuilder::new_okp_key()
            .algorithm(iana::Algorithm::EdDSA)
            .param(
                iana::OkpKeyParameter::Crv as i64,
                Value::from(iana::EllipticCurve::Ed25519 as i64),
            )
            .param(
                iana::OkpKeyParameter::D as i64,
                Value::Bytes(secret.to_vec()),
            );

        if !kid.is_empty() {
            key = key.key_id(kid.to_vec());
        }
        Ok(Self(key.build()))
    }

    pub fn secp256k1_from_keypair(keypair: &Keypair, kid: &[u8]) -> anyhow::Result<Self> {
        let mut key = CoseKey {
            kty: KeyType::Assigned(iana::KeyType::EC2),
            alg: Some(RegisteredLabelWithPrivate::Assigned(
                iana::Algorithm::ES256K,
            )),
            params: vec![
                (
                    Label::Int(iana::Ec2KeyParameter::Crv as i64),
                    Value::from(iana::EllipticCurve::Secp256k1 as i64),
                ),
                (
                    Label::Int(iana::Ec2KeyParameter::D as i64),
                    Value::Bytes(keypair.secret_key().as_ref().to_vec()),
                ),
            ],
            ..Default::default()
        };

        if !kid.is_empty() {
            key.key_id.extend_from_slice(kid);
        }
        Ok(Self(key))
    }

    pub fn key_id(&self) -> Vec<u8> {
        self.0.key_id.clone()
    }

    pub fn is_crv(&self, crv: iana::EllipticCurve) -> bool {
        for (label, value) in &self.0.params {
            if label == &Label::Int(iana::Ec2KeyParameter::Crv as i64) {
                if let Some(val) = value.as_integer() {
                    return val == (crv as i64).into();
                }
            }
        }
        false
    }

    pub fn to_vec(self) -> anyhow::Result<Vec<u8>> {
        self.0.to_vec().map_err(anyhow::Error::msg)
    }

    pub fn from_slice(data: &[u8]) -> anyhow::Result<Self> {
        let key = CoseKey::from_slice(data).map_err(anyhow::Error::msg)?;
        Ok(Self(key))
    }

    pub fn secret_key(&self) -> anyhow::Result<[u8; 32]> {
        let key_param = match self.0.kty {
            KeyType::Assigned(iana::KeyType::Symmetric) => &KEY_PARAM_K,
            KeyType::Assigned(iana::KeyType::OKP) => &KEY_PARAM_D,
            KeyType::Assigned(iana::KeyType::EC2) => &Label::Int(iana::Ec2KeyParameter::D as i64),
            _ => {
                return Err(anyhow::Error::msg("unsupport key type"));
            }
        };

        for (label, value) in &self.0.params {
            if label == key_param {
                match value {
                    Value::Bytes(val) => {
                        if val.len() != 32 {
                            return Err(anyhow::Error::msg("invalid key length, expected 32"));
                        }
                        let mut key = [0u8; 32];
                        key.copy_from_slice(val);
                        return Ok(key);
                    }
                    _ => {
                        return Err(anyhow::Error::msg("invalid key type"));
                    }
                }
            }
        }

        Err(anyhow::Error::msg("invalid key"))
    }
}
