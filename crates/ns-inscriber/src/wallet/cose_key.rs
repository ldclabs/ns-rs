use coset::{
    iana, CborSerializable, CoseKey, CoseKeyBuilder, KeyType, Label, RegisteredLabelWithPrivate,
};
use ns_protocol::{
    ns::Value,
    state::{from_bytes, to_bytes},
};
use rand_core::{OsRng, RngCore};

pub trait CoseSigner {
    fn alg(&self) -> iana::Algorithm;
    fn kid(&self) -> Vec<u8>;
    fn sign(&self, data: &[u8]) -> Vec<u8>;
}

pub trait CoseVerifier {
    fn alg(&self) -> iana::Algorithm;
    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<(), anyhow::Error>;
}

pub trait KeyHelper {
    fn to_slice(self) -> anyhow::Result<Vec<u8>>;
    fn kty(&self) -> iana::KeyType;
    fn alg(&self) -> iana::Algorithm;
    fn kid(&self) -> Option<Value>;
    fn set_kid(&mut self, kid: Value) -> anyhow::Result<()>;
    fn is_crv(&self, crv: iana::EllipticCurve) -> bool;
    fn has_param(&self, key_label: &Label) -> bool;
    fn get_param(&self, key_label: &Label) -> anyhow::Result<&Value>;

    fn kid_string(&self) -> String {
        if let Some(kid) = self.kid() {
            match kid {
                Value::Text(s) => return s,
                Value::Bytes(b) => return hex::encode(b),
                Value::Bool(b) => return b.to_string(),
                Value::Integer(i) => return i128::from(i).to_string(),
                v => {
                    return format!("{:?}", v);
                }
            }
        }
        "".to_string()
    }

    fn get_secret(&self) -> anyhow::Result<[u8; 32]> {
        let key_label = match self.kty() {
            iana::KeyType::Symmetric => Label::Int(iana::SymmetricKeyParameter::K as i64),
            iana::KeyType::OKP => Label::Int(iana::OkpKeyParameter::D as i64),
            iana::KeyType::EC2 => Label::Int(iana::Ec2KeyParameter::D as i64),
            _ => {
                return Err(anyhow::Error::msg("unsupport key type"));
            }
        };

        let val = self
            .get_param(&key_label)?
            .as_bytes()
            .filter(|v| v.len() == 32)
            .ok_or_else(|| anyhow::Error::msg("invalid secret key"))?;
        let mut key = [0u8; 32];
        key.copy_from_slice(val);
        Ok(key)
    }
}

impl KeyHelper for CoseKey {
    fn to_slice(self) -> anyhow::Result<Vec<u8>> {
        self.to_vec().map_err(anyhow::Error::msg)
    }

    fn kty(&self) -> iana::KeyType {
        match self.kty {
            KeyType::Assigned(kty) => kty,
            _ => iana::KeyType::Reserved,
        }
    }

    fn alg(&self) -> iana::Algorithm {
        if let Some(RegisteredLabelWithPrivate::Assigned(alg)) = self.alg {
            return alg;
        }

        iana::Algorithm::Reserved
    }

    fn kid(&self) -> Option<Value> {
        if self.key_id.is_empty() {
            return None;
        }

        Some(from_bytes(&self.key_id).unwrap_or_else(|_e| Value::Bytes(self.key_id.clone())))
    }

    fn set_kid(&mut self, kid: Value) -> anyhow::Result<()> {
        self.key_id = to_bytes(&kid)?;
        Ok(())
    }

    fn is_crv(&self, crv: iana::EllipticCurve) -> bool {
        for (label, value) in &self.params {
            // https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
            if label == &Label::Int(-1i64) {
                if let Some(val) = value.as_integer() {
                    return val == (crv as i64).into();
                }
            }
        }
        false
    }

    fn has_param(&self, key_label: &Label) -> bool {
        self.params.iter().any(|(label, _)| label == key_label)
    }

    fn get_param(&self, key_label: &Label) -> anyhow::Result<&Value> {
        for (label, value) in &self.params {
            if label == key_label {
                return Ok(value);
            }
        }
        Err(anyhow::Error::msg(format!("key {:?} not found", key_label)))
    }
}

pub fn new_sym(alg: iana::Algorithm, kid: Option<Value>) -> anyhow::Result<CoseKey> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    let mut key = CoseKeyBuilder::new_symmetric_key(key.to_vec())
        .algorithm(alg)
        .build();
    if let Some(kid) = kid {
        key.set_kid(kid)?;
    }
    Ok(key)
}
