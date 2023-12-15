use ciborium::{from_reader, into_writer};
use serde::{de, Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::{borrow::BorrowMut, fmt::Debug};

use crate::ns::{Error, Name, PublicKeyParams, Service, ThresholdLevel, Value};

// After the silence period exceeds 365 days, the name is invalid, the application validation signature should be invalid, and the original registrant can activate the name with any update.
pub const NAME_SILENT_SECONDS: u64 = 60 * 60 * 24 * 365;
// After the silence period exceeds 365 + 180 days, others are allowed to re-register the name, if no one registers, the original registrant can activate the name with any update
pub const NAME_EXPIRE_SECONDS: u64 = NAME_SILENT_SECONDS + 60 * 60 * 24 * 180;

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
pub struct NameState {
    pub name: String,
    pub sequence: u64,
    pub block_height: u64,
    pub block_time: u64,
    pub threshold: u8,
    pub key_kind: u8,
    pub public_keys: Vec<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_public_keys: Option<Vec<Vec<u8>>>,
}

impl NameState {
    pub fn public_key_params(&self) -> PublicKeyParams {
        PublicKeyParams {
            public_keys: self.public_keys.clone(),
            threshold: Some(self.threshold),
            kind: Some(self.key_kind),
        }
    }

    pub fn hash(&self) -> Result<Vec<u8>, Error> {
        hash_sha3(self)
    }

    pub fn verify_the_next(
        &self,
        block_height: u64,
        block_time: u64,
        next: &Name,
    ) -> Result<NameState, Error> {
        // next name must be validated by Name::validate.
        if self.name != next.name {
            return Err(Error::Custom("name mismatch".to_string()));
        }
        if self.sequence + 1 != next.sequence {
            return Err(Error::Custom(format!(
                "invalid sequence, expected: {}, got: {}",
                self.sequence + 1,
                next.sequence
            )));
        }

        if next.payload.code != 0 {
            next.verify(&self.public_key_params(), ThresholdLevel::Default)?;
            return Ok(NameState {
                name: next.name.clone(),
                sequence: next.sequence,
                block_height,
                block_time,
                threshold: self.threshold,
                key_kind: self.key_kind,
                public_keys: self.public_keys.clone(),
                next_public_keys: None,
            });
        }

        // handle the `0` service code (Name service)
        let mut next_state = self.clone();
        for op in &next.payload.operations {
            let public_key_params = PublicKeyParams::try_from(&op.params)?;
            public_key_params.validate()?;
            match op.subcode {
                2 => {
                    // allows updates to next public_keys
                    next.verify(&next_state.public_key_params(), ThresholdLevel::Strict)?;
                    next_state = NameState {
                        name: next.name.clone(),
                        sequence: next.sequence,
                        block_height,
                        block_time,
                        threshold: self.threshold,
                        key_kind: self.key_kind,
                        public_keys: self.public_keys.clone(),
                        next_public_keys: Some(public_key_params.public_keys),
                    };
                }
                1 => {
                    // update public_keys
                    let allow_update = (self.block_time + NAME_EXPIRE_SECONDS < block_time)
                        || (self.next_public_keys.is_some()
                            && self.next_public_keys.as_ref().unwrap()
                                == &public_key_params.public_keys);

                    if !allow_update {
                        return Err(Error::Custom(
                            "public_keys mismatch, or name is not expired".to_string(),
                        ));
                    }

                    next_state = NameState {
                        name: next.name.clone(),
                        sequence: next.sequence,
                        block_height,
                        block_time,
                        threshold: public_key_params
                            .threshold
                            .unwrap_or(public_key_params.public_keys.len() as u8),
                        key_kind: public_key_params.kind.unwrap_or(0),
                        public_keys: public_key_params.public_keys,
                        next_public_keys: None,
                    };
                    next.verify(&next_state.public_key_params(), ThresholdLevel::All)?;
                }
                v => return Err(Error::Custom(format!("invalid operation subcode: {}", v))),
            }
        }

        Ok(next_state)
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
pub struct ServiceState {
    pub name: String,
    pub code: u64,
    pub sequence: u64,
    pub data: Vec<(u16, Value)>,
}

impl ServiceState {
    pub fn hash(&self) -> Result<Vec<u8>, Error> {
        hash_sha3(self)
    }

    pub fn verify_the_next(&self, next: &Name) -> Result<ServiceState, Error> {
        // next name must be validated by Name::validate.
        if self.name != next.name {
            return Err(Error::Custom("name mismatch".to_string()));
        }
        if self.sequence + 1 != next.sequence {
            return Err(Error::Custom(format!(
                "invalid sequence, expected: {}, got: {}",
                self.sequence + 1,
                next.sequence
            )));
        }

        if next.payload.code != self.code {
            return Err(Error::Custom(format!(
                "invalid service code, expected: {}, got: {}",
                self.code, next.payload.code
            )));
        }

        let mut next_state = ServiceState {
            name: next.name.clone(),
            code: next.payload.code,
            sequence: next.sequence,
            data: self.data.clone(),
        };
        for op in &next.payload.operations {
            if let Some(i) = next_state.data.iter().position(|v| v.0 == op.subcode) {
                // default to replace operation
                // we should support other operations in the future
                next_state.data[i].1 = op.params.clone();
            } else {
                next_state.data.push((op.subcode, op.params.clone()));
            }
        }
        next_state
            .data
            .sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

        Ok(next_state)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ServiceProtocol {
    pub code: u64,
    pub version: u16,
    pub protocol: Value,
    pub submitter: String,
    pub sequence: u64,
}

impl Default for ServiceProtocol {
    fn default() -> Self {
        Self {
            code: 0,
            version: 0,
            protocol: Value::Null,
            submitter: "".to_string(),
            sequence: 0,
        }
    }
}

impl ServiceProtocol {
    pub fn hash(&self) -> Result<Vec<u8>, Error> {
        hash_sha3(self)
    }

    pub fn validate(&self, service: &Service) -> Result<(), Error> {
        if self.code != service.code {
            return Err(Error::Custom(format!(
                "invalid service code, expected: {}, got: {}",
                self.code, service.code
            )));
        }

        // ToDO: protocol should be parsed as a CBOR Schema
        match self.code {
            0 => {
                // Native Name service, will be handled in NameState::verify_the_next
                Ok(())
            }
            v => Err(Error::Custom(format!("invalid service code: {}", v))),
        }
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
pub struct Inscription {
    pub name: String,
    pub sequence: u64,
    pub height: u64,
    pub previous_hash: Vec<u8>,
    pub name_hash: Vec<u8>,
    pub service_hash: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_hash: Option<Vec<u8>>,
    pub block_hash: Vec<u8>,
    pub block_height: u64,
    pub txid: Vec<u8>,
    pub vin: u8,
    pub data: Name,
}

impl Inscription {
    pub fn hash(&self) -> Result<Vec<u8>, Error> {
        hash_sha3(self)
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
pub struct InvalidInscription {
    pub name: String,
    pub block_height: u64,
    pub hash: Vec<u8>,
    pub reason: String,
    pub data: Name,
}

impl InvalidInscription {
    pub fn hash(&self) -> Result<Vec<u8>, Error> {
        hash_sha3(self)
    }
}

pub fn from_bytes<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: de::DeserializeOwned,
{
    let value = from_reader(bytes).map_err(|err| Error::Custom(err.to_string()))?;
    Ok(value)
}

pub fn to_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut buf: Vec<u8> = Vec::new();
    into_writer(value, &mut buf).map_err(|err| Error::Custom(err.to_string()))?;
    Ok(buf)
}

pub fn hash_sha3<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut hasher = Sha3_256::new();
    into_writer(value, hasher.borrow_mut())
        .map_err(|err| Error::Custom(format!("hash_sha3: {:?}", err)))?;
    Ok(hasher.finalize().to_vec())
}
