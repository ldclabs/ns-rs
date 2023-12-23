use ciborium::{from_reader, into_writer};
use serde::{de, Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::{borrow::BorrowMut, fmt::Debug};

use crate::ns::{Error, Name, PublicKeyParams, Service, ThresholdLevel, Value};

// After the silence period exceeds 365 days, the name is invalid, the application validation signature should be invalid, and the original registrant can activate the name with any update.
pub const NAME_STALE_SECONDS: u64 = 60 * 60 * 24 * 365;
// After the silence period exceeds 365 + 180 days, others are allowed to re-register the name, if no one registers, the original registrant can activate the name with any update
pub const NAME_EXPIRE_SECONDS: u64 = NAME_STALE_SECONDS + 60 * 60 * 24 * 180;

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

    pub fn is_stale(&self, block_time: u64) -> bool {
        self.block_time + NAME_STALE_SECONDS < block_time
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
        if next.payload.operations.len() == 1 && next.payload.operations[0].subcode == 0 {
            // This is the lightweight update operation
            next.verify(&next_state.public_key_params(), ThresholdLevel::Default)?;
            next_state.sequence = next.sequence;
            next_state.block_height = block_height;
            next_state.block_time = block_time;
            next_state.next_public_keys = None;
            return Ok(next_state);
        }

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
                        threshold: next_state.threshold,
                        key_kind: next_state.key_kind,
                        public_keys: next_state.public_keys.clone(),
                        next_public_keys: Some(public_key_params.public_keys),
                    };
                }
                1 => {
                    // update public_keys
                    let allow_update = (next_state.block_time + NAME_EXPIRE_SECONDS < block_time)
                        || (next_state.next_public_keys.is_some()
                            && next_state.next_public_keys.as_ref().unwrap()
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    use crate::{ed25519, ns};

    fn secret_key() -> [u8; 32] {
        let mut data = [0u8; 32];
        OsRng.fill_bytes(&mut data);
        data
    }

    #[test]
    fn name_state_works() {
        let s1 = ed25519::SigningKey::from_bytes(&secret_key());
        let s2 = ed25519::SigningKey::from_bytes(&secret_key());
        let s3 = ed25519::SigningKey::from_bytes(&secret_key());

        let name_state = NameState {
            name: "test".to_string(),
            sequence: 0,
            block_height: 1,
            block_time: 1,
            threshold: 1,
            key_kind: 0,
            public_keys: vec![s1.verifying_key().to_bytes().to_vec()],
            next_public_keys: None,
        };

        let mut next_name = ns::Name {
            name: "test".to_string(),
            sequence: 1,
            payload: ns::Service {
                code: 0,
                operations: vec![ns::Operation {
                    subcode: 1,
                    params: ns::Value::from(&ns::PublicKeyParams {
                        public_keys: vec![
                            s1.verifying_key().to_bytes().to_vec(),
                            s2.verifying_key().to_bytes().to_vec(),
                        ],
                        threshold: None,
                        kind: None,
                    }),
                }],
                approver: None,
            },
            signatures: vec![],
        };
        next_name
            .sign(
                &name_state.public_key_params(),
                ns::ThresholdLevel::Default,
                &[s1.clone()],
            )
            .unwrap();
        next_name.validate().unwrap();

        assert!(
            name_state.verify_the_next(3, 3, &next_name).is_err(),
            "do not allow update"
        );

        let mut next_name = ns::Name {
            name: "test".to_string(),
            sequence: 1,
            payload: ns::Service {
                code: 0,
                operations: vec![ns::Operation {
                    subcode: 2,
                    params: ns::Value::from(&ns::PublicKeyParams {
                        public_keys: vec![
                            s1.verifying_key().to_bytes().to_vec(),
                            s2.verifying_key().to_bytes().to_vec(),
                        ],
                        threshold: None,
                        kind: None,
                    }),
                }],
                approver: None,
            },
            signatures: vec![],
        };
        next_name
            .sign(
                &name_state.public_key_params(),
                ns::ThresholdLevel::Default,
                &[s1.clone()],
            )
            .unwrap();
        next_name.validate().unwrap();

        let name_state = name_state.verify_the_next(3, 3, &next_name).unwrap();
        assert_eq!(1, name_state.sequence);
        assert_eq!(3, name_state.block_height);
        assert_eq!(3, name_state.block_time);
        assert_eq!(1, name_state.threshold);
        assert_eq!(0, name_state.key_kind);
        assert_eq!(
            vec![s1.verifying_key().to_bytes().to_vec()],
            name_state.public_keys
        );
        assert_eq!(
            Some(vec![
                s1.verifying_key().to_bytes().to_vec(),
                s2.verifying_key().to_bytes().to_vec()
            ]),
            name_state.next_public_keys
        );

        let mut next_name = ns::Name {
            name: "test".to_string(),
            sequence: 2,
            payload: ns::Service {
                code: 0,
                operations: vec![ns::Operation {
                    subcode: 1,
                    params: ns::Value::from(&ns::PublicKeyParams {
                        public_keys: vec![
                            s1.verifying_key().to_bytes().to_vec(),
                            s2.verifying_key().to_bytes().to_vec(),
                        ],
                        threshold: None,
                        kind: None,
                    }),
                }],
                approver: None,
            },
            signatures: vec![],
        };
        next_name
            .sign(
                &name_state.public_key_params(),
                ns::ThresholdLevel::Default,
                &[s1.clone()],
            )
            .unwrap();
        next_name.validate().unwrap();

        assert!(
            name_state.verify_the_next(5, 5, &next_name).is_err(),
            "invalid signatures"
        );

        next_name
            .sign(
                &ns::PublicKeyParams {
                    public_keys: vec![
                        s1.verifying_key().to_bytes().to_vec(),
                        s2.verifying_key().to_bytes().to_vec(),
                    ],
                    threshold: None,
                    kind: None,
                },
                ns::ThresholdLevel::All,
                &[s1.clone(), s2.clone()],
            )
            .unwrap();
        next_name.validate().unwrap();

        let name_state = name_state.verify_the_next(5, 5, &next_name).unwrap();
        assert_eq!(2, name_state.sequence);
        assert_eq!(5, name_state.block_height);
        assert_eq!(5, name_state.block_time);
        assert_eq!(2, name_state.threshold);
        assert_eq!(0, name_state.key_kind);
        assert_eq!(
            vec![
                s1.verifying_key().to_bytes().to_vec(),
                s2.verifying_key().to_bytes().to_vec()
            ],
            name_state.public_keys
        );
        assert_eq!(None, name_state.next_public_keys);

        // update public_keys in one call
        let mut next_name = ns::Name {
            name: "test".to_string(),
            sequence: 3,
            payload: ns::Service {
                code: 0,
                operations: vec![
                    ns::Operation {
                        subcode: 2,
                        params: ns::Value::from(&ns::PublicKeyParams {
                            public_keys: vec![s3.verifying_key().to_bytes().to_vec()],
                            threshold: None,
                            kind: None,
                        }),
                    },
                    ns::Operation {
                        subcode: 1,
                        params: ns::Value::from(&ns::PublicKeyParams {
                            public_keys: vec![s3.verifying_key().to_bytes().to_vec()],
                            threshold: None,
                            kind: None,
                        }),
                    },
                ],
                approver: None,
            },
            signatures: vec![],
        };
        next_name
            .sign(
                &name_state.public_key_params(),
                ns::ThresholdLevel::Default,
                &[s1.clone(), s2.clone()],
            )
            .unwrap();

        next_name.validate().unwrap();
        assert!(
            name_state.verify_the_next(7, 7, &next_name).is_err(),
            "invalid signatures"
        );

        next_name.sign_with(&s3).unwrap();
        assert_eq!(3, next_name.signatures.len());
        let name_state = name_state.verify_the_next(7, 7, &next_name).unwrap();
        assert_eq!(3, name_state.sequence);
        assert_eq!(7, name_state.block_height);
        assert_eq!(7, name_state.block_time);
        assert_eq!(1, name_state.threshold);
        assert_eq!(0, name_state.key_kind);
        assert_eq!(
            vec![s3.verifying_key().to_bytes().to_vec()],
            name_state.public_keys
        );
        assert_eq!(None, name_state.next_public_keys);

        // update public_keys after NAME_EXPIRE_SECONDS
        let mut next_name = ns::Name {
            name: "test".to_string(),
            sequence: 4,
            payload: ns::Service {
                code: 0,
                operations: vec![ns::Operation {
                    subcode: 1,
                    params: ns::Value::from(&ns::PublicKeyParams {
                        public_keys: vec![
                            s2.verifying_key().to_bytes().to_vec(),
                            s1.verifying_key().to_bytes().to_vec(),
                        ],
                        threshold: Some(1),
                        kind: None,
                    }),
                }],
                approver: None,
            },
            signatures: vec![],
        };

        next_name.sign_with(&s1).unwrap();
        next_name.sign_with(&s2).unwrap();
        next_name.validate().unwrap();

        let name_state = name_state
            .verify_the_next(8, 8 + NAME_EXPIRE_SECONDS, &next_name)
            .unwrap();
        assert_eq!(4, name_state.sequence);
        assert_eq!(8, name_state.block_height);
        assert_eq!(8 + NAME_EXPIRE_SECONDS, name_state.block_time);
        assert_eq!(1, name_state.threshold);
        assert_eq!(0, name_state.key_kind);
        assert_eq!(
            vec![
                s2.verifying_key().to_bytes().to_vec(),
                s1.verifying_key().to_bytes().to_vec()
            ],
            name_state.public_keys
        );
        assert_eq!(None, name_state.next_public_keys);

        // the lightweight update operation
        let mut next_name = ns::Name {
            name: "test".to_string(),
            sequence: 5,
            payload: ns::Service {
                code: 0,
                operations: vec![ns::Operation {
                    // this operation will be overwritten
                    subcode: 2,
                    params: ns::Value::from(&ns::PublicKeyParams {
                        public_keys: vec![s3.verifying_key().to_bytes().to_vec()],
                        threshold: None,
                        kind: None,
                    }),
                }],
                approver: None,
            },
            signatures: vec![],
        };
        next_name
            .sign(
                &name_state.public_key_params(),
                ns::ThresholdLevel::Strict,
                &[s1.clone(), s2.clone()],
            )
            .unwrap();

        next_name.validate().unwrap();
        let name_state = name_state
            .verify_the_next(name_state.block_height, name_state.block_time, &next_name)
            .unwrap();
        assert!(name_state.next_public_keys.is_some());

        let mut next_name = ns::Name {
            name: "test".to_string(),
            sequence: 6,
            payload: ns::Service {
                code: 0,
                operations: vec![ns::Operation {
                    subcode: 0,
                    params: ns::Value::Null,
                }],
                approver: None,
            },
            signatures: vec![],
        };
        next_name
            .sign(
                &name_state.public_key_params(),
                ns::ThresholdLevel::Default,
                &[s1.clone()],
            )
            .unwrap();

        next_name.validate().unwrap();
        let name_state = name_state
            .verify_the_next(name_state.block_height, name_state.block_time, &next_name)
            .unwrap();
        assert_eq!(6, name_state.sequence);
        assert_eq!(1, name_state.threshold);
        assert_eq!(
            vec![
                s2.verifying_key().to_bytes().to_vec(),
                s1.verifying_key().to_bytes().to_vec()
            ],
            name_state.public_keys
        );
        assert_eq!(None, name_state.next_public_keys);

        // the other update operation
        let mut next_name = ns::Name {
            name: "test".to_string(),
            sequence: 7,
            payload: ns::Service {
                code: 0,
                operations: vec![ns::Operation {
                    // this operation will be overwritten
                    subcode: 2,
                    params: ns::Value::from(&ns::PublicKeyParams {
                        public_keys: vec![s3.verifying_key().to_bytes().to_vec()],
                        threshold: None,
                        kind: None,
                    }),
                }],
                approver: None,
            },
            signatures: vec![],
        };
        next_name
            .sign(
                &name_state.public_key_params(),
                ns::ThresholdLevel::Strict,
                &[s2.clone(), s1.clone()],
            )
            .unwrap();

        next_name.validate().unwrap();
        let name_state = name_state
            .verify_the_next(name_state.block_height, name_state.block_time, &next_name)
            .unwrap();
        assert!(name_state.next_public_keys.is_some());

        let mut next_name = ns::Name {
            name: "test".to_string(),
            sequence: 8,
            payload: ns::Service {
                code: 123,
                operations: vec![ns::Operation {
                    subcode: 0,
                    params: ns::Value::Null,
                }],
                approver: None,
            },
            signatures: vec![],
        };
        next_name
            .sign(
                &name_state.public_key_params(),
                ns::ThresholdLevel::Default,
                &[s1.clone()],
            )
            .unwrap();

        next_name.validate().unwrap();
        let name_state = name_state
            .verify_the_next(name_state.block_height, name_state.block_time, &next_name)
            .unwrap();
        assert_eq!(8, name_state.sequence);
        assert_eq!(1, name_state.threshold);
        assert_eq!(
            vec![
                s2.verifying_key().to_bytes().to_vec(),
                s1.verifying_key().to_bytes().to_vec()
            ],
            name_state.public_keys
        );
        assert_eq!(None, name_state.next_public_keys);
    }

    #[test]
    fn service_state_works() {
        let mut service_state = ServiceState {
            name: "test".to_string(),
            code: 0,
            sequence: 0,
            data: Vec::new(),
        };
        let next_name = ns::Name {
            name: "test".to_string(),
            sequence: 1,
            payload: ns::Service {
                code: 0,
                operations: vec![ns::Operation {
                    subcode: 0,
                    params: ns::Value::Null,
                }],
                approver: None,
            },
            signatures: vec![],
        };

        service_state = service_state.verify_the_next(&next_name).unwrap();
        assert_eq!(1, service_state.sequence);
        assert_eq!(1, service_state.data.len());
        assert_eq!(0, service_state.data[0].0);
        assert_eq!(ns::Value::Null, service_state.data[0].1);

        let next_name = ns::Name {
            name: "test".to_string(),
            sequence: 2,
            payload: ns::Service {
                code: 0,
                operations: vec![ns::Operation {
                    subcode: 0,
                    params: ns::Value::Text("hello".to_string()),
                }],
                approver: None,
            },
            signatures: vec![],
        };

        service_state = service_state.verify_the_next(&next_name).unwrap();
        assert_eq!(2, service_state.sequence);
        assert_eq!(1, service_state.data.len());
        assert_eq!(0, service_state.data[0].0);
        assert_eq!(
            ns::Value::Text("hello".to_string()),
            service_state.data[0].1
        );

        let next_name = ns::Name {
            name: "test".to_string(),
            sequence: 3,
            payload: ns::Service {
                code: 0,
                operations: vec![ns::Operation {
                    subcode: 3,
                    params: ns::Value::Null,
                }],
                approver: None,
            },
            signatures: vec![],
        };

        service_state = service_state.verify_the_next(&next_name).unwrap();
        assert_eq!(3, service_state.sequence);
        assert_eq!(2, service_state.data.len());
        assert_eq!(0, service_state.data[0].0);
        assert_eq!(
            ns::Value::Text("hello".to_string()),
            service_state.data[0].1
        );
        assert_eq!(3, service_state.data[1].0);
        assert_eq!(ns::Value::Null, service_state.data[1].1);

        let next_name = ns::Name {
            name: "test".to_string(),
            sequence: 4,
            payload: ns::Service {
                code: 0,
                operations: vec![ns::Operation {
                    subcode: 2,
                    params: ns::Value::Text("hello2".to_string()),
                }],
                approver: None,
            },
            signatures: vec![],
        };

        service_state = service_state.verify_the_next(&next_name).unwrap();
        assert_eq!(4, service_state.sequence);
        assert_eq!(3, service_state.data.len());
        assert_eq!(0, service_state.data[0].0);
        assert_eq!(
            ns::Value::Text("hello".to_string()),
            service_state.data[0].1
        );
        assert_eq!(2, service_state.data[1].0);
        assert_eq!(
            ns::Value::Text("hello2".to_string()),
            service_state.data[1].1
        );
        assert_eq!(3, service_state.data[2].0);
        assert_eq!(ns::Value::Null, service_state.data[2].1);
    }
}
