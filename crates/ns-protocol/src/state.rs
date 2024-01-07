use ciborium::{from_reader, into_writer, Value};
use serde::{de, ser, Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::{borrow::BorrowMut, fmt::Debug};

use crate::ns::{
    kind_of_value, Bytes32, Error, IntValue, Name, PublicKeyParams, Service, ThresholdLevel,
};

// After the silence period exceeds 365 days, the name is invalid, the application validation signature should be invalid, and the original registrant can activate the name with any update.
pub const NAME_STALE_SECONDS: u64 = 60 * 60 * 24 * 365;
// After the silence period exceeds 365 + 180 days, others are allowed to re-register the name, if no one registers, the original registrant can activate the name with any update
pub const NAME_EXPIRE_SECONDS: u64 = NAME_STALE_SECONDS + 60 * 60 * 24 * 180;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct NameState {
    pub name: String,
    pub sequence: u64,
    pub block_height: u64,
    pub block_time: u64,
    pub stale_time: u64,
    pub expire_time: u64,
    pub threshold: u8,
    pub key_kind: u8,
    pub public_keys: Vec<Bytes32>,
    pub next_public_keys: Option<Vec<Bytes32>>,
}

impl From<&NameState> for Value {
    fn from(state: &NameState) -> Self {
        let mut arr = vec![
            Value::from(state.name.clone()),
            Value::from(state.sequence),
            Value::from(state.block_height),
            Value::from(state.block_time),
            Value::from(state.stale_time),
            Value::from(state.expire_time),
            Value::from(state.threshold),
            Value::from(state.key_kind),
            Value::Array(state.public_keys.iter().map(Value::from).collect()),
        ];
        if let Some(keys) = state.next_public_keys.as_ref() {
            arr.push(Value::Array(keys.iter().map(Value::from).collect()));
        }
        Value::Array(arr)
    }
}

impl TryFrom<&Value> for NameState {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let arr = value.as_array().ok_or_else(|| {
            Error::Custom(format!(
                "NameState: expected array, got {}",
                kind_of_value(value)
            ))
        })?;
        match arr.len() {
            9 | 10 => {
                let mut state = NameState {
                    name: arr[0]
                        .as_text()
                        .ok_or_else(|| {
                            Error::Custom(format!(
                                "NameState: expected string, got {}",
                                kind_of_value(&arr[0])
                            ))
                        })?
                        .to_string(),
                    sequence: u64::try_from(&IntValue(&arr[1]))?,
                    block_height: u64::try_from(&IntValue(&arr[2]))?,
                    block_time: u64::try_from(&IntValue(&arr[3]))?,
                    stale_time: u64::try_from(&IntValue(&arr[4]))?,
                    expire_time: u64::try_from(&IntValue(&arr[5]))?,
                    threshold: u8::try_from(&IntValue(&arr[6]))?,
                    key_kind: u8::try_from(&IntValue(&arr[7]))?,
                    public_keys: Bytes32::vec_try_from_value(&arr[8])?,
                    ..Default::default()
                };
                if arr.len() == 10 {
                    state.next_public_keys = Some(Bytes32::vec_try_from_value(&arr[9])?);
                }
                Ok(state)
            }
            _ => Err(Error::Custom(format!(
                "NameState: expected array of length 9 or 10, got {}",
                arr.len()
            ))),
        }
    }
}

impl NameState {
    pub fn public_key_params(&self) -> PublicKeyParams {
        PublicKeyParams {
            public_keys: self.public_keys.clone(),
            threshold: Some(self.threshold),
            kind: Some(self.key_kind),
        }
    }

    pub fn hash(&self) -> Result<Bytes32, Error> {
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

        if next.service.code != 0 {
            next.verify(&self.public_key_params(), ThresholdLevel::Default)?;
            return Ok(NameState {
                name: next.name.clone(),
                sequence: next.sequence,
                block_height,
                block_time,
                stale_time: block_time + NAME_STALE_SECONDS,
                expire_time: block_time + NAME_EXPIRE_SECONDS,
                threshold: self.threshold,
                key_kind: self.key_kind,
                public_keys: self.public_keys.clone(),
                next_public_keys: None,
            });
        }

        // handle the `0` service code (Name service)
        let mut next_state = self.clone();
        if next.service.operations.len() == 1 && next.service.operations[0].subcode == 0 {
            // This is the lightweight update operation
            next.verify(&next_state.public_key_params(), ThresholdLevel::Default)?;
            next_state.sequence = next.sequence;
            next_state.block_height = block_height;
            next_state.block_time = block_time;
            next_state.stale_time = block_time + NAME_STALE_SECONDS;
            next_state.expire_time = block_time + NAME_EXPIRE_SECONDS;
            next_state.next_public_keys = None;
            return Ok(next_state);
        }

        for op in &next.service.operations {
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
                        stale_time: block_time + NAME_STALE_SECONDS,
                        expire_time: block_time + NAME_EXPIRE_SECONDS,
                        threshold: next_state.threshold,
                        key_kind: next_state.key_kind,
                        public_keys: next_state.public_keys.clone(),
                        next_public_keys: Some(public_key_params.public_keys),
                    };
                }
                1 => {
                    // update public_keys
                    let allow_update = (next_state.expire_time < block_time)
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
                        stale_time: block_time + NAME_STALE_SECONDS,
                        expire_time: block_time + NAME_EXPIRE_SECONDS,
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

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ServiceState {
    pub name: String,
    pub code: u64,
    pub sequence: u64,
    pub data: Vec<(u16, Value)>,
}

impl From<&ServiceState> for Value {
    fn from(state: &ServiceState) -> Self {
        Value::Array(vec![
            Value::from(state.name.clone()),
            Value::from(state.code),
            Value::from(state.sequence),
            Value::Map(
                state
                    .data
                    .iter()
                    .map(|(subcode, params)| (Value::from(*subcode), params.clone()))
                    .collect(),
            ),
        ])
    }
}

impl TryFrom<&Value> for ServiceState {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let arr = value.as_array().ok_or_else(|| {
            Error::Custom(format!(
                "ServiceState: expected array, got {}",
                kind_of_value(value)
            ))
        })?;
        match arr.len() {
            4 => {
                let state = ServiceState {
                    name: arr[0]
                        .as_text()
                        .ok_or_else(|| {
                            Error::Custom(format!(
                                "ServiceState: expected string, got {}",
                                kind_of_value(&arr[0])
                            ))
                        })?
                        .to_string(),
                    code: u64::try_from(&IntValue(&arr[1]))?,
                    sequence: u64::try_from(&IntValue(&arr[2]))?,
                    data: arr[3]
                        .as_map()
                        .ok_or_else(|| {
                            Error::Custom(format!(
                                "ServiceState: expected map, got {}",
                                kind_of_value(&arr[3])
                            ))
                        })?
                        .iter()
                        .map(|(k, v)| {
                            let subcode = u16::try_from(&IntValue(k))?;
                            Ok((subcode, v.clone()))
                        })
                        .collect::<Result<Vec<(u16, Value)>, Error>>()?,
                };
                Ok(state)
            }
            _ => Err(Error::Custom(format!(
                "ServiceState: expected array of length 4, got {}",
                arr.len()
            ))),
        }
    }
}

impl ServiceState {
    pub fn hash(&self) -> Result<Bytes32, Error> {
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

        if next.service.code != self.code {
            return Err(Error::Custom(format!(
                "invalid service code, expected: {}, got: {}",
                self.code, next.service.code
            )));
        }

        let mut next_state = ServiceState {
            name: next.name.clone(),
            code: next.service.code,
            sequence: next.sequence,
            data: self.data.clone(),
        };
        for op in &next.service.operations {
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

#[derive(Debug, Clone, PartialEq)]
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

impl From<&ServiceProtocol> for Value {
    fn from(state: &ServiceProtocol) -> Self {
        Value::Array(vec![
            Value::from(state.code),
            Value::from(state.version),
            state.protocol.clone(),
            Value::from(state.submitter.clone()),
            Value::from(state.sequence),
        ])
    }
}

impl TryFrom<&Value> for ServiceProtocol {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let arr = value.as_array().ok_or_else(|| {
            Error::Custom(format!(
                "ServiceProtocol: expected array, got {}",
                kind_of_value(value)
            ))
        })?;
        match arr.len() {
            5 => {
                let state = ServiceProtocol {
                    code: u64::try_from(&IntValue(&arr[0]))?,
                    version: u16::try_from(&IntValue(&arr[1]))?,
                    protocol: arr[2].clone(),
                    submitter: arr[3]
                        .as_text()
                        .ok_or_else(|| {
                            Error::Custom(format!(
                                "ServiceProtocol: expected string, got {}",
                                kind_of_value(&arr[0])
                            ))
                        })?
                        .to_string(),
                    sequence: u64::try_from(&IntValue(&arr[4]))?,
                };
                Ok(state)
            }
            _ => Err(Error::Custom(format!(
                "ServiceProtocol: expected array of length 4, got {}",
                arr.len()
            ))),
        }
    }
}

impl ServiceProtocol {
    pub fn hash(&self) -> Result<Bytes32, Error> {
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

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Inscription {
    pub name: String,
    pub sequence: u64,
    pub height: u64,
    pub name_height: u64,
    pub previous_hash: Bytes32,
    pub name_hash: Bytes32,
    pub service_hash: Bytes32,
    pub protocol_hash: Option<Bytes32>,
    pub block_height: u64,
    pub block_hash: Bytes32,
    pub txid: Bytes32,
    pub vin: u8,
    pub data: Name,
}

impl From<&Inscription> for Value {
    fn from(state: &Inscription) -> Self {
        let mut arr = vec![
            Value::from(state.name.clone()),
            Value::from(state.sequence),
            Value::from(state.height),
            Value::Array(vec![
                Value::from(state.name_height),
                Value::from(&state.previous_hash),
                Value::from(&state.name_hash),
                Value::from(&state.service_hash),
            ]),
            Value::Array(vec![
                Value::from(state.block_height),
                Value::from(&state.block_hash),
                Value::from(&state.txid),
                Value::from(state.vin),
            ]),
            Value::from(&state.data),
        ];
        if let Some(ref hash) = state.protocol_hash {
            arr[3].as_array_mut().unwrap().push(Value::from(hash));
        }
        Value::Array(arr)
    }
}

impl TryFrom<&Value> for Inscription {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let arr = value.as_array().ok_or_else(|| {
            Error::Custom(format!(
                "Inscription: expected array, got {}",
                kind_of_value(value)
            ))
        })?;
        match arr.len() {
            6 => {
                let ins_state = arr[3].as_array().ok_or_else(|| {
                    Error::Custom(format!(
                        "Inscription: expected array at 3, got {}",
                        kind_of_value(&arr[3])
                    ))
                })?;
                if ins_state.len() != 4 && ins_state.len() != 5 {
                    return Err(Error::Custom(format!(
                        "Inscription: expected array of length 4 or 5 at 3, got {}",
                        ins_state.len()
                    )));
                }
                let tx_state = arr[4].as_array().ok_or_else(|| {
                    Error::Custom(format!(
                        "Inscription: expected array at 4, got {}",
                        kind_of_value(&arr[3])
                    ))
                })?;
                if tx_state.len() != 4 {
                    return Err(Error::Custom(format!(
                        "Inscription: expected array of length 4 at 4, got {}",
                        tx_state.len()
                    )));
                }

                let mut ins = Inscription {
                    name: arr[0]
                        .as_text()
                        .ok_or_else(|| {
                            Error::Custom(format!(
                                "Inscription: expected string, got {}",
                                kind_of_value(&arr[0])
                            ))
                        })?
                        .to_string(),
                    sequence: u64::try_from(&IntValue(&arr[1]))?,
                    height: u64::try_from(&IntValue(&arr[2]))?,
                    name_height: u64::try_from(&IntValue(&ins_state[0]))?,
                    previous_hash: Bytes32::try_from(&ins_state[1])?,
                    name_hash: Bytes32::try_from(&ins_state[2])?,
                    service_hash: Bytes32::try_from(&ins_state[3])?,
                    protocol_hash: None,
                    block_height: u64::try_from(&IntValue(&tx_state[0]))?,
                    block_hash: Bytes32::try_from(&tx_state[1])?,
                    txid: Bytes32::try_from(&tx_state[2])?,
                    vin: u8::try_from(&IntValue(&tx_state[3]))?,
                    data: Name::try_from(&arr[5])?,
                };
                if ins_state.len() == 5 {
                    ins.protocol_hash = Some(Bytes32::try_from(&ins_state[4])?);
                }

                Ok(ins)
            }
            _ => Err(Error::Custom(format!(
                "Inscription: expected array of length 4, got {}",
                arr.len()
            ))),
        }
    }
}

impl Inscription {
    pub fn hash(&self) -> Result<Bytes32, Error> {
        hash_sha3(self)
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
pub struct InvalidInscription {
    pub name: String,
    pub block_height: u64,
    pub hash: Bytes32,
    pub reason: String,
    pub data: Name,
}

impl InvalidInscription {}

impl Serialize for NameState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        Value::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NameState {
    fn deserialize<D>(deserializer: D) -> Result<NameState, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let val = Value::deserialize(deserializer)?;
        NameState::try_from(&val).map_err(de::Error::custom)
    }
}

impl Serialize for ServiceState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        Value::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ServiceState {
    fn deserialize<D>(deserializer: D) -> Result<ServiceState, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let val = Value::deserialize(deserializer)?;
        ServiceState::try_from(&val).map_err(de::Error::custom)
    }
}

impl Serialize for ServiceProtocol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        Value::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ServiceProtocol {
    fn deserialize<D>(deserializer: D) -> Result<ServiceProtocol, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let val = Value::deserialize(deserializer)?;
        ServiceProtocol::try_from(&val).map_err(de::Error::custom)
    }
}

impl Serialize for Inscription {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        Value::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Inscription {
    fn deserialize<D>(deserializer: D) -> Result<Inscription, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let val = Value::deserialize(deserializer)?;
        Inscription::try_from(&val).map_err(de::Error::custom)
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

pub fn hash_sha3<T: Serialize>(value: &T) -> Result<Bytes32, Error> {
    let mut hasher = Sha3_256::new();
    into_writer(value, hasher.borrow_mut())
        .map_err(|err| Error::Custom(format!("hash_sha3: {:?}", err)))?;
    Bytes32::try_from(hasher.finalize().as_slice())
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
            public_keys: vec![s1.verifying_key().to_bytes().into()],
            ..Default::default()
        };

        let mut next_name = ns::Name {
            name: "test".to_string(),
            sequence: 1,
            service: ns::Service {
                code: 0,
                operations: vec![ns::Operation {
                    subcode: 1,
                    params: ns::Value::from(&ns::PublicKeyParams {
                        public_keys: vec![
                            s1.verifying_key().to_bytes().into(),
                            s2.verifying_key().to_bytes().into(),
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
            service: ns::Service {
                code: 0,
                operations: vec![ns::Operation {
                    subcode: 2,
                    params: ns::Value::from(&ns::PublicKeyParams {
                        public_keys: vec![
                            s1.verifying_key().to_bytes().into(),
                            s2.verifying_key().to_bytes().into(),
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
        assert_eq!(3 + NAME_STALE_SECONDS, name_state.stale_time);
        assert_eq!(3 + NAME_EXPIRE_SECONDS, name_state.expire_time);
        assert_eq!(1, name_state.threshold);
        assert_eq!(0, name_state.key_kind);
        assert_eq!(
            vec![Bytes32::from(s1.verifying_key().to_bytes())],
            name_state.public_keys
        );
        assert_eq!(
            Some(vec![
                s1.verifying_key().to_bytes().into(),
                s2.verifying_key().to_bytes().into()
            ]),
            name_state.next_public_keys
        );

        let mut next_name = ns::Name {
            name: "test".to_string(),
            sequence: 2,
            service: ns::Service {
                code: 0,
                operations: vec![ns::Operation {
                    subcode: 1,
                    params: ns::Value::from(&ns::PublicKeyParams {
                        public_keys: vec![
                            s1.verifying_key().to_bytes().into(),
                            s2.verifying_key().to_bytes().into(),
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
                        s1.verifying_key().to_bytes().into(),
                        s2.verifying_key().to_bytes().into(),
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
        assert_eq!(5 + NAME_STALE_SECONDS, name_state.stale_time);
        assert_eq!(5 + NAME_EXPIRE_SECONDS, name_state.expire_time);
        assert_eq!(2, name_state.threshold);
        assert_eq!(0, name_state.key_kind);
        assert_eq!(
            vec![
                Bytes32::from(s1.verifying_key().to_bytes()),
                Bytes32::from(s2.verifying_key().to_bytes()),
            ],
            name_state.public_keys
        );
        assert_eq!(None, name_state.next_public_keys);

        // update public_keys in one call
        let mut next_name = ns::Name {
            name: "test".to_string(),
            sequence: 3,
            service: ns::Service {
                code: 0,
                operations: vec![
                    ns::Operation {
                        subcode: 2,
                        params: ns::Value::from(&ns::PublicKeyParams {
                            public_keys: vec![s3.verifying_key().to_bytes().into()],
                            threshold: None,
                            kind: None,
                        }),
                    },
                    ns::Operation {
                        subcode: 1,
                        params: ns::Value::from(&ns::PublicKeyParams {
                            public_keys: vec![s3.verifying_key().to_bytes().into()],
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
        assert_eq!(7 + NAME_STALE_SECONDS, name_state.stale_time);
        assert_eq!(7 + NAME_EXPIRE_SECONDS, name_state.expire_time);
        assert_eq!(1, name_state.threshold);
        assert_eq!(0, name_state.key_kind);
        assert_eq!(
            vec![Bytes32::from(s3.verifying_key().to_bytes())],
            name_state.public_keys
        );
        assert_eq!(None, name_state.next_public_keys);

        // update public_keys after NAME_EXPIRE_SECONDS
        let mut next_name = ns::Name {
            name: "test".to_string(),
            sequence: 4,
            service: ns::Service {
                code: 0,
                operations: vec![ns::Operation {
                    subcode: 1,
                    params: ns::Value::from(&ns::PublicKeyParams {
                        public_keys: vec![
                            s2.verifying_key().to_bytes().into(),
                            s1.verifying_key().to_bytes().into(),
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

        let block_time = name_state.expire_time + 1;
        let name_state = name_state
            .verify_the_next(8, block_time, &next_name)
            .unwrap();
        assert_eq!(4, name_state.sequence);
        assert_eq!(8, name_state.block_height);
        assert_eq!(block_time, name_state.block_time);
        assert_eq!(block_time + NAME_STALE_SECONDS, name_state.stale_time);
        assert_eq!(block_time + NAME_EXPIRE_SECONDS, name_state.expire_time);
        assert_eq!(1, name_state.threshold);
        assert_eq!(0, name_state.key_kind);
        assert_eq!(
            vec![
                Bytes32::from(s2.verifying_key().to_bytes()),
                Bytes32::from(s1.verifying_key().to_bytes())
            ],
            name_state.public_keys
        );
        assert_eq!(None, name_state.next_public_keys);

        // the lightweight update operation
        let mut next_name = ns::Name {
            name: "test".to_string(),
            sequence: 5,
            service: ns::Service {
                code: 0,
                operations: vec![ns::Operation {
                    // this operation will be overwritten
                    subcode: 2,
                    params: ns::Value::from(&ns::PublicKeyParams {
                        public_keys: vec![s3.verifying_key().to_bytes().into()],
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
            service: ns::Service {
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
                Bytes32::from(s2.verifying_key().to_bytes()),
                Bytes32::from(s1.verifying_key().to_bytes())
            ],
            name_state.public_keys
        );
        assert_eq!(None, name_state.next_public_keys);

        // the other update operation
        let mut next_name = ns::Name {
            name: "test".to_string(),
            sequence: 7,
            service: ns::Service {
                code: 0,
                operations: vec![ns::Operation {
                    // this operation will be overwritten
                    subcode: 2,
                    params: ns::Value::from(&ns::PublicKeyParams {
                        public_keys: vec![s3.verifying_key().to_bytes().into()],
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
            service: ns::Service {
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
                Bytes32::from(s2.verifying_key().to_bytes()),
                Bytes32::from(s1.verifying_key().to_bytes())
            ],
            name_state.public_keys
        );
        assert_eq!(None, name_state.next_public_keys);

        let mut data: Vec<u8> = Vec::new();
        into_writer(&name_state, &mut data).unwrap();
        println!("name_state: {:?}", hex::encode(&data));
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
            service: ns::Service {
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
            service: ns::Service {
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
            service: ns::Service {
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
            service: ns::Service {
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
