use ciborium_io::{Read, Write};
use finl_unicode::categories::CharacterCategories;
use serde::{de, ser, Deserialize, Serialize};
use std::{convert::From, fmt::Debug};

pub use ciborium::{
    from_reader, into_writer, tag,
    value::{Error, Value},
};

use crate::ed25519::{self, Signer};

pub type NSTag = tag::Required<Name, 53>;
pub type NSTagRef<'a> = tag::Required<&'a Name, 53>;
pub const MAX_NAME_BYTES: usize = 520;
pub(crate) const NS_PREFIX: [u8; 3] = [0xd8, 0x35, 0x84]; // d835: tag(53), 84: array(4)

#[derive(Clone, PartialEq, Debug, Default)]
pub struct Name {
    pub name: String,
    pub sequence: u64,
    pub service: Service,
    pub signatures: Vec<Bytes64>,
}

#[derive(Clone, PartialEq, Debug, Default)]
pub struct Service {
    pub code: u64,
    pub operations: Vec<Operation>,
    pub attesters: Option<Vec<String>>, // attester's name
}

#[derive(Clone, PartialEq, Debug)]
pub struct Operation {
    pub subcode: u16,
    pub params: Value,
}

impl core::default::Default for Operation {
    fn default() -> Self {
        Operation {
            subcode: 0,
            params: Value::Array(vec![]),
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct IntValue<'a>(pub &'a Value);
impl<'a> IntValue<'a> {
    fn to_int(&self) -> Result<ciborium::value::Integer, Error> {
        self.0.as_integer().ok_or_else(|| {
            Error::Custom(format!(
                "IntValue: expected integer, got {}",
                kind_of_value(self.0)
            ))
        })
    }
}

impl TryFrom<&IntValue<'_>> for u64 {
    type Error = Error;

    fn try_from(value: &IntValue) -> Result<Self, Self::Error> {
        u64::try_from(value.to_int()?)
            .map_err(|err| Error::Custom(format!("IntValue: expected u64, error: {:?}", err)))
    }
}

impl TryFrom<&IntValue<'_>> for u32 {
    type Error = Error;

    fn try_from(value: &IntValue) -> Result<Self, Self::Error> {
        u32::try_from(value.to_int()?)
            .map_err(|err| Error::Custom(format!("IntValue: expected u64, error: {:?}", err)))
    }
}

impl TryFrom<&IntValue<'_>> for u16 {
    type Error = Error;

    fn try_from(value: &IntValue) -> Result<Self, Self::Error> {
        u16::try_from(value.to_int()?)
            .map_err(|err| Error::Custom(format!("IntValue: expected u64, error: {:?}", err)))
    }
}

impl TryFrom<&IntValue<'_>> for u8 {
    type Error = Error;

    fn try_from(value: &IntValue) -> Result<Self, Self::Error> {
        u8::try_from(value.to_int()?)
            .map_err(|err| Error::Custom(format!("IntValue: expected u64, error: {:?}", err)))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash, Default)]
pub struct Bytes32(pub [u8; 32]);

impl From<[u8; 32]> for Bytes32 {
    fn from(value: [u8; 32]) -> Self {
        Bytes32(value)
    }
}

impl From<&[u8; 32]> for Bytes32 {
    fn from(value: &[u8; 32]) -> Self {
        Bytes32(value.to_owned())
    }
}

impl From<&Bytes32> for Vec<u8> {
    fn from(value: &Bytes32) -> Self {
        value.to_vec()
    }
}

impl From<Bytes32> for Vec<u8> {
    fn from(value: Bytes32) -> Self {
        value.to_vec()
    }
}

impl TryFrom<&[u8]> for Bytes32 {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 32 {
            Err(Error::Custom(format!(
                "Bytes32: expected value length is 32, got {:?}",
                value.len()
            )))
        } else {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(value);
            Ok(Bytes32(bytes))
        }
    }
}

impl TryFrom<&Vec<u8>> for Bytes32 {
    type Error = Error;
    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Bytes32::try_from(value.as_slice())
    }
}

impl TryFrom<Vec<u8>> for Bytes32 {
    type Error = Error;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Bytes32::try_from(value.as_slice())
    }
}

impl Bytes32 {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn vec_into(values: &[Self]) -> Vec<Vec<u8>> {
        values.iter().map(|v| v.to_vec()).collect()
    }

    pub fn vec_try_from(values: &[Vec<u8>]) -> Result<Vec<Self>, Error> {
        values.iter().map(Bytes32::try_from).collect()
    }

    pub fn vec_try_from_value(value: &Value) -> Result<Vec<Self>, Error> {
        value
            .as_array()
            .ok_or_else(|| {
                Error::Custom(format!(
                    "Bytes32: expected array, got {}",
                    kind_of_value(value)
                ))
            })?
            .iter()
            .map(Bytes32::try_from)
            .collect::<Result<Vec<Bytes32>, Error>>()
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct Bytes64(pub [u8; 64]);

impl core::default::Default for Bytes64 {
    fn default() -> Self {
        Bytes64([0u8; 64])
    }
}

impl From<[u8; 64]> for Bytes64 {
    fn from(value: [u8; 64]) -> Self {
        Bytes64(value)
    }
}

impl From<&[u8; 64]> for Bytes64 {
    fn from(value: &[u8; 64]) -> Self {
        Bytes64(value.to_owned())
    }
}

impl From<&Bytes64> for Vec<u8> {
    fn from(value: &Bytes64) -> Self {
        value.to_vec()
    }
}

impl From<Bytes64> for Vec<u8> {
    fn from(value: Bytes64) -> Self {
        value.to_vec()
    }
}

impl TryFrom<&[u8]> for Bytes64 {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 64 {
            Err(Error::Custom(format!(
                "Bytes64: expected value length is 64, got {:?}",
                value.len()
            )))
        } else {
            let mut bytes = [0u8; 64];
            bytes.copy_from_slice(value);
            Ok(Bytes64(bytes))
        }
    }
}

impl TryFrom<&Vec<u8>> for Bytes64 {
    type Error = Error;
    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Bytes64::try_from(value.as_slice())
    }
}

impl Bytes64 {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn vec_into(values: &[Self]) -> Vec<Vec<u8>> {
        values.iter().map(|v| v.to_vec()).collect()
    }

    pub fn vec_try_from(values: &[Vec<u8>]) -> Result<Vec<Self>, Error> {
        values.iter().map(Bytes64::try_from).collect()
    }

    pub fn vec_try_from_value(value: &Value) -> Result<Vec<Self>, Error> {
        value
            .as_array()
            .ok_or_else(|| {
                Error::Custom(format!(
                    "Bytes64: expected array, got {}",
                    kind_of_value(value)
                ))
            })?
            .iter()
            .map(Bytes64::try_from)
            .collect::<Result<Vec<Bytes64>, Error>>()
    }
}

// PublicKeyParams is Ed25519 Multisignatures with threshold,
// every public key can be FROST (Flexible Round-Optimised Schnorr Threshold signatures)
// see: https://github.com/ZcashFoundation/frost
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct PublicKeyParams {
    pub public_keys: Vec<Bytes32>,
    pub threshold: Option<u8>, // default to public_keys.len()
    pub kind: Option<u8>,      // default to 0: ed25519
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum ThresholdLevel {
    Single,
    #[default]
    Default, // DefaultLevel = threshold, 1 <= DefaultLevel <= public_keys.len()
    Strict, // StrictLevel = threshold + 1, 1 <= StrictLevel <= public_keys.len()
    All,    // AllLevel = public_keys.len()
}

impl PublicKeyParams {
    pub fn validate(&self) -> Result<(), Error> {
        if self.public_keys.is_empty() {
            return Err(Error::Custom(
                "PublicKeyParams: expected at least one public key".to_string(),
            ));
        }

        if let Some(threshold) = self.threshold {
            if threshold == 0 {
                return Err(Error::Custom(
                    "PublicKeyParams: threshold must be greater than 0".to_string(),
                ));
            }
            if threshold > self.public_keys.len() as u8 {
                return Err(Error::Custom(format!(
                    "PublicKeyParams: threshold {} is greater than number of public keys {}",
                    threshold,
                    self.public_keys.len()
                )));
            }
        }
        if let Some(kind) = self.kind {
            if kind != 0 {
                return Err(Error::Custom(format!(
                    "PublicKeyParams: unsupported public key kind {}",
                    kind
                )));
            }
        }
        let mut public_keys = self.public_keys.clone();
        public_keys.dedup();
        if public_keys.len() != self.public_keys.len() {
            return Err(Error::Custom(
                "PublicKeyParams: duplicate public_keys".to_string(),
            ));
        }

        Ok(())
    }

    pub fn verifying_threshold(&self, level: ThresholdLevel) -> u8 {
        match level {
            ThresholdLevel::Single => 1,
            ThresholdLevel::Default => self.threshold.unwrap_or(self.public_keys.len() as u8),
            ThresholdLevel::Strict => {
                let full = self.public_keys.len() as u8;
                let l = self.threshold.map(|v| v + 1).unwrap_or(full);
                if l > full {
                    full
                } else {
                    l
                }
            }
            ThresholdLevel::All => self.public_keys.len() as u8,
        }
    }
}

// name should be valid utf-8 string, not empty, not longer than 64 bytes, and not contain any of the following characters: uppercase letters, punctuations, separators, marks, symbols, and other control characters, format characters, surrogates, unassigned characters and private use characters.
// https://docs.rs/finl_unicode/latest/finl_unicode/categories/trait.CharacterCategories.html
pub fn valid_name(name: &str) -> bool {
    let mut size = 0;
    // let cs = Graphemes::new(name);
    for c in name.chars() {
        size += 1;
        if size > 64 {
            return false;
        }
        if c.is_letter_uppercase()
            || c.is_punctuation()
            || c.is_separator()
            || c.is_mark()
            || c.is_symbol()
            || c.is_other()
        {
            return false;
        }
    }

    !name.is_empty()
}

impl Name {
    pub fn decode_from<R: Read>(r: R) -> Result<Self, Error>
    where
        R::Error: core::fmt::Debug,
    {
        let value: NSTag = from_reader(r)
            .map_err(|err| Error::Custom(format!("Name: decode_from error, {:?}", err)))?;
        Ok(value.0)
    }

    pub fn encode_to<W: Write>(&self, w: W) -> Result<(), Error>
    where
        W::Error: core::fmt::Debug,
    {
        let v: NSTagRef = tag::Required(self);
        into_writer(&v, w)
            .map_err(|err| Error::Custom(format!("Name: encode_to error, {:?}", err)))?;
        Ok(())
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        if !buf.starts_with(&NS_PREFIX) {
            return Err(Error::Custom("Name: invalid bytes".to_string()));
        }

        let name = Self::decode_from(buf)?;
        let data = name.to_bytes()?;
        if !buf.eq(&data) {
            return Err(Error::Custom(
                "Name: data not consumed entirely".to_string(),
            ));
        }
        Ok(name)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = Vec::new();
        self.encode_to(&mut buf)?;
        Ok(buf)
    }

    pub fn to_sign_bytes(&self) -> Result<Vec<u8>, Error> {
        let arr = Value::Array(vec![
            Value::from(self.name.clone()),
            Value::from(self.sequence),
            Value::from(&self.service),
        ]);
        let mut buf: Vec<u8> = Vec::new();
        into_writer(&arr, &mut buf).map_err(|err| Error::Custom(err.to_string()))?;
        Ok(buf)
    }
}

impl Name {
    // validate the name is well-formed
    pub fn validate(&self) -> Result<(), Error> {
        if !valid_name(&self.name) {
            return Err(Error::Custom(format!("Name: invalid name {}", self.name)));
        }

        if self.sequence > i64::MAX as u64 {
            return Err(Error::Custom(format!(
                "Name: invalid sequence {}, expected less than {}",
                self.sequence,
                i64::MAX
            )));
        }

        if self.service.code > i64::MAX as u64 {
            return Err(Error::Custom(format!(
                "Name: invalid service code {}, expected less than {}",
                self.service.code,
                i64::MAX
            )));
        }

        if let Some(attesters) = &self.service.attesters {
            if attesters.is_empty() {
                return Err(Error::Custom("Name: empty attesters".to_string()));
            }
            for attester in attesters {
                if !valid_name(attester) {
                    return Err(Error::Custom(format!(
                        "Name: invalid attester {}",
                        attester
                    )));
                }
            }
        }

        if self.service.operations.is_empty() {
            return Err(Error::Custom("Name: missing operations".to_string()));
        }

        if self.signatures.is_empty() {
            return Err(Error::Custom("Name: missing signatures".to_string()));
        }

        let mut signatures = self.signatures.clone();
        signatures.dedup();
        if signatures.len() != self.signatures.len() {
            return Err(Error::Custom("Name: duplicate signatures".to_string()));
        }
        Ok(())
    }

    // verify the data is signed by the public keys with the given threshold level
    pub fn verify(&self, params: &PublicKeyParams, level: ThresholdLevel) -> Result<(), Error> {
        let threshold = params.verifying_threshold(level);
        if threshold == 0 {
            return Err(Error::Custom(
                "Name: threshold must be greater than 0".to_string(),
            ));
        }

        let data = self.to_sign_bytes()?;
        let mut keys: Vec<ed25519::VerifyingKey> = Vec::with_capacity(params.public_keys.len());
        for pk in &params.public_keys {
            let key = ed25519::VerifyingKey::from_bytes(&pk.0)
                .map_err(|err| Error::Custom(err.to_string()))?;
            keys.push(key);
        }

        let mut count = 0;
        for sig in self.signatures.iter() {
            let sig = ed25519::Signature::from_bytes(&sig.0);
            for key in keys.iter() {
                if key.verify_strict(&data, &sig).is_ok() {
                    count += 1;
                    if count >= threshold {
                        return Ok(());
                    }

                    break;
                }
            }
        }

        Err(Error::Custom(format!(
            "Name: verify failed, expected {} signatures, got {}",
            threshold, count
        )))
    }

    pub fn sign(
        &mut self,
        params: &PublicKeyParams,
        level: ThresholdLevel,
        signers: &[ed25519::SigningKey],
    ) -> Result<(), Error> {
        let threshold = params.verifying_threshold(level);
        if threshold == 0 {
            return Err(Error::Custom(
                "Name: threshold must be greater than 0".to_string(),
            ));
        }

        let data = self.to_sign_bytes()?;
        self.signatures = Vec::with_capacity(threshold as usize);
        // siging in order of public keys
        for pk in params.public_keys.iter() {
            if let Some(signer) = signers
                .iter()
                .find(|sk| sk.verifying_key().as_bytes() == &pk.0)
            {
                let sig = Bytes64::from(signer.sign(&data).to_bytes());
                self.signatures.push(sig);
                if self.signatures.len() == threshold as usize {
                    break;
                }
            }
        }

        if self.signatures.len() != threshold as usize {
            return Err(Error::Custom(format!(
                "Name: expected {} signatures, got {}",
                threshold,
                self.signatures.len()
            )));
        }

        Ok(())
    }

    pub fn sign_with(&mut self, signer: &ed25519::SigningKey) -> Result<(), Error> {
        let data = self.to_sign_bytes()?;
        let sig = Bytes64::from(signer.sign(&data).to_bytes());
        self.signatures.push(sig);
        Ok(())
    }
}

impl From<&Bytes32> for Value {
    fn from(val: &Bytes32) -> Self {
        Value::Bytes(val.to_vec())
    }
}

impl From<&Bytes64> for Value {
    fn from(val: &Bytes64) -> Self {
        Value::Bytes(val.to_vec())
    }
}

impl From<&PublicKeyParams> for Value {
    fn from(params: &PublicKeyParams) -> Self {
        let mut arr = vec![Value::Array(
            params.public_keys.iter().map(Value::from).collect(),
        )];
        if let Some(threshold) = params.threshold {
            arr.push(Value::Integer(threshold.into()));
        }
        if let Some(kind) = params.kind {
            if params.threshold.is_none() {
                arr.push(Value::Integer(params.public_keys.len().into()));
            }
            arr.push(Value::Integer(kind.into()));
        }
        Value::Array(arr)
    }
}

impl From<&Operation> for Value {
    fn from(op: &Operation) -> Self {
        Value::Array(vec![op.subcode.into(), op.params.clone()])
    }
}

impl From<&Service> for Value {
    fn from(service: &Service) -> Self {
        let mut arr = vec![
            service.code.into(),
            Value::Array(service.operations.iter().map(Value::from).collect()),
        ];
        if let Some(attesters) = &service.attesters {
            arr.push(Value::Array(
                attesters.clone().into_iter().map(Value::from).collect(),
            ));
        }
        Value::Array(arr)
    }
}

impl From<&Name> for Value {
    fn from(name: &Name) -> Self {
        Value::Array(vec![
            Value::from(name.name.clone()),
            Value::from(name.sequence),
            Value::from(&name.service),
            Value::Array(name.signatures.iter().map(Value::from).collect()),
        ])
    }
}

impl TryFrom<&Value> for Bytes32 {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        match value {
            Value::Bytes(bytes) => Bytes32::try_from(bytes),
            _ => Err(Error::Custom(format!(
                "Bytes32: expected bytes, got {}",
                kind_of_value(value)
            ))),
        }
    }
}

impl TryFrom<&Value> for Bytes64 {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        match value {
            Value::Bytes(bytes) => Bytes64::try_from(bytes),
            _ => Err(Error::Custom(format!(
                "Bytes64: expected bytes, got {}",
                kind_of_value(value)
            ))),
        }
    }
}

impl TryFrom<&Value> for Operation {
    type Error = Error;
    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        match value {
            Value::Array(arr) => {
                if arr.len() != 2 {
                    return Err(Error::Custom(format!(
                        "Operation: expected array of length is 2, got {:?}",
                        arr.len()
                    )));
                }

                Ok(Operation {
                    subcode: u16::try_from(&IntValue(&arr[0]))?,
                    params: arr[1].clone(),
                })
            }
            _ => Err(Error::Custom(format!(
                "Operation: expected array, got {}",
                kind_of_value(value)
            ))),
        }
    }
}

impl TryFrom<&Value> for Service {
    type Error = Error;
    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let arr = value.as_array().ok_or_else(|| {
            Error::Custom(format!(
                "Service: expected array, got {}",
                kind_of_value(value)
            ))
        })?;
        match arr.len() {
            v if v == 2 || v == 3 => {
                let mut srv = Service {
                    code: u64::try_from(&IntValue(&arr[0]))?,
                    operations: arr[1]
                        .as_array()
                        .ok_or_else(|| {
                            Error::Custom(format!(
                                "Service: expected array, got {}",
                                kind_of_value(&arr[1])
                            ))
                        })?
                        .iter()
                        .map(Operation::try_from)
                        .collect::<Result<Vec<Operation>, Self::Error>>()?,
                    attesters: None,
                };
                if v == 3 {
                    let attesters = arr[2].as_array().ok_or_else(|| {
                        Error::Custom(format!(
                            "Service: expected array, got {}",
                            kind_of_value(&arr[2])
                        ))
                    })?;
                    if attesters.is_empty() {
                        return Err(Error::Custom(
                            "Service: expected non-empty array of attesters".to_string(),
                        ));
                    }

                    let attesters: Result<Vec<String>, Error> = attesters
                        .iter()
                        .map(|v| {
                            v.as_text().map(String::from).ok_or_else(|| {
                                Error::Custom(format!(
                                    "Name: expected text, got {}",
                                    kind_of_value(&arr[0])
                                ))
                            })
                        })
                        .collect();
                    srv.attesters = Some(attesters?);
                }
                Ok(srv)
            }
            v => Err(Error::Custom(format!(
                "Service: expected array of length 2 or 3, got {}",
                v
            ))),
        }
    }
}

impl TryFrom<&Value> for PublicKeyParams {
    type Error = Error;
    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let arr = value.as_array().ok_or_else(|| {
            Error::Custom(format!(
                "PublicKeyParams: expected array, got {}",
                kind_of_value(value)
            ))
        })?;
        match arr.len() {
            v if (1..=3).contains(&v) => {
                let mut params = PublicKeyParams {
                    public_keys: Bytes32::vec_try_from_value(&arr[0])?,
                    threshold: None,
                    kind: None,
                };
                if v >= 2 {
                    let threshold = u8::try_from(&IntValue(&arr[1]))?;
                    params.threshold = Some(threshold);
                }

                if v == 3 {
                    let kind = u8::try_from(&IntValue(&arr[2]))?;
                    params.kind = Some(kind);
                }
                Ok(params)
            }
            v => Err(Error::Custom(format!(
                "PublicKeyParams: expected array of length [1, 3], got {}",
                v
            ))),
        }
    }
}

impl TryFrom<&Value> for Name {
    type Error = Error;
    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let arr = value.as_array().ok_or_else(|| {
            Error::Custom(format!(
                "Name: expected array, got {}",
                kind_of_value(value)
            ))
        })?;
        match arr.len() {
            4 => Ok(Name {
                name: arr[0]
                    .as_text()
                    .ok_or_else(|| {
                        Error::Custom(format!(
                            "Name: expected text, got {}",
                            kind_of_value(&arr[0])
                        ))
                    })?
                    .to_string(),
                sequence: u64::try_from(&IntValue(&arr[1]))?,
                service: Service::try_from(&arr[2])?,
                signatures: Bytes64::vec_try_from_value(&arr[3])?,
            }),
            _ => Err(Error::Custom(format!(
                "Name: expected array of length 4, got {}",
                arr.len()
            ))),
        }
    }
}

impl Serialize for Bytes32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Bytes32 {
    fn deserialize<D>(deserializer: D) -> Result<Bytes32, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let val = Value::deserialize(deserializer)?;
        Bytes32::try_from(&val).map_err(de::Error::custom)
    }
}

impl Serialize for Bytes64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Bytes64 {
    fn deserialize<D>(deserializer: D) -> Result<Bytes64, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let val = Value::deserialize(deserializer)?;
        Bytes64::try_from(&val).map_err(de::Error::custom)
    }
}

impl Serialize for PublicKeyParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        Value::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKeyParams {
    fn deserialize<D>(deserializer: D) -> Result<PublicKeyParams, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let val = Value::deserialize(deserializer)?;
        PublicKeyParams::try_from(&val).map_err(de::Error::custom)
    }
}

impl Serialize for Service {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        Value::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Service {
    fn deserialize<D>(deserializer: D) -> Result<Service, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let val = Value::deserialize(deserializer)?;
        Service::try_from(&val).map_err(de::Error::custom)
    }
}

impl Serialize for Name {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        Value::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D>(deserializer: D) -> Result<Name, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let val = Value::deserialize(deserializer)?;
        Name::try_from(&val).map_err(de::Error::custom)
    }
}

pub(crate) fn kind_of_value(v: &Value) -> String {
    match v {
        Value::Integer(_) => "integer".to_string(),
        Value::Bytes(_) => "bytes".to_string(),
        Value::Text(_) => "text".to_string(),
        Value::Array(_) => "array".to_string(),
        Value::Map(_) => "map".to_string(),
        Value::Tag(_, _) => "tag".to_string(),
        Value::Bool(_) => "bool".to_string(),
        Value::Null => "null".to_string(),
        Value::Float(_) => "float".to_string(),
        _ => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use rand_core::{OsRng, RngCore};

    fn secret_key() -> [u8; 32] {
        let mut data = [0u8; 32];
        OsRng.fill_bytes(&mut data);
        data
    }

    #[test]
    fn valid_name_works() {
        for name in &["a", "abc", "ʦ", "公信", "0", "b0"] {
            assert!(valid_name(name), "{} is invalid", name)
        }
        for name in &[
            "",
            " ",
            "‍",
            "\n",
            "a‍",
            "A",
            ".",
            ":",
            "*",
            "。",
            "-",
            "_",
            "——",
            "\0",
            "\u{301}",
            "🀄",
            "❤️‍🔥",
            "a\u{301}",
        ] {
            assert!(!valid_name(name), "{} is valid", name)
        }
    }

    #[test]
    fn check_ascii_name() {
        let mut i = 0;
        let mut result: String = String::new();
        while i < 127 {
            let s = char::from(i).to_string();
            // println!("{}>{}<: {}", i, s, valid_name(&s));
            if valid_name(&s) {
                result.push_str(&s)
            }
            i += 1;
        }
        assert_eq!(result, "0123456789abcdefghijklmnopqrstuvwxyz");
    }

    #[test]
    fn check_greek_name() {
        for name in &[
            "α", "β", "γ", "δ", "ε", "ζ", "η", "θ", "ι", "κ", "λ", "μ", "ν", "ξ", "ο", "π", "ρ",
            "ς", "σ", "τ", "υ", "φ", "χ", "ψ", "ω", "ϕ", "ϵ",
        ] {
            println!("{} is {}", name, valid_name(name))
        }
    }

    #[test]
    fn signature_ser_de() {
        let sig = Bytes64(hex!("6b71fd0c8ae2ccc910c39dd20e76653fccca2638b7935f2312e954f5dccd71b209c58ca57e9d4fc2d3c06a57d585dbadf4535abb8a9cf103eeb9b9717d87f201"));
        let mut buf: Vec<u8> = Vec::new();
        into_writer(&sig, &mut buf).unwrap();
        assert_eq!(buf.len(), 66);
        assert_eq!(buf[0], 0x58); // byte string
        assert_eq!(buf[1], 0x40); // 64 bytes
        let sig2: Bytes64 = from_reader(&buf[..]).unwrap();
        assert_eq!(sig, sig2);
    }

    #[test]
    fn name_ser_de() {
        let secret_key = Bytes32(hex!(
            "7ef3811aabb916dc2f646ef1a371b90adec91bc07992cd4d44c156c42fc1b300"
        ));
        let public_key = Bytes32(hex!(
            "ee90735ac719e85dc2f3e5974036387fdf478af7d9d1f8480e97eee601890266"
        ));
        let params = PublicKeyParams {
            public_keys: vec![public_key],
            threshold: Some(1),
            kind: None,
        };
        let signer = ed25519::SigningKey::from_bytes(&secret_key.0);
        assert!(params.validate().is_ok());

        let mut name = Name {
            name: "a".to_string(),
            sequence: 0,
            service: Service {
                code: 0,
                operations: vec![Operation {
                    subcode: 1,
                    params: Value::from(&params),
                }],
                attesters: None,
            },
            signatures: vec![],
        };
        assert!(name.validate().is_err());
        name.sign(&params, ThresholdLevel::Default, &[signer])
            .unwrap();
        assert!(name.validate().is_ok());
        assert!(name.verify(&params, ThresholdLevel::Single).is_ok());
        assert!(name.verify(&params, ThresholdLevel::Default).is_ok());
        assert!(name.verify(&params, ThresholdLevel::Strict).is_ok());
        assert!(name.verify(&params, ThresholdLevel::All).is_ok());
        assert_eq!(name.signatures, vec![Bytes64(
            hex!("e23554d996647e86f69115d04515398cc7463062d2683b099371360e93fa1cba02351492b70ef31037baa7780053bcf20b12bafe9531ee17fe140b93082a3f0c")
        )]);

        let data = name.to_bytes().unwrap();
        assert_eq!(hex::encode(&data), "d83584616100820081820182815820ee90735ac719e85dc2f3e5974036387fdf478af7d9d1f8480e97eee60189026601815840e23554d996647e86f69115d04515398cc7463062d2683b099371360e93fa1cba02351492b70ef31037baa7780053bcf20b12bafe9531ee17fe140b93082a3f0c");
        // 53(["a", 0, [0, [[1, [[h'ee90735ac719e85dc2f3e5974036387fdf478af7d9d1f8480e97eee601890266'], 1]]]], [h'e23554d996647e86f69115d04515398cc7463062d2683b099371360e93fa1cba02351492b70ef31037baa7780053bcf20b12bafe9531ee17fe140b93082a3f0c']])

        let name2 = Name::decode_from(&data[..]).unwrap();
        assert_eq!(name, name2);
        assert_eq!(name2.to_bytes().unwrap(), data);

        let name3 = Name::from_bytes(&data[..]).unwrap();
        assert_eq!(name, name3);
        assert_eq!(name3.to_bytes().unwrap(), data);

        let mut buf: Vec<u8> = Vec::with_capacity(data.len() + 1);
        buf.extend_from_slice(&data);
        buf.push(0x80);
        assert!(Name::from_bytes(&buf[..]).is_err());
    }

    #[test]
    fn name_sign_verify() {
        let s1 = ed25519::SigningKey::from_bytes(&secret_key());
        let s2 = ed25519::SigningKey::from_bytes(&secret_key());
        let s3 = ed25519::SigningKey::from_bytes(&secret_key());
        let s4 = ed25519::SigningKey::from_bytes(&secret_key());
        let mut signers = vec![s1.clone(), s2.clone(), s3.clone(), s4.clone()];

        let params = PublicKeyParams {
            public_keys: vec![
                s1.verifying_key().as_bytes().into(),
                s2.verifying_key().as_bytes().into(),
                s3.verifying_key().as_bytes().into(),
                s4.verifying_key().as_bytes().into(),
            ],
            threshold: Some(2),
            kind: None,
        };

        let mut name = Name {
            name: "道".to_string(),
            sequence: 0,
            service: Service {
                code: 0,
                operations: vec![Operation {
                    subcode: 1,
                    params: Value::from(&params),
                }],
                attesters: None,
            },
            signatures: vec![],
        };
        assert!(name.validate().is_err());
        name.sign(&params, ThresholdLevel::Single, &signers)
            .unwrap();
        assert!(name.validate().is_ok());
        assert_eq!(1, name.signatures.len());
        assert!(name.verify(&params, ThresholdLevel::Single).is_ok());
        assert!(name.verify(&params, ThresholdLevel::Default).is_err());
        assert!(name.verify(&params, ThresholdLevel::Strict).is_err());
        assert!(name.verify(&params, ThresholdLevel::All).is_err());

        let mut invalid_name = name.clone();
        invalid_name.sequence = 1;
        assert!(invalid_name
            .verify(&params, ThresholdLevel::Single)
            .is_err());

        name.sign(&params, ThresholdLevel::Default, &signers)
            .unwrap();
        assert!(name.validate().is_ok());
        assert_eq!(2, name.signatures.len());
        assert!(name.verify(&params, ThresholdLevel::Single).is_ok());
        assert!(name.verify(&params, ThresholdLevel::Default).is_ok());
        assert!(name.verify(&params, ThresholdLevel::Strict).is_err());
        assert!(name.verify(&params, ThresholdLevel::All).is_err());

        name.sign(&params, ThresholdLevel::Strict, &signers)
            .unwrap();
        assert!(name.validate().is_ok());
        assert_eq!(3, name.signatures.len());
        assert!(name.verify(&params, ThresholdLevel::Single).is_ok());
        assert!(name.verify(&params, ThresholdLevel::Default).is_ok());
        assert!(name.verify(&params, ThresholdLevel::Strict).is_ok());
        assert!(name.verify(&params, ThresholdLevel::All).is_err());

        name.sign(&params, ThresholdLevel::All, &signers).unwrap();
        assert!(name.validate().is_ok());
        assert_eq!(4, name.signatures.len());
        assert!(name.verify(&params, ThresholdLevel::Single).is_ok());
        assert!(name.verify(&params, ThresholdLevel::Default).is_ok());
        assert!(name.verify(&params, ThresholdLevel::Strict).is_ok());
        assert!(name.verify(&params, ThresholdLevel::All).is_ok());

        assert!(
            name.sign(&params, ThresholdLevel::All, &signers[1..])
                .is_err(),
            "signers less than ThresholdLevel::All"
        );
        assert!(name
            .sign(&params, ThresholdLevel::Strict, &signers[1..])
            .is_ok());
        assert!(name.verify(&params, ThresholdLevel::Strict).is_ok());
        assert!(name.verify(&params, ThresholdLevel::All).is_err());

        signers[3] = s3.clone();
        assert!(
            name.sign(&params, ThresholdLevel::All, &signers).is_err(),
            "depulicate signer"
        );
        assert!(name.sign(&params, ThresholdLevel::Strict, &signers).is_ok());
        assert!(name.verify(&params, ThresholdLevel::Strict).is_ok());
        assert!(name.verify(&params, ThresholdLevel::All).is_err());

        signers[3] = ed25519::SigningKey::from_bytes(&secret_key());
        assert!(
            name.sign(&params, ThresholdLevel::All, &signers).is_err(),
            "stranger signer"
        );
        assert!(name.sign(&params, ThresholdLevel::Strict, &signers).is_ok());
        assert!(name.verify(&params, ThresholdLevel::Strict).is_ok());
        assert!(name.verify(&params, ThresholdLevel::All).is_err());

        signers[3] = s4.clone();
        assert!(name.sign(&params, ThresholdLevel::All, &signers).is_ok());
        assert!(name.verify(&params, ThresholdLevel::All).is_ok());
    }
}
