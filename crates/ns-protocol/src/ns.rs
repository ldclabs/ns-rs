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
    pub signatures: Vec<Signature>,
}

#[derive(Clone, PartialEq, Debug, Default)]
pub struct Service {
    pub code: u64,
    pub operations: Vec<Operation>,
    pub approver: Option<String>, // approver's name
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

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Signature(pub Vec<u8>);

// PublicKeyParams is Ed25519 Multisignatures with threshold,
// every public key can be FROST (Flexible Round-Optimised Schnorr Threshold signatures)
// see: https://github.com/ZcashFoundation/frost
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct PublicKeyParams {
    pub public_keys: Vec<Vec<u8>>,
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
        for pk in self.public_keys.iter() {
            if pk.len() != 32 {
                return Err(Error::Custom(format!(
                    "PublicKeyParams: expected key length is 32, got {:?}",
                    pk.len()
                )));
            }
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

        if let Some(approver) = &self.service.approver {
            if !valid_name(approver) {
                return Err(Error::Custom(format!(
                    "Name: invalid approver {}",
                    approver
                )));
            }
        }

        if self.service.operations.is_empty() {
            return Err(Error::Custom("Name: missing operations".to_string()));
        }

        if self.signatures.is_empty() {
            return Err(Error::Custom("Name: missing signatures".to_string()));
        }
        for sig in self.signatures.iter() {
            if sig.0.len() != 64 {
                return Err(Error::Custom(format!(
                    "Name: expected signature length is 64, got {:?}",
                    sig.0.len()
                )));
            }
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
            let key = ed25519::VerifyingKey::try_from(pk.as_slice())
                .map_err(|err| Error::Custom(err.to_string()))?;
            keys.push(key);
        }

        let mut count = 0;
        for sig in self.signatures.iter() {
            let sig = ed25519::Signature::from_slice(&sig.0)
                .map_err(|err| Error::Custom(err.to_string()))?;
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
                .find(|sk| sk.verifying_key().as_bytes().as_slice() == pk)
            {
                let sig = Signature(signer.sign(&data).to_bytes().to_vec());
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
        let sig = Signature(signer.sign(&data).to_bytes().to_vec());
        self.signatures.push(sig);
        Ok(())
    }
}

impl From<&Signature> for Value {
    fn from(signature: &Signature) -> Self {
        Value::Bytes(signature.0.clone())
    }
}

impl From<&PublicKeyParams> for Value {
    fn from(params: &PublicKeyParams) -> Self {
        let mut arr = vec![Value::Array(
            params
                .public_keys
                .iter()
                .map(|pk| Value::Bytes(pk.clone()))
                .collect(),
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
        if let Some(ref approver) = service.approver {
            arr.push(Value::Text(approver.clone()));
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

impl TryFrom<&Value> for Signature {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        match value {
            Value::Bytes(bytes) => {
                if bytes.len() != 64 {
                    Err(Error::Custom(format!(
                        "Signature: expected value length is 64, got {:?}",
                        bytes.len()
                    )))
                } else {
                    let mut value = Vec::with_capacity(64);
                    value.extend(bytes);
                    Ok(Signature(value))
                }
            }
            _ => Err(Error::Custom(format!(
                "Signature: expected bytes, got {}",
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
                    subcode: arr[0]
                        .as_integer()
                        .ok_or_else(|| {
                            Error::Custom(format!(
                                "Operation: expected integer, got {}",
                                kind_of_value(&arr[0])
                            ))
                        })?
                        .try_into()
                        .map_err(|err| {
                            Error::Custom(format!("Operation: expected u32, error, {:?}", err))
                        })?,
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
                    code: arr[0]
                        .as_integer()
                        .ok_or_else(|| {
                            Error::Custom(format!(
                                "Service: expected integer, got {}",
                                kind_of_value(&arr[0])
                            ))
                        })?
                        .try_into()
                        .map_err(|err| {
                            Error::Custom(format!("Service: expected u32, error: {:?}", err))
                        })?,
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
                    approver: None,
                };
                if v == 3 {
                    let approver = arr[2].as_text().ok_or_else(|| {
                        Error::Custom(format!(
                            "Service: expected text, got {}",
                            kind_of_value(&arr[2])
                        ))
                    })?;
                    srv.approver = Some(approver.to_string());
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
                    public_keys: arr[0]
                        .as_array()
                        .ok_or_else(|| {
                            Error::Custom(format!(
                                "PublicKeyParams: expected array, got {}",
                                kind_of_value(&arr[0])
                            ))
                        })?
                        .iter()
                        .map(|pk| {
                            pk.as_bytes().map(|v| v.to_owned()).ok_or_else(|| {
                                Error::Custom(format!(
                                    "PublicKeyParams: expected bytes, got {}",
                                    kind_of_value(pk)
                                ))
                            })
                        })
                        .collect::<Result<Vec<Vec<u8>>, Error>>()?,
                    threshold: None,
                    kind: None,
                };
                if v >= 2 {
                    let threshold = arr[1]
                        .as_integer()
                        .ok_or_else(|| {
                            Error::Custom(format!(
                                "PublicKeyParams: expected integer, got {}",
                                kind_of_value(&arr[1])
                            ))
                        })?
                        .try_into()
                        .map_err(|err| {
                            Error::Custom(format!("PublicKeyParams: expected u8, error: {:?}", err))
                        })?;
                    params.threshold = Some(threshold);
                }

                if v == 3 {
                    let kind = arr[2]
                        .as_integer()
                        .ok_or_else(|| {
                            Error::Custom(format!(
                                "PublicKeyParams: expected integer, got {}",
                                kind_of_value(&arr[2])
                            ))
                        })?
                        .try_into()
                        .map_err(|err| {
                            Error::Custom(format!("PublicKeyParams: expected u8, error: {:?}", err))
                        })?;
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
                sequence: arr[1]
                    .as_integer()
                    .ok_or_else(|| {
                        Error::Custom(format!(
                            "Name: expected integer, got {}",
                            kind_of_value(&arr[1])
                        ))
                    })?
                    .try_into()
                    .map_err(|err| {
                        Error::Custom(format!("Name: expected u64, error: {:?}", err))
                    })?,
                service: Service::try_from(&arr[2])?,
                signatures: arr[3]
                    .as_array()
                    .ok_or_else(|| {
                        Error::Custom(format!(
                            "Name: expected array, got {}",
                            kind_of_value(&arr[3])
                        ))
                    })?
                    .iter()
                    .map(Signature::try_from)
                    .collect::<Result<Vec<Signature>, Self::Error>>()?,
            }),
            _ => Err(Error::Custom(format!(
                "Name: expected array of length 4, got {}",
                arr.len()
            ))),
        }
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let val = Value::deserialize(deserializer)?;
        Signature::try_from(&val).map_err(de::Error::custom)
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

fn kind_of_value(v: &Value) -> String {
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
    fn signature_ser_de() {
        let sig = Signature(hex!("6b71fd0c8ae2ccc910c39dd20e76653fccca2638b7935f2312e954f5dccd71b209c58ca57e9d4fc2d3c06a57d585dbadf4535abb8a9cf103eeb9b9717d87f201").to_vec());
        let mut buf: Vec<u8> = Vec::new();
        into_writer(&sig, &mut buf).unwrap();
        assert_eq!(buf.len(), 66);
        assert_eq!(buf[0], 0x58); // byte string
        assert_eq!(buf[1], 0x40); // 64 bytes
        let sig2: Signature = from_reader(&buf[..]).unwrap();
        assert_eq!(sig, sig2);
    }

    #[test]
    fn name_ser_de() {
        let secret_key = hex!("7ef3811aabb916dc2f646ef1a371b90adec91bc07992cd4d44c156c42fc1b300");
        let public_key = hex!("ee90735ac719e85dc2f3e5974036387fdf478af7d9d1f8480e97eee601890266");
        let params = PublicKeyParams {
            public_keys: vec![public_key.to_vec()],
            threshold: Some(1),
            kind: None,
        };
        let signer = ed25519::SigningKey::try_from(&secret_key).unwrap();
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
                approver: None,
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
        assert_eq!(name.signatures, vec![Signature(
            hex!("e23554d996647e86f69115d04515398cc7463062d2683b099371360e93fa1cba02351492b70ef31037baa7780053bcf20b12bafe9531ee17fe140b93082a3f0c").to_vec(),
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
                s1.verifying_key().as_bytes().to_vec(),
                s2.verifying_key().as_bytes().to_vec(),
                s3.verifying_key().as_bytes().to_vec(),
                s4.verifying_key().as_bytes().to_vec(),
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
                approver: None,
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
