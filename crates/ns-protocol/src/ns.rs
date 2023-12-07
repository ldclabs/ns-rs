use ciborium::{from_reader, into_writer, tag, value::Value};
use ciborium_io::{Read, Write};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use finl_unicode::categories::CharacterCategories;
use serde::{de, ser, Deserialize, Serialize};
use std::{convert::From, error::Error, fmt, fmt::Debug};

pub type NSTag = tag::Required<Name, 53>;
pub type NSTagRef<'a> = tag::Required<&'a Name, 53>;
pub const MAX_NAME_BYTES: usize = 520;

#[derive(Clone, PartialEq, Debug)]
pub struct Name {
    pub name: String,
    pub sequence: u64,
    pub payload: Service,
    pub signatures: Signatures,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Service {
    pub code: u32,
    pub opcode: u8,
    pub params: Value,
    pub approver: Option<String>, // approver's name
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature(Vec<u8>);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signatures(Vec<Signature>);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKeyParams {
    pub public_keys: Vec<Vec<u8>>,
    pub threshold: Option<u8>, // default to public_keys.len()
    pub kind: Option<u8>,      // default to 0: ed25519
}

impl PublicKeyParams {
    pub fn validate(&self) -> Result<(), Box<dyn Error>> {
        if self.public_keys.is_empty() {
            return Err("expected at least one public key".into());
        }
        for pk in self.public_keys.iter() {
            if pk.len() != 32 {
                return Err(format!("expected public key length 32, got {:?}", pk.len()).into());
            }
        }
        if let Some(threshold) = self.threshold {
            if threshold == 0 {
                return Err("threshold must be greater than 0".into());
            }
            if threshold > self.public_keys.len() as u8 {
                return Err(format!(
                    "threshold {} is greater than number of public keys {}",
                    threshold,
                    self.public_keys.len()
                )
                .into());
            }
        }
        if let Some(kind) = self.kind {
            if kind != 0 {
                return Err(format!("unsupported public key kind {}", kind).into());
            }
        }
        let mut public_keys = self.public_keys.clone();
        public_keys.dedup();
        if public_keys.len() != self.public_keys.len() {
            return Err(format!("duplicate public_keys {:?}", self.public_keys).into());
        }

        Ok(())
    }

    pub fn verifying_threshold(&self, level: ThresholdLevel) -> u8 {
        match level {
            ThresholdLevel::One => 1,
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
            ThresholdLevel::Full => self.public_keys.len() as u8,
        }
    }
}

pub enum ThresholdLevel {
    One,
    Default, // DefaultLevel = threshold, 1 <= DefaultLevel <= public_keys.len()
    Strict,  // StrictLevel = threshold + 1, 1 <= StrictLevel <= public_keys.len()
    Full,    // FullLevel = public_keys.len()
}

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
            || c.is_other()
        {
            return false;
        }
    }

    true
}

impl Name {
    pub fn decode_from<R: Read>(r: R) -> Result<Self, Box<dyn Error>>
    where
        R::Error: core::fmt::Debug,
    {
        let value: NSTag =
            from_reader(r).map_err(|err| format!("decode_from failed: {:?}", err))?;
        Ok(value.0)
    }

    pub fn encode_to<W: Write>(&self, w: W) -> Result<(), Box<dyn Error>>
    where
        W::Error: core::fmt::Debug,
    {
        let v: NSTagRef = tag::Required(self);
        into_writer(&v, w).map_err(|err| format!("encode_to failed: {:?}", err))?;
        Ok(())
    }

    pub fn to_sign_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let arr = Value::Array(vec![
            Value::from(self.name.clone()),
            Value::from(self.sequence),
            Value::from(&self.payload),
        ]);
        let mut buf: Vec<u8> = Vec::new();
        into_writer(&arr, &mut buf)?;
        Ok(buf)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buf: Vec<u8> = Vec::new();
        self.encode_to(&mut buf)?;
        Ok(buf)
    }
}

impl Name {
    // validate the name is well-formed
    pub fn validate(&self) -> Result<(), Box<dyn Error>> {
        if !valid_name(&self.name) {
            return Err(format!("invalid name {}", self.name).into());
        }
        if let Some(approver) = &self.payload.approver {
            if !valid_name(approver) {
                return Err(format!("invalid approver {}", approver).into());
            }
        }
        if self.signatures.0.is_empty() {
            return Err("missing signatures".into());
        }
        for sig in self.signatures.0.iter() {
            if sig.0.len() != 64 {
                return Err(format!("expected signature length 64, got {:?}", sig.0.len()).into());
            }
        }

        let mut signatures = self.signatures.0.clone();
        signatures.dedup();
        if signatures.len() != self.signatures.0.len() {
            return Err(format!("duplicate signatures {:?}", self.signatures).into());
        }
        Ok(())
    }

    // verify the data is signed by the public keys with the given threshold level
    pub fn verify(
        &self,
        params: &PublicKeyParams,
        level: ThresholdLevel,
    ) -> Result<(), Box<dyn Error>> {
        let threshold = params.verifying_threshold(level);
        if threshold == 0 {
            return Err("threshold must be greater than 0".into());
        }

        let data = self.to_sign_bytes()?;
        let mut keys = params.public_keys.iter();
        let mut count = 0;
        for sig in self.signatures.0.iter() {
            let sig = Ed25519Signature::from_slice(&sig.0)?;
            for key in keys.by_ref() {
                let verifying_key = Ed25519VerifyingKey::try_from(key.as_slice())?;
                if verifying_key.verify_strict(&data, &sig).is_ok() {
                    count += 1;
                    if count >= threshold {
                        return Ok(());
                    }

                    break;
                }
            }
        }

        Err(format!(
            "verify failed, expected {} signatures, got {}",
            threshold, count
        )
        .into())
    }

    pub fn sign(
        &mut self,
        params: &PublicKeyParams,
        level: ThresholdLevel,
        secret_keys: &[Vec<u8>],
    ) -> Result<(), Box<dyn Error>> {
        let threshold = params.verifying_threshold(level);
        if threshold == 0 {
            return Err("threshold must be greater than 0".into());
        }

        let data = self.to_sign_bytes()?;
        let signing_keys = secret_keys
            .iter()
            .map(|key| Ed25519SigningKey::try_from(key.as_slice()))
            .collect::<Result<Vec<Ed25519SigningKey>, ed25519_dalek::ed25519::Error>>()?;

        let mut signatures: Vec<Signature> = Vec::with_capacity(threshold as usize);
        // siging in order of public keys
        for pk in params.public_keys.iter() {
            if let Some(signer) = signing_keys
                .iter()
                .find(|sk| sk.verifying_key().as_bytes().as_slice() == pk)
            {
                let sig = Signature(signer.sign(&data).to_bytes().to_vec());
                signatures.push(sig);
            }
        }
        self.signatures = Signatures(signatures);
        Ok(())
    }

    pub fn sign_with(&mut self, signer: &Ed25519SigningKey) -> Result<(), Box<dyn Error>> {
        let data = self.to_sign_bytes()?;
        let sig = Signature(signer.sign(&data).to_bytes().to_vec());
        self.signatures.0.push(sig);
        Ok(())
    }
}

impl From<&Signature> for Value {
    fn from(signature: &Signature) -> Self {
        Value::Bytes(signature.0.clone())
    }
}

impl From<&Signatures> for Value {
    fn from(signatures: &Signatures) -> Self {
        Value::Array(signatures.0.iter().map(Value::from).collect())
    }
}

impl From<&Service> for Value {
    fn from(service: &Service) -> Self {
        if let Some(ref approver) = service.approver {
            Value::Array(vec![
                Value::Integer(service.code.into()),
                Value::Integer(service.opcode.into()),
                service.params.clone(),
                Value::Text(approver.clone()),
            ])
        } else {
            Value::Array(vec![
                Value::Integer(service.code.into()),
                Value::Integer(service.opcode.into()),
                service.params.clone(),
            ])
        }
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

impl From<&Name> for Value {
    fn from(name: &Name) -> Self {
        Value::Array(vec![
            Value::from(name.name.clone()),
            Value::from(name.sequence),
            Value::from(&name.payload),
            Value::from(&name.signatures),
        ])
    }
}

impl TryFrom<&Value> for Signature {
    type Error = Box<dyn Error>;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        match value {
            Value::Bytes(bytes) => {
                if bytes.len() != 64 {
                    Err(format!("expected value length 64, got {:?}", bytes.len()).into())
                } else {
                    let mut value = Vec::with_capacity(64);
                    value.extend(bytes);
                    Ok(Signature(value))
                }
            }
            _ => Err(format!("expected bytes, got {}", kind_of_value(value)).into()),
        }
    }
}

impl TryFrom<&Value> for Signatures {
    type Error = Box<dyn Error>;
    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        match value {
            Value::Array(arr) => {
                let sigs: Vec<Signature> =
                    arr.iter()
                        .map(Signature::try_from)
                        .collect::<Result<Vec<Signature>, Self::Error>>()?;
                Ok(Signatures(sigs))
            }
            _ => Err(format!("expected array, got {}", kind_of_value(value)).into()),
        }
    }
}

impl TryFrom<&Value> for Service {
    type Error = Box<dyn Error>;
    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let arr = value
            .as_array()
            .ok_or_else(|| format!("expected array, got {}", kind_of_value(value)))?;
        match arr.len() {
            v if v == 3 || v == 4 => {
                let mut srv = Service {
                    code: arr[0]
                        .as_integer()
                        .ok_or_else(|| format!("expected integer, got {}", kind_of_value(&arr[0])))?
                        .try_into()
                        .map_err(|err| format!("expected u32, error: {:?}", err))?,
                    opcode: arr[1]
                        .as_integer()
                        .ok_or_else(|| format!("expected integer, got {}", kind_of_value(&arr[1])))?
                        .try_into()
                        .map_err(|err| format!("expected u8, error: {:?}", err))?,
                    params: arr[2].clone(),
                    approver: None,
                };
                if v == 4 {
                    let approver = arr[3]
                        .as_text()
                        .ok_or_else(|| format!("expected text, got {}", kind_of_value(&arr[3])))?;
                    srv.approver = Some(approver.to_string());
                }
                Ok(srv)
            }
            v => Err(format!("expected array of length 3 or 4, got {:?}", v).into()),
        }
    }
}

impl TryFrom<&Value> for PublicKeyParams {
    type Error = Box<dyn Error>;
    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let arr = value
            .as_array()
            .ok_or_else(|| format!("expected array, got {}", kind_of_value(value)))?;
        match arr.len() {
            v if (1..=3).contains(&v) => {
                let mut params = PublicKeyParams {
                    public_keys: arr[0]
                        .as_array()
                        .ok_or_else(|| format!("expected array, got {}", kind_of_value(&arr[0])))?
                        .iter()
                        .map(|pk| {
                            pk.as_bytes().map(|v| v.to_owned())
                                .ok_or_else(|| format!("expected bytes, got {}", kind_of_value(pk)))
                        })
                        .collect::<Result<Vec<Vec<u8>>, String>>()?,
                    threshold: None,
                    kind: None,
                };
                if v >= 2 {
                    let threshold = arr[1]
                        .as_integer()
                        .ok_or_else(|| format!("expected integer, got {}", kind_of_value(&arr[1])))?
                        .try_into()
                        .map_err(|err| format!("expected u8, error: {:?}", err))?;
                    params.threshold = Some(threshold);
                }

                if v == 3 {
                    let kind = arr[2]
                        .as_integer()
                        .ok_or_else(|| format!("expected integer, got {}", kind_of_value(&arr[2])))?
                        .try_into()
                        .map_err(|err| format!("expected u8, error: {:?}", err))?;
                    params.kind = Some(kind);
                }
                Ok(params)
            }
            v => Err(format!("expected array of length 4, got {:?}", v).into()),
        }
    }
}

impl TryFrom<&Value> for Name {
    type Error = Box<dyn Error>;
    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let arr = value
            .as_array()
            .ok_or_else(|| format!("expected array, got {}", kind_of_value(value)))?;
        match arr.len() {
            4 => Ok(Name {
                name: arr[0]
                    .as_text()
                    .ok_or_else(|| format!("expected text, got {}", kind_of_value(&arr[0])))?
                    .to_string(),
                sequence: arr[1]
                    .as_integer()
                    .ok_or_else(|| format!("expected integer, got {}", kind_of_value(&arr[1])))?
                    .try_into()
                    .map_err(|err| format!("expected u64, error: {:?}", err))?,
                payload: Service::try_from(&arr[2])?,
                signatures: Signatures::try_from(&arr[3])?,
            }),
            _ => Err(format!("expected array of length 4, got {:?}", arr.len()).into()),
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

struct SignatureVisitor;

impl<'de> de::Visitor<'de> for SignatureVisitor {
    type Value = Signature;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a 64 bytes signature")
    }

    fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.len() != 64 {
            Err(de::Error::custom(format!(
                "expected value length 64, got {:?}",
                v.len()
            )))
        } else {
            let mut value = Vec::with_capacity(64);
            value.extend_from_slice(v);
            Ok(Signature(value))
        }
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_borrowed_bytes(v)
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_borrowed_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_any(SignatureVisitor)
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
        let arr = Value::deserialize(deserializer)?;
        Service::try_from(&arr).map_err(de::Error::custom)
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
        let arr = Value::deserialize(deserializer)?;
        Name::try_from(&arr).map_err(de::Error::custom)
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
    use faster_hex::hex_string;
    use hex_literal::hex;

    #[test]
    fn valid_name_works() {
        for name in &["", "a", "abc", "公信", "0", "🀄", "b0"] {
            assert!(valid_name(name), "{} is invalid", name)
        }
        for name in &[
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
            "❤️‍🔥",
            "a\u{301}",
        ] {
            assert!(!valid_name(name), "{} is valid", name)
        }
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
        assert!(params.validate().is_ok());

        let mut name = Name {
            name: "a".to_string(),
            sequence: 0,
            payload: Service {
                code: 0,
                opcode: 1,
                params: Value::from(&params),
                approver: None,
            },
            signatures: Signatures(vec![]),
        };
        assert!(name.validate().is_err());
        name.sign(&params, ThresholdLevel::Default, &[secret_key.to_vec()])
            .unwrap();
        assert!(name.validate().is_ok());
        assert!(name.verify(&params, ThresholdLevel::One).is_ok());
        assert!(name.verify(&params, ThresholdLevel::Default).is_ok());
        assert!(name.verify(&params, ThresholdLevel::Strict).is_ok());
        assert!(name.verify(&params, ThresholdLevel::Full).is_ok());
        assert_eq!(name.signatures.0, vec![Signature(
            hex!("d4eee79600a9414099f172d7416b64d8901154e479fd26f54f30b47bf9ddd014aaf1396f5f3ab8134ec0bed1763803701a485e8e3b1e2e47968b3e1b846c7b00").to_vec(),
        )]);

        let data = name.to_bytes().unwrap();
        assert_eq!(hex_string(&data), "d8358461610083000182815820ee90735ac719e85dc2f3e5974036387fdf478af7d9d1f8480e97eee60189026601815840d4eee79600a9414099f172d7416b64d8901154e479fd26f54f30b47bf9ddd014aaf1396f5f3ab8134ec0bed1763803701a485e8e3b1e2e47968b3e1b846c7b00");
        // 53(["a", 0, [0, 1, [[h'ee90735ac719e85dc2f3e5974036387fdf478af7d9d1f8480e97eee601890266'], 1]], [h'd4eee79600a9414099f172d7416b64d8901154e479fd26f54f30b47bf9ddd014aaf1396f5f3ab8134ec0bed1763803701a485e8e3b1e2e47968b3e1b846c7b00']])

        let name2 = Name::decode_from(&data[..]).unwrap();
        assert_eq!(name, name2);
        assert_eq!(name2.to_bytes().unwrap(), data);
    }
}
