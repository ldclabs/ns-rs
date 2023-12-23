use axum::http::header;
use libflate::gzip::{Decoder, Encoder};
use std::{io, string::ToString};

// recommended minimum size for compression.
pub const MIN_ENCODING_SIZE: u16 = 128;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Encoding {
    Zstd,
    Gzip,
    Identity,
}

impl ToString for Encoding {
    fn to_string(&self) -> String {
        match self {
            Self::Zstd => "zstd".to_string(),
            Self::Gzip => "gzip".to_string(),
            Self::Identity => "identity".to_string(),
        }
    }
}

impl Encoding {
    pub fn identity(&self) -> bool {
        matches!(self, Self::Identity)
    }

    pub fn from_header_value(val: Option<&header::HeaderValue>) -> Self {
        if let Some(val) = val {
            if let Ok(val) = val.to_str() {
                if val.contains("zstd") {
                    return Self::Zstd;
                } else if val.contains("gzip") {
                    return Self::Gzip;
                }
            }
        }
        Self::Identity
    }

    pub fn header_value(&self) -> header::HeaderValue {
        match self {
            Self::Zstd => header::HeaderValue::from_static("zstd"),
            Self::Gzip => header::HeaderValue::from_static("gzip"),
            Self::Identity => header::HeaderValue::from_static("identity"),
        }
    }

    pub fn encode_all<R: io::Read>(&self, r: R) -> Result<Vec<u8>, io::Error> {
        match self {
            Self::Zstd => {
                let buf = zstd::stream::encode_all(r, 9)?;
                Ok(buf)
            }
            Self::Gzip => {
                let mut encoder = Encoder::new(Vec::new())?;
                let mut r = r;
                let _ = io::copy(&mut r, &mut encoder);
                encoder.finish().into_result()
            }
            Self::Identity => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "identity encoding not supported",
            )),
        }
    }

    pub fn decode_all<R: io::Read>(&self, r: R) -> Result<Vec<u8>, io::Error> {
        use io::Read;
        match self {
            Self::Zstd => {
                let buf = zstd::stream::decode_all(r)?;
                Ok(buf)
            }
            Self::Gzip => {
                let mut decoder = Decoder::new(r)?;
                let mut buf = Vec::new();
                decoder.read_to_end(&mut buf)?;
                Ok(buf)
            }
            Self::Identity => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "identity decoding not supported",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gzip_encode_decode() {
        let enc = Encoding::from_header_value(Some(&Encoding::Gzip.header_value()));
        assert_eq!(enc, Encoding::Gzip);

        let data = r#"[{"id":"------","texts":[]},{"id":"Esp9G6","texts":["Stream:"]},{"id": "------","texts":[]},{"id":"ykuRdu","texts":["Internet Engineering Task Force (IETF)"]}]"#;

        let encoded = enc.encode_all(data.as_bytes()).unwrap();
        println!("{}, {}", data.len(), encoded.len());
        assert!(encoded.len() < data.len());

        let decoded = enc.decode_all(encoded.as_slice()).unwrap();
        assert_eq!(data.as_bytes(), decoded.as_slice());
    }

    #[test]
    fn zstd_encode_decode() {
        let enc = Encoding::from_header_value(Some(&Encoding::Zstd.header_value()));
        assert_eq!(enc, Encoding::Zstd);

        let data = r#"[{"id":"------","texts":[]},{"id":"Esp9G6","texts":["Stream:"]},{"id": "------","texts":[]},{"id":"ykuRdu","texts":["Internet Engineering Task Force (IETF)"]}]"#;

        let encoded = enc.encode_all(data.as_bytes()).unwrap();
        println!("{}, {}", data.len(), encoded.len());
        assert!(encoded.len() < data.len());

        let decoded = enc.decode_all(encoded.as_slice()).unwrap();
        assert_eq!(data.as_bytes(), decoded.as_slice());
    }
}
