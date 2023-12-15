use std::collections::{HashMap, HashSet};

pub use scylla::cql_to_rust::{FromCqlVal, FromCqlValError};
pub use scylla::frame::response::result::CqlValue;

pub trait ToCqlVal: Sized {
    fn to_cql(&self) -> CqlValue;
}

impl ToCqlVal for String {
    fn to_cql(&self) -> CqlValue {
        CqlValue::Text(self.to_owned())
    }
}

impl ToCqlVal for bool {
    fn to_cql(&self) -> CqlValue {
        CqlValue::Boolean(self.to_owned())
    }
}

impl ToCqlVal for i8 {
    fn to_cql(&self) -> CqlValue {
        CqlValue::TinyInt(self.to_owned())
    }
}

impl ToCqlVal for i16 {
    fn to_cql(&self) -> CqlValue {
        CqlValue::SmallInt(self.to_owned())
    }
}

impl ToCqlVal for i32 {
    fn to_cql(&self) -> CqlValue {
        CqlValue::Int(self.to_owned())
    }
}

impl ToCqlVal for i64 {
    fn to_cql(&self) -> CqlValue {
        CqlValue::BigInt(self.to_owned())
    }
}

impl ToCqlVal for f32 {
    fn to_cql(&self) -> CqlValue {
        CqlValue::Float(self.to_owned())
    }
}

impl ToCqlVal for f64 {
    fn to_cql(&self) -> CqlValue {
        CqlValue::Double(self.to_owned())
    }
}

impl ToCqlVal for Vec<u8> {
    fn to_cql(&self) -> CqlValue {
        CqlValue::Blob(self.to_owned())
    }
}

impl ToCqlVal for CqlValue {
    fn to_cql(&self) -> CqlValue {
        self.to_owned()
    }
}

impl<T: ToCqlVal> ToCqlVal for Option<T> {
    fn to_cql(&self) -> CqlValue {
        match self {
            Some(v) => v.to_cql(),
            None => CqlValue::Empty,
        }
    }
}

impl<T: ToCqlVal> ToCqlVal for Vec<T> {
    fn to_cql(&self) -> CqlValue {
        let mut rt: Vec<CqlValue> = Vec::with_capacity(self.len());
        for item in self {
            rt.push(item.to_cql());
        }
        CqlValue::List(rt)
    }
}

impl<T: ToCqlVal> ToCqlVal for HashSet<T> {
    fn to_cql(&self) -> CqlValue {
        let mut rt: Vec<CqlValue> = Vec::with_capacity(self.len());
        for item in self {
            rt.push(item.to_cql());
        }
        CqlValue::Set(rt)
    }
}

impl<T: ToCqlVal> ToCqlVal for HashMap<String, T> {
    fn to_cql(&self) -> CqlValue {
        let mut rt: Vec<(CqlValue, CqlValue)> = Vec::with_capacity(self.len());
        for item in self {
            rt.push((item.0.to_cql(), item.1.to_cql()));
        }
        CqlValue::Map(rt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_cql_val_works() {
        assert_eq!(
            "hello".to_string().to_cql(),
            CqlValue::Text("hello".to_string())
        );
    }
}
