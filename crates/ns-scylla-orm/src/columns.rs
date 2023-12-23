use scylla::frame::response::result::Row;
use std::collections::{hash_map::Iter, HashMap};

use crate::{CqlValue, FromCqlVal, ToCqlVal};

#[derive(Debug, Default, PartialEq)]
pub struct ColumnsMap(HashMap<String, CqlValue>);

impl ColumnsMap {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(HashMap::with_capacity(capacity))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn has(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    pub fn keys(&self) -> Vec<String> {
        self.0.keys().cloned().collect()
    }

    pub fn get(&self, key: &str) -> Option<&CqlValue> {
        match self.0.get(key) {
            Some(v) => Some(v),
            None => None,
        }
    }

    pub fn iter(&self) -> Iter<'_, String, CqlValue> {
        self.0.iter()
    }

    pub fn get_as<T: FromCqlVal<Option<CqlValue>>>(&self, key: &str) -> anyhow::Result<T> {
        match self.0.get(key) {
            Some(v) => T::from_cql(Some(v.clone())).map_err(anyhow::Error::new),
            None => T::from_cql(None).map_err(anyhow::Error::new),
        }
    }

    pub fn set_as<T: ToCqlVal>(&mut self, key: &str, val: &T) {
        self.0.insert(key.to_string(), val.to_cql());
    }

    pub fn append_map<T: ToCqlVal>(&mut self, map_name: &str, key: &str, val: T) {
        let mut map: HashMap<String, CqlValue> = self.get_as(map_name).unwrap_or_default();

        map.insert(key.to_string(), val.to_cql());
        self.0.insert(map_name.to_string(), map.to_cql());
    }

    pub fn fill(&mut self, row: Row, fields: &Vec<String>) -> anyhow::Result<()> {
        if row.columns.len() != fields.len() {
            return Err(anyhow::Error::msg(format!(
                "ColumnsMap::fill: row.columns.len({}) != fields.len({})",
                row.columns.len(),
                fields.len()
            )));
        }
        for (i, val) in row.columns.iter().enumerate() {
            if let Some(v) = val {
                self.0.insert(fields[i].to_owned(), v.to_owned());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{de::DeserializeOwned, Serialize};

    impl ColumnsMap {
        pub fn get_from_cbor<T: DeserializeOwned>(&self, key: &str) -> anyhow::Result<T> {
            let data = self.get_as::<Vec<u8>>(key)?;
            let val: T = ciborium::from_reader(&data[..])?;
            Ok(val)
        }

        pub fn set_in_cbor<T: ?Sized + Serialize>(
            &mut self,
            key: &str,
            val: &T,
        ) -> anyhow::Result<()> {
            let mut buf: Vec<u8> = Vec::new();
            ciborium::into_writer(val, &mut buf)?;
            self.0.insert(key.to_string(), CqlValue::Blob(buf));
            Ok(())
        }
    }

    #[test]
    fn columns_map_works() {
        let mut map = ColumnsMap::new();

        assert_eq!(map.len(), 0);
        assert!(!map.has("name"));
        assert_eq!(map.get("name"), None);
        assert!(map.get_as::<String>("name").is_err());

        map.set_as("name", &"jarvis".to_string());
        assert_eq!(map.len(), 1);
        assert!(map.has("name"));
        assert_eq!(map.get("name"), Some(&CqlValue::Text("jarvis".to_string())));
        assert_eq!(map.get_as::<String>("name").unwrap(), "jarvis".to_string());

        map.set_as("name", &"jarvis2".to_string());
        assert_eq!(map.len(), 1);
        assert!(map.has("name"));
        assert_eq!(
            map.get("name"),
            Some(&CqlValue::Text("jarvis2".to_string()))
        );
        assert_eq!(map.get_as::<String>("name").unwrap(), "jarvis2".to_string());

        assert!(!map.has("data"));
        assert_eq!(map.get("data"), None);
        assert!(map.get_as::<Vec<u8>>("data").is_err());
        assert_eq!(map.get_as::<Option<Vec<u8>>>("data").unwrap(), None);
        assert!(map.set_in_cbor("data", &vec![1i64, 2i64, 3i64]).is_ok()); // CBOR: 0x83010203
        assert!(map.has("data"));
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get_as::<Vec<u8>>("data").unwrap(),
            vec![0x83, 0x01, 0x02, 0x03],
        );
        assert_eq!(
            map.get_as::<Option<Vec<u8>>>("data").unwrap(),
            Some(vec![0x83, 0x01, 0x02, 0x03]),
        );
        assert!(map.get_as::<String>("data").is_err());

        let mut keys: Option<Vec<Vec<u8>>> = None;
        assert!(!map.has("data2"));
        assert_eq!(map.get("data2"), None);
        assert!(map.get_as::<Vec<Vec<u8>>>("data2").is_err());
        assert_eq!(map.get_as::<Option<Vec<Vec<u8>>>>("data2").unwrap(), None);
        map.set_as("data2", &keys);
        assert!(map.has("data2"));
        assert_eq!(map.len(), 3);
        assert!(map.get_as::<Vec<Vec<u8>>>("data2").is_err());
        assert_eq!(map.get_as::<Option<Vec<Vec<u8>>>>("data2").unwrap(), None);

        keys = Some(vec![vec![0x83, 0x01, 0x02, 0x03]]);
        map.set_as("data2", &keys);
        assert_eq!(map.get_as::<Option<Vec<Vec<u8>>>>("data2").unwrap(), keys);
        assert_eq!(map.get_as::<Vec<Vec<u8>>>("data2").unwrap(), keys.unwrap());

        let mut row: Row = Row {
            columns: Vec::new(),
        };

        let mut fields: Vec<String> = Vec::new();
        for (k, v) in map.iter() {
            fields.push(k.to_owned());
            row.columns.push(Some(v.to_owned()));
        }

        assert_eq!(fields.len(), 3);
        let mut map2 = ColumnsMap::new();
        assert!(map2
            .fill(
                Row {
                    columns: Vec::new(),
                },
                &fields
            )
            .is_err());
        assert_ne!(map2, map);

        assert!(map2.fill(row, &fields).is_ok());
        assert_eq!(map2, map);
    }
}
