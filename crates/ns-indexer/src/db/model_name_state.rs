use ns_axum_web::erring::HTTPError;
use ns_scylla_orm::{ColumnsMap, CqlValue, ToCqlVal};
use ns_scylla_orm_macros::CqlOrm;
use std::collections::{BTreeMap, HashSet};

use ns_protocol::state;

use crate::db::scylladb;

#[derive(Debug, Default, Clone, CqlOrm, PartialEq)]
pub struct NameState {
    pub name: String,
    pub sequence: i64,
    pub block_height: i64,
    pub block_time: i64,
    pub threshold: i8,
    pub key_kind: i8,
    pub public_keys: Vec<Vec<u8>>,
    pub next_public_keys: Vec<Vec<u8>>,

    pub _fields: Vec<String>, // selected fields，field with `_` will be ignored by CqlOrm
}

#[derive(Debug, Default, Clone, CqlOrm, PartialEq)]
pub struct NameIndex {
    pub name: String,
    pub block_time: i64,

    pub _fields: Vec<String>,
}

#[derive(Debug, Default, Clone, CqlOrm, PartialEq)]
pub struct PubkeyName {
    pub pubkey: Vec<u8>,
    pub name: String,

    pub _fields: Vec<String>,
}

impl NameState {
    pub fn with_pk(name: String) -> Self {
        Self {
            name,
            ..Default::default()
        }
    }

    pub fn from_index(value: &state::NameState) -> anyhow::Result<Self> {
        Ok(Self {
            name: value.name.clone(),
            sequence: value.sequence as i64,
            block_height: value.block_height as i64,
            block_time: value.block_time as i64,
            threshold: value.threshold as i8,
            key_kind: value.key_kind as i8,
            public_keys: value.public_keys.clone(),
            next_public_keys: value.next_public_keys.as_ref().unwrap_or(&vec![]).clone(),
            _fields: Self::fields(),
        })
    }

    pub fn to_index(&self) -> anyhow::Result<state::NameState> {
        Ok(state::NameState {
            name: self.name.clone(),
            sequence: self.sequence as u64,
            block_height: self.block_height as u64,
            block_time: self.block_time as u64,
            threshold: self.threshold as u8,
            key_kind: self.key_kind as u8,
            public_keys: self.public_keys.clone(),
            next_public_keys: if self.next_public_keys.is_empty() {
                None
            } else {
                Some(self.next_public_keys.clone())
            },
        })
    }

    pub fn select_fields(select_fields: Vec<String>, with_pk: bool) -> anyhow::Result<Vec<String>> {
        if select_fields.is_empty() {
            return Ok(Self::fields());
        }

        let fields = Self::fields();
        let mut select_fields = select_fields;
        for field in &select_fields {
            if !fields.contains(field) {
                return Err(HTTPError::new(400, format!("Invalid field: {}", field)).into());
            }
        }

        let field = "sequence".to_string();
        if !select_fields.contains(&field) {
            select_fields.push(field);
        }
        let field = "block_time".to_string();
        if !select_fields.contains(&field) {
            select_fields.push(field);
        }

        if with_pk {
            let field = "name".to_string();
            if !select_fields.contains(&field) {
                select_fields.push(field);
            }
        }

        Ok(select_fields)
    }

    pub async fn get_one(
        &mut self,
        db: &scylladb::ScyllaDB,
        select_fields: Vec<String>,
    ) -> anyhow::Result<()> {
        let fields = Self::select_fields(select_fields, false)?;
        self._fields = fields.clone();

        let query = format!(
            "SELECT {} FROM name_state WHERE name=? LIMIT 1",
            fields.join(",")
        );
        let params = (self.name.to_cql(),);
        let res = db.execute(query, params).await?.single_row()?;

        let mut cols = ColumnsMap::with_capacity(fields.len());
        cols.fill(res, &fields)?;
        self.fill(&cols);

        Ok(())
    }

    pub async fn capture_name_with_public_keys(
        db: &scylladb::ScyllaDB,
        names: Vec<&String>,
    ) -> anyhow::Result<Vec<NameState>> {
        let fields = vec!["name".to_string(), "public_keys".to_string()];

        let mut output: Vec<NameState> = Vec::with_capacity(names.len());

        let mut start = 0;
        while start < names.len() {
            let end = if start + 100 > names.len() {
                names.len()
            } else {
                start + 100
            };

            let mut vals_name: Vec<&str> = Vec::with_capacity(end - start);
            let mut params: Vec<CqlValue> = Vec::with_capacity(end - start);
            for name in &names[start..end] {
                vals_name.push("?");
                params.push(name.to_cql());
            }

            let query = format!(
                "SELECT {} FROM name_state WHERE name IN ({})",
                fields.join(","),
                vals_name.join(",")
            );
            let res = db.execute(query, params).await?;
            let rows = res.rows.unwrap_or_default();
            for r in rows {
                let mut cols = ColumnsMap::with_capacity(2);
                cols.fill(r, &fields)?;
                let mut item = NameState::default();
                item.fill(&cols);
                output.push(item);
            }
            start = end;
        }

        Ok(output)
    }

    pub async fn batch_update_name_indexs(
        db: &scylladb::ScyllaDB,
        indexs: BTreeMap<String, u64>,
    ) -> anyhow::Result<()> {
        let mut statements: Vec<&str> = Vec::with_capacity(indexs.len());
        let mut values: Vec<(String, i64)> = Vec::with_capacity(indexs.len());

        // name_index
        let fields = vec!["name".to_string(), "block_time".to_string()];
        let mut cols: Vec<&str> = Vec::with_capacity(fields.len());
        let mut vals: Vec<&str> = Vec::with_capacity(fields.len());
        for field in &fields {
            cols.push(field);
            vals.push("?");
        }
        let query = format!(
            "INSERT INTO name_index ({}) VALUES ({})",
            cols.join(","),
            vals.join(",")
        );
        for state in indexs {
            statements.push(query.as_str());
            values.push((state.0, state.1 as i64));
        }
        let _ = db.batch(statements, values).await?;
        Ok(())
    }

    pub async fn batch_remove_pubkey_names(
        db: &scylladb::ScyllaDB,
        pubkey_names: HashSet<(Vec<u8>, String)>,
    ) -> anyhow::Result<()> {
        let mut statements: Vec<&str> = Vec::with_capacity(pubkey_names.len());
        let mut values: Vec<(Vec<u8>, String)> = Vec::with_capacity(pubkey_names.len());

        // pubkey_name
        let query = "DELETE FROM pubkey_name WHERE pubk=? AND name=?";
        for state in pubkey_names {
            statements.push(query);
            values.push((state.0, state.1));
        }
        let _ = db.batch(statements, values).await?;
        Ok(())
    }

    pub async fn batch_add_pubkey_names(
        db: &scylladb::ScyllaDB,
        pubkey_names: HashSet<(Vec<u8>, String)>,
    ) -> anyhow::Result<()> {
        let mut statements: Vec<&str> = Vec::with_capacity(pubkey_names.len());
        let mut values: Vec<(Vec<u8>, String)> = Vec::with_capacity(pubkey_names.len());

        // pubkey_name
        let fields = vec!["pubkey".to_string(), "name".to_string()];
        let mut cols: Vec<&str> = Vec::with_capacity(fields.len());
        let mut vals: Vec<&str> = Vec::with_capacity(fields.len());
        for field in &fields {
            cols.push(field);
            vals.push("?");
        }
        let query = format!(
            "INSERT INTO pubkey_name ({}) VALUES ({})",
            cols.join(","),
            vals.join(",")
        );
        for state in pubkey_names {
            statements.push(query.as_str());
            values.push((state.0, state.1));
        }
        let _ = db.batch(statements, values).await?;
        Ok(())
    }

    pub async fn list_by_query(db: &scylladb::ScyllaDB, q: String) -> anyhow::Result<Vec<String>> {
        let fields = NameIndex::fields();

        let query = format!(
            "SELECT {} FROM name_index WHERE name LIKE ? LIMIT 100 ALLOW FILTERING",
            fields.clone().join(",")
        );
        let params = (q + "%",);
        let rows = db.execute_iter(query, params).await?;

        let mut res: Vec<NameIndex> = Vec::with_capacity(rows.len());
        for row in rows {
            let mut doc = NameIndex::default();
            let mut cols = ColumnsMap::with_capacity(fields.len());
            cols.fill(row, &fields)?;
            doc.fill(&cols);
            res.push(doc);
        }

        res.sort_by(|a, b| b.block_time.partial_cmp(&a.block_time).unwrap());
        Ok(res.into_iter().map(|name| name.name).collect())
    }

    pub async fn list_by_pubkey(
        db: &scylladb::ScyllaDB,
        pubkey: Vec<u8>,
    ) -> anyhow::Result<Vec<String>> {
        let fields = vec!["name".to_string()];
        if pubkey.len() != 32 {
            return Ok(vec![]);
        }

        let query = "SELECT name FROM pubkey_name WHERE pubkey=?";
        let params = (pubkey,);
        let rows = db.execute_iter(query, params).await?;

        let mut res: Vec<PubkeyName> = Vec::with_capacity(rows.len());
        for row in rows {
            let mut doc = PubkeyName::default();
            let mut cols = ColumnsMap::with_capacity(fields.len());
            cols.fill(row, &fields)?;
            doc.fill(&cols);
            res.push(doc);
        }

        Ok(res.into_iter().map(|name| name.name).collect())
    }
}
