use axum_web::erring::HTTPError;
use scylla_orm::{ColumnsMap, ToCqlVal};
use scylla_orm_macros::CqlOrm;

use ns_protocol::state;

use crate::db::scylladb;

#[derive(Debug, Default, Clone, CqlOrm, PartialEq)]
pub struct ServiceProtocol {
    pub code: i64,
    pub version: i32,
    pub protocol: Vec<u8>,
    pub submitter: String,
    pub sequence: i64,

    pub _fields: Vec<String>, // selected fields，field with `_` will be ignored by CqlOrm
}

impl ServiceProtocol {
    pub fn with_pk(code: i64, version: i32) -> Self {
        Self {
            code,
            version,
            ..Default::default()
        }
    }

    pub fn from_index(value: &state::ServiceProtocol) -> anyhow::Result<Self> {
        let protocol = state::to_bytes(&value.protocol)?;
        Ok(Self {
            code: value.code as i64,
            version: value.version as i32,
            protocol,
            submitter: value.submitter.clone(),
            sequence: value.sequence as i64,
            _fields: Self::fields(),
        })
    }

    pub fn to_index(&self) -> anyhow::Result<state::ServiceProtocol> {
        let protocol = state::from_bytes(&self.protocol)?;
        Ok(state::ServiceProtocol {
            code: self.code as u64,
            version: self.version as u16,
            protocol,
            submitter: self.submitter.clone(),
            sequence: self.sequence as u64,
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

        let field = "submitter".to_string();
        if !select_fields.contains(&field) {
            select_fields.push(field);
        }
        let field = "sequence".to_string();
        if !select_fields.contains(&field) {
            select_fields.push(field);
        }

        if with_pk {
            let field = "code".to_string();
            if !select_fields.contains(&field) {
                select_fields.push(field);
            }
            let field = "version".to_string();
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
            "SELECT {} FROM service_protocol WHERE code=? AND version=? LIMIT 1",
            fields.join(",")
        );
        let params = (self.code.to_cql(), self.version.to_cql());
        let res = db.execute(query, params).await?.single_row()?;

        let mut cols = ColumnsMap::with_capacity(fields.len());
        cols.fill(res, &fields)?;
        self.fill(&cols);

        Ok(())
    }

    pub async fn get_latest(
        db: &scylladb::ScyllaDB,
        code: i64,
        select_fields: Vec<String>,
    ) -> anyhow::Result<Self> {
        let fields = Self::select_fields(select_fields, true)?;

        let query = format!(
            "SELECT {} FROM service_protocol WHERE code=? LIMIT 1",
            fields.join(",")
        );
        let params = (code.to_cql(),);
        let res = db.execute(query, params).await?.single_row()?;

        let mut cols = ColumnsMap::with_capacity(fields.len());
        cols.fill(res, &fields)?;
        let mut doc = Self::default();
        doc.fill(&cols);
        doc._fields = fields.clone();

        Ok(doc)
    }
}
