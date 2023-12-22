use axum_web::erring::HTTPError;
use scylla_orm::{ColumnsMap, ToCqlVal};
use scylla_orm_macros::CqlOrm;

use ns_protocol::state;

use crate::db::scylladb;

#[derive(Debug, Default, Clone, CqlOrm, PartialEq)]
pub struct ServiceState {
    pub name: String,
    pub code: i64,
    pub sequence: i64,
    pub data: Vec<u8>,

    pub _fields: Vec<String>, // selected fields，field with `_` will be ignored by CqlOrm
}

impl ServiceState {
    pub fn with_pk(name: String, code: i64) -> Self {
        Self {
            name,
            code,
            ..Default::default()
        }
    }

    pub fn from_index(value: &state::ServiceState) -> anyhow::Result<Self> {
        let data = state::to_bytes(&value.data)?;
        Ok(Self {
            name: value.name.clone(),
            code: value.code as i64,
            sequence: value.sequence as i64,
            data,
            _fields: Self::fields(),
        })
    }

    pub fn to_index(&self) -> anyhow::Result<state::ServiceState> {
        let data = state::from_bytes(&self.data)?;
        Ok(state::ServiceState {
            name: self.name.clone(),
            code: self.code as u64,
            sequence: self.sequence as u64,
            data,
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

        if with_pk {
            let field = "name".to_string();
            if !select_fields.contains(&field) {
                select_fields.push(field);
            }
            let field = "code".to_string();
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
            "SELECT {} FROM service_state WHERE name=? AND code=? LIMIT 1",
            fields.join(",")
        );
        let params = (self.name.to_cql(), self.code.to_cql());
        let res = db.execute(query, params).await?.single_row()?;

        let mut cols = ColumnsMap::with_capacity(fields.len());
        cols.fill(res, &fields)?;
        self.fill(&cols);

        Ok(())
    }

    pub async fn list_by_name(
        db: &scylladb::ScyllaDB,
        name: &String,
        select_fields: Vec<String>,
    ) -> anyhow::Result<Vec<Self>> {
        let fields = Self::select_fields(select_fields, true)?;

        let query = format!(
            "SELECT {} FROM service_state WHERE name=? USING TIMEOUT 3s",
            fields.clone().join(",")
        );
        let params = (name.to_cql(),);
        let rows = db.execute_iter(query, params).await?;

        let mut res: Vec<Self> = Vec::with_capacity(rows.len());
        for row in rows {
            let mut doc = Self::default();
            let mut cols = ColumnsMap::with_capacity(fields.len());
            cols.fill(row, &fields)?;
            doc.fill(&cols);
            doc._fields = fields.clone();
            res.push(doc);
        }

        Ok(res)
    }
}
