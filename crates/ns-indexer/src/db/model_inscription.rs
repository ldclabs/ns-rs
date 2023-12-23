use ns_axum_web::erring::HTTPError;
use ns_scylla_orm::{ColumnsMap, CqlValue, ToCqlVal};
use ns_scylla_orm_macros::CqlOrm;

use ns_protocol::state;

use crate::db::{self, scylladb, scylladb::filter_single_row_err};

#[derive(Debug, Default, Clone, CqlOrm, PartialEq)]
pub struct Checkpoint {
    pub checkpoint: String,
    pub block_height: i64,
    pub height: i64,
    pub hash: Vec<u8>,
    pub name: String,
    pub sequence: i64,

    pub _fields: Vec<String>, // selected fields，field with `_` will be ignored by CqlOrm
}

#[derive(Debug, Default, Clone, CqlOrm, PartialEq)]
pub struct Inscription {
    pub name: String,
    pub sequence: i64,
    pub height: i64,
    pub previous_hash: Vec<u8>,
    pub name_hash: Vec<u8>,
    pub service_hash: Vec<u8>,
    pub protocol_hash: Vec<u8>,
    pub block_hash: Vec<u8>,
    pub block_height: i64,
    pub txid: Vec<u8>,
    pub vin: i8,
    pub data: Vec<u8>,

    pub _fields: Vec<String>, // selected fields，field with `_` will be ignored by CqlOrm
}

#[derive(Debug, Default, Clone, CqlOrm, PartialEq)]
pub struct InvalidInscription {
    pub name: String,
    pub block_height: i64,
    pub hash: Vec<u8>,
    pub reason: String,
    pub data: Vec<u8>,

    pub _fields: Vec<String>,
}

impl Checkpoint {
    const LAST_ACCEPTED: &'static str = "LastAccepted";
    const LAST_ACCEPTED_HEIGHT: &'static str = "LastAcceptedHeight";

    pub async fn get_last_accepted(db: &scylladb::ScyllaDB) -> anyhow::Result<Option<Self>> {
        let mut doc = Self {
            checkpoint: Self::LAST_ACCEPTED.to_string(),
            ..Default::default()
        };
        match doc.get_one(db).await {
            Ok(_) => Ok(Some(doc)),
            Err(err) => {
                if let Some(err) = filter_single_row_err(err) {
                    return Err(err);
                }
                Ok(None)
            }
        }
    }

    pub async fn get_last_accepted_height(db: &scylladb::ScyllaDB) -> anyhow::Result<Self> {
        let mut doc = Self {
            checkpoint: Self::LAST_ACCEPTED_HEIGHT.to_string(),
            ..Default::default()
        };
        match doc.get_one(db).await {
            Ok(_) => Ok(doc),
            Err(err) => {
                if let Some(err) = filter_single_row_err(err) {
                    return Err(err);
                }
                Ok(doc)
            }
        }
    }

    pub async fn save_last_accepted_height(
        db: &scylladb::ScyllaDB,
        height: u64,
    ) -> anyhow::Result<()> {
        let doc = Self {
            checkpoint: Self::LAST_ACCEPTED_HEIGHT.to_string(),
            block_height: height as i64,
            ..Default::default()
        };
        let fields = Checkpoint::fields();

        let mut cols_name: Vec<&str> = Vec::with_capacity(fields.len());
        let mut vals_name: Vec<&str> = Vec::with_capacity(fields.len());
        let mut params: Vec<CqlValue> = Vec::with_capacity(fields.len());
        let cols = doc.to();

        for field in &fields {
            cols_name.push(field);
            vals_name.push("?");
            params.push(cols.get(field).unwrap().to_owned());
        }

        let query = format!(
            "INSERT INTO checkpoint ({}) VALUES ({})",
            cols_name.join(","),
            vals_name.join(",")
        );
        db.execute(query, params).await?;
        Ok(())
    }

    async fn get_one(&mut self, db: &scylladb::ScyllaDB) -> anyhow::Result<()> {
        let fields = Self::fields();
        self._fields = fields.clone();

        let query = format!(
            "SELECT {} FROM checkpoint WHERE checkpoint=? LIMIT 1",
            fields.join(",")
        );
        let params = (self.checkpoint.to_cql(),);
        let res = db.execute(query, params).await?.single_row()?;

        let mut cols = ColumnsMap::with_capacity(fields.len());
        cols.fill(res, &fields)?;
        self.fill(&cols);

        Ok(())
    }
}

impl Inscription {
    pub fn with_pk(name: String, sequence: i64) -> Self {
        Self {
            name,
            sequence,
            ..Default::default()
        }
    }

    pub fn from_index(value: &state::Inscription) -> anyhow::Result<Self> {
        let data = state::to_bytes(&value.data)?;
        Ok(Self {
            name: value.name.clone(),
            sequence: value.sequence as i64,
            height: value.height as i64,
            previous_hash: value.previous_hash.clone(),
            name_hash: value.name_hash.clone(),
            service_hash: value.service_hash.clone(),
            protocol_hash: value.protocol_hash.as_ref().unwrap_or(&vec![]).clone(),
            block_hash: value.block_hash.clone(),
            block_height: value.block_height as i64,
            txid: value.txid.clone(),
            vin: value.vin as i8,
            data,
            _fields: Self::fields(),
        })
    }

    pub fn to_index(&self) -> anyhow::Result<state::Inscription> {
        let data = state::from_bytes(&self.data)?;
        Ok(state::Inscription {
            name: self.name.clone(),
            sequence: self.sequence as u64,
            height: self.height as u64,
            previous_hash: self.previous_hash.clone(),
            name_hash: self.name_hash.clone(),
            service_hash: self.service_hash.clone(),
            protocol_hash: if self.protocol_hash.is_empty() {
                None
            } else {
                Some(self.protocol_hash.clone())
            },
            block_hash: self.block_hash.clone(),
            block_height: self.block_height as u64,
            txid: self.txid.clone(),
            vin: self.vin as u8,
            data,
        })
    }

    pub fn to_checkpoint(&self, hash: Vec<u8>) -> anyhow::Result<Checkpoint> {
        Ok(Checkpoint {
            checkpoint: Checkpoint::LAST_ACCEPTED.to_string(),
            block_height: self.block_height,
            height: self.height,
            hash,
            name: self.name.clone(),
            sequence: self.sequence,
            _fields: Checkpoint::fields(),
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

        let field = "height".to_string();
        if !select_fields.contains(&field) {
            select_fields.push(field);
        }

        if with_pk {
            let field = "name".to_string();
            if !select_fields.contains(&field) {
                select_fields.push(field);
            }
            let field = "sequence".to_string();
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
            "SELECT {} FROM inscription WHERE name=? AND sequence=? LIMIT 1",
            fields.join(",")
        );
        let params = (self.name.to_cql(), self.sequence.to_cql());
        let res = db.execute(query, params).await?.single_row()?;

        let mut cols = ColumnsMap::with_capacity(fields.len());
        cols.fill(res, &fields)?;
        self.fill(&cols);

        Ok(())
    }

    // save inscriptions and states in a block to db
    pub async fn save_checkpoint(
        db: &scylladb::ScyllaDB,
        name_states: &Vec<state::NameState>,
        service_states: &Vec<state::ServiceState>,
        protocol_states: &Vec<state::ServiceProtocol>,
        inscriptions: &Vec<state::Inscription>,
    ) -> anyhow::Result<()> {
        let mut statements: Vec<&str> = Vec::with_capacity(1024);
        let mut values: Vec<Vec<CqlValue>> = Vec::with_capacity(1024);

        // name_states
        let name_state_fields = db::NameState::fields();
        let mut name_state_cols: Vec<&str> = Vec::with_capacity(name_state_fields.len());
        let mut name_state_vals: Vec<&str> = Vec::with_capacity(name_state_fields.len());
        for field in &name_state_fields {
            name_state_cols.push(field);
            name_state_vals.push("?");
        }
        let name_state_query = format!(
            "INSERT INTO name_state ({}) VALUES ({})",
            name_state_cols.join(","),
            name_state_vals.join(",")
        );
        for state in name_states {
            let mut params: Vec<CqlValue> = Vec::with_capacity(name_state_fields.len());
            let cols = db::NameState::from_index(state)?.to();

            for field in &name_state_fields {
                params.push(cols.get(field).unwrap().to_owned());
            }
            statements.push(name_state_query.as_str());
            values.push(params);
        }

        // service_states
        let service_state_fields = db::ServiceState::fields();
        let mut service_state_cols: Vec<&str> = Vec::with_capacity(service_state_fields.len());
        let mut service_state_vals: Vec<&str> = Vec::with_capacity(service_state_fields.len());
        for field in &service_state_fields {
            service_state_cols.push(field);
            service_state_vals.push("?");
        }
        let service_state_query = format!(
            "INSERT INTO service_state ({}) VALUES ({})",
            service_state_cols.join(","),
            service_state_vals.join(",")
        );
        for state in service_states {
            let mut params: Vec<CqlValue> = Vec::with_capacity(service_state_fields.len());
            let cols = db::ServiceState::from_index(state)?.to();

            for field in &service_state_fields {
                params.push(cols.get(field).unwrap().to_owned());
            }
            statements.push(service_state_query.as_str());
            values.push(params);
        }

        // protocol_states
        let protocol_state_fields = db::ServiceProtocol::fields();
        let mut protocol_state_cols: Vec<&str> = Vec::with_capacity(protocol_state_fields.len());
        let mut protocol_state_vals: Vec<&str> = Vec::with_capacity(protocol_state_fields.len());
        for field in &protocol_state_fields {
            protocol_state_cols.push(field);
            protocol_state_vals.push("?");
        }
        let protocol_state_query = format!(
            "INSERT INTO service_protocol ({}) VALUES ({})",
            protocol_state_cols.join(","),
            protocol_state_vals.join(",")
        );
        for state in protocol_states {
            let mut params: Vec<CqlValue> = Vec::with_capacity(protocol_state_fields.len());
            let cols = db::ServiceProtocol::from_index(state)?.to();

            for field in &protocol_state_fields {
                params.push(cols.get(field).unwrap().to_owned());
            }
            statements.push(protocol_state_query.as_str());
            values.push(params);
        }

        // inscriptions
        let inscription_fields = db::Inscription::fields();
        let mut inscription_cols: Vec<&str> = Vec::with_capacity(inscription_fields.len());
        let mut inscription_vals: Vec<&str> = Vec::with_capacity(inscription_fields.len());
        for field in &inscription_fields {
            inscription_cols.push(field);
            inscription_vals.push("?");
        }
        let inscription_query = format!(
            "INSERT INTO inscription ({}) VALUES ({})",
            inscription_cols.join(","),
            inscription_vals.join(",")
        );
        for state in inscriptions {
            let mut params: Vec<CqlValue> = Vec::with_capacity(inscription_fields.len());
            let cols = db::Inscription::from_index(state)?.to();

            for field in &inscription_fields {
                params.push(cols.get(field).unwrap().to_owned());
            }
            statements.push(inscription_query.as_str());
            values.push(params);
        }

        let last_inscription = inscriptions.last().expect("should get last inscription");
        let inscription = db::Inscription::from_index(last_inscription)?;
        let checkpoint = inscription.to_checkpoint(last_inscription.hash()?)?;
        let checkpoint_cols = checkpoint.to();

        let (checkpoint_query, checkpoint_params) = {
            let fields = Checkpoint::fields();

            let mut cols_name: Vec<&str> = Vec::with_capacity(fields.len());
            let mut vals_name: Vec<&str> = Vec::with_capacity(fields.len());
            let mut params: Vec<CqlValue> = Vec::with_capacity(fields.len());

            for field in &fields {
                cols_name.push(field);
                vals_name.push("?");
                params.push(checkpoint_cols.get(field).unwrap().to_owned());
            }

            (
                format!(
                    "INSERT INTO checkpoint ({}) VALUES ({})",
                    cols_name.join(","),
                    vals_name.join(",")
                ),
                params,
            )
        };
        statements.push(checkpoint_query.as_str());
        values.push(checkpoint_params);

        if statements.len() > 500 {
            log::info!(target: "ns-indexer",
                action = "save_checkpoint",
                statements = statements.len(),
                block_height = checkpoint.block_height,
                height = checkpoint.height;
                "",
            );
        }

        let mut start = 0;
        while start < statements.len() {
            let end = if start + 1000 > statements.len() {
                statements.len()
            } else {
                start + 1000
            };

            let _ = db
                .batch(statements[start..end].to_vec(), &values[start..end])
                .await?;
            start = end;
        }
        Ok(())
    }

    pub async fn get_by_height(
        db: &scylladb::ScyllaDB,
        height: i64,
        select_fields: Vec<String>,
    ) -> anyhow::Result<Self> {
        let fields = Self::select_fields(select_fields, true)?;

        let query = format!(
            "SELECT {} FROM inscription WHERE height=? LIMIT 1",
            fields.clone().join(",")
        );
        let params = (height,);
        let res = db.execute(query, params).await?.single_row()?;

        let mut cols = ColumnsMap::with_capacity(fields.len());
        cols.fill(res, &fields)?;
        let mut doc = Self::default();
        doc.fill(&cols);
        doc._fields = fields.clone();

        Ok(doc)
    }

    pub async fn list_by_block_height(
        db: &scylladb::ScyllaDB,
        height: i64,
        select_fields: Vec<String>,
    ) -> anyhow::Result<Vec<Self>> {
        let fields = Self::select_fields(select_fields, true)?;

        let query = format!(
            "SELECT {} FROM inscription WHERE block_height=?",
            fields.clone().join(",")
        );
        let params = (height,);
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

    pub async fn list_by_name(
        db: &scylladb::ScyllaDB,
        name: &String,
        select_fields: Vec<String>,
        page_size: u16,
        page_token: Option<i64>,
    ) -> anyhow::Result<Vec<Self>> {
        let fields = Self::select_fields(select_fields, true)?;

        let token = match page_token {
            Some(i) => i,
            None => i64::MAX,
        };

        let query = format!(
            "SELECT {} FROM inscription WHERE name=? AND sequence<? LIMIT ? USING TIMEOUT 3s",
            fields.clone().join(",")
        );
        let params = (name.to_cql(), token.to_cql(), page_size as i32);
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

impl InvalidInscription {
    pub fn from_index(value: &state::InvalidInscription) -> anyhow::Result<Self> {
        let data = state::to_bytes(&value.data)?;
        Ok(Self {
            name: value.name.clone(),
            block_height: value.block_height as i64,
            hash: value.hash.clone(),
            reason: value.reason.clone(),
            data,
            _fields: Self::fields(),
        })
    }

    pub fn to_index(&self) -> anyhow::Result<state::InvalidInscription> {
        let data = state::from_bytes(&self.data)?;
        Ok(state::InvalidInscription {
            name: self.name.clone(),
            block_height: self.block_height as u64,
            hash: self.hash.clone(),
            reason: self.reason.clone(),
            data,
        })
    }

    pub async fn save(&mut self, db: &scylladb::ScyllaDB) -> anyhow::Result<bool> {
        let fields = Self::fields();
        self._fields = fields.clone();

        let mut cols_name: Vec<&str> = Vec::with_capacity(fields.len());
        let mut vals_name: Vec<&str> = Vec::with_capacity(fields.len());
        let mut params: Vec<&CqlValue> = Vec::with_capacity(fields.len());
        let cols = self.to();

        for field in &fields {
            cols_name.push(field);
            vals_name.push("?");
            params.push(cols.get(field).unwrap());
        }

        let query = format!(
            "INSERT INTO invalid_inscription ({}) VALUES ({})",
            cols_name.join(","),
            vals_name.join(",")
        );

        let _ = db.execute(query, params).await?;
        Ok(true)
    }

    pub async fn list_by_name(db: &scylladb::ScyllaDB, name: &String) -> anyhow::Result<Vec<Self>> {
        let fields = Self::fields();

        let query = format!(
            "SELECT {} FROM invalid_inscription WHERE name=? USING TIMEOUT 3s",
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
