use std::vec;

use ns_scylla_orm::{ColumnsMap, CqlValue, ToCqlVal};
use ns_scylla_orm_macros::CqlOrm;

use crate::db::scylladb;
use crate::utxo;

#[derive(Debug, Default, Clone, CqlOrm, PartialEq)]
pub struct Utxo {
    pub txid: Vec<u8>,
    pub vout: i32,
    pub amount: i64,
    pub address: Vec<u8>,

    pub _fields: Vec<String>, // selected fields，field with `_` will be ignored by CqlOrm
}

impl Utxo {
    pub fn from_utxo(address: Vec<u8>, value: &utxo::UTXO) -> Self {
        Self {
            txid: value.txid.clone(),
            vout: value.vout as i32,
            amount: value.amount as i64,
            address,
            _fields: vec![],
        }
    }

    pub fn to_utxo(&self) -> utxo::UTXO {
        utxo::UTXO {
            txid: self.txid.clone(),
            vout: self.vout as u32,
            amount: self.amount as u64,
        }
    }

    pub async fn handle_utxo(
        db: &scylladb::ScyllaDB,
        spent: &Vec<utxo::UTXO>,
        unspent: &Vec<(Vec<u8>, utxo::UTXO)>,
    ) -> anyhow::Result<()> {
        let mut start = 0;
        while start < unspent.len() {
            let end = if start + 1000 > unspent.len() {
                unspent.len()
            } else {
                start + 1000
            };
            let mut statements: Vec<&str> = Vec::with_capacity(unspent.len());
            let mut values: Vec<Vec<CqlValue>> = Vec::with_capacity(unspent.len());
            let query = "INSERT INTO utxo (txid,vout,amount,address) VALUES (?,?,?,?)";

            for tx in &unspent[start..end] {
                statements.push(query);
                let tx = Self::from_utxo(tx.0.clone(), &tx.1);
                values.push(vec![
                    tx.txid.to_cql(),
                    tx.vout.to_cql(),
                    tx.amount.to_cql(),
                    tx.address.to_cql(),
                ]);
            }

            if statements.len() > 500 {
                log::info!(target: "ns-indexer",
                    action = "handle_unspent_utxos",
                    statements = statements.len();
                    "",
                );
            }

            let _ = db
                .batch(scylladb::BatchType::Unlogged, statements, values)
                .await?;
            start = end;
        }

        // delete spent utxos after insert unspent utxos
        let mut start = 0;
        while start < spent.len() {
            let end = if start + 1000 > spent.len() {
                spent.len()
            } else {
                start + 1000
            };
            let mut statements: Vec<&str> = Vec::with_capacity(end - start);
            let mut values: Vec<Vec<CqlValue>> = Vec::with_capacity(end - start);
            let query = "DELETE FROM utxo WHERE txid=? AND vout=?";

            for tx in &spent[start..end] {
                statements.push(query);
                values.push(vec![tx.txid.to_cql(), (tx.vout as i32).to_cql()]);
            }

            if statements.len() > 500 {
                log::info!(target: "ns-indexer",
                    action = "handle_spent_utxos",
                    statements = statements.len();
                    "",
                );
            }

            let _ = db
                .batch(scylladb::BatchType::Unlogged, statements, values)
                .await?;
            start = end;
        }

        Ok(())
    }

    pub async fn list(db: &scylladb::ScyllaDB, address: &Vec<u8>) -> anyhow::Result<Vec<Self>> {
        let fields = Self::fields();

        let query = format!(
            "SELECT {} FROM utxo WHERE address=? USING TIMEOUT 3s",
            fields.clone().join(",")
        );
        let params = (address.to_cql(),);
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
