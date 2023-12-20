use axum::{
    extract::{Query, State},
    Extension,
};
use bitcoin::{Address, AddressType};
use std::{collections::BTreeMap, str::FromStr, sync::Arc};
use validator::Validate;

use axum_web::{
    context::ReqContext,
    erring::{HTTPError, SuccessResponse},
    object::PackObject,
};

use crate::api::{IndexerAPI, QueryAddress};
use crate::db;
use crate::utxo::UTXO;

pub struct UtxoAPI;

impl UtxoAPI {
    pub async fn list(
        State(app): State<Arc<IndexerAPI>>,
        Extension(ctx): Extension<Arc<ReqContext>>,
        to: PackObject<()>,
        input: Query<QueryAddress>,
    ) -> Result<PackObject<SuccessResponse<Vec<UTXO>>>, HTTPError> {
        input.validate()?;

        let address = Address::from_str(input.address.as_str())
            .map_err(|_| HTTPError::new(400, format!("invalid address: {}", input.address)))?
            .assume_checked();

        match address.address_type() {
            Some(AddressType::P2tr) | Some(AddressType::P2wpkh) => {}
            other => {
                return Err(HTTPError::new(
                    400,
                    format!("only support p2tr address, got: {:?}", other),
                ));
            }
        }

        ctx.set_kvs(vec![("action", "list_utxos_by_address".into())])
            .await;

        let address = address.script_pubkey().as_bytes().to_vec();
        let utxos = db::Utxo::list(&app.scylla, &address).await?;
        let mut utxos: BTreeMap<(&Vec<u8>, u32), UTXO> = utxos
            .iter()
            .map(|utxo| ((&utxo.txid, utxo.vout as u32), utxo.to_utxo()))
            .collect();

        let confirming_utxos = app.state.confirming_utxos.read().await;
        for utxo in confirming_utxos.iter() {
            for spent in &utxo.1 {
                utxos.remove(&(&spent.txid, spent.vout));
            }
            for (_, unspent) in &utxo.2 {
                utxos.insert((&unspent.txid, unspent.vout), unspent.clone());
            }
        }

        let mut utxos = utxos.into_values().collect::<Vec<_>>();
        utxos.sort_by(|a, b| a.amount.partial_cmp(&b.amount).unwrap());
        Ok(to.with(SuccessResponse::new(utxos)))
    }
}
