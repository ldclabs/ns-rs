use bitcoin::{hashes::Hash, Transaction};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
pub struct UTXO {
    pub txid: Vec<u8>,
    pub vout: u32,
    pub amount: u64, // 0 means the UTXO is spent
}

impl UTXO {
    // return (spent, unspent)
    pub fn from_transaction(tx: &Transaction) -> (Vec<Self>, Vec<(Vec<u8>, Self)>) {
        let txid = tx.txid().to_byte_array().to_vec();

        let spent: Vec<Self> = tx
            .input
            .iter()
            .map(|txin| UTXO {
                txid: txin.previous_output.txid.to_byte_array().into(),
                vout: txin.previous_output.vout,
                amount: 0,
            })
            .collect();

        let mut unspent: Vec<(Vec<u8>, Self)> = Vec::new();
        for (i, txout) in tx.output.iter().enumerate() {
            if txout.script_pubkey.is_p2tr() || txout.script_pubkey.is_p2wpkh() {
                unspent.push((
                    txout.script_pubkey.to_bytes(),
                    UTXO {
                        txid: txid.clone(),
                        vout: i as u32,
                        amount: txout.value.to_sat(),
                    },
                ));
            }
        }

        (spent, unspent)
    }
}
