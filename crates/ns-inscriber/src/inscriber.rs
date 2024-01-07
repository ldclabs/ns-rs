use bitcoin::{
    address::NetworkChecked,
    blockdata::{opcodes, script::PushBytesBuf},
    ecdsa,
    hashes::Hash,
    key::{
        constants::{SCHNORR_PUBLIC_KEY_SIZE, SCHNORR_SIGNATURE_SIZE},
        TapTweak, TweakedKeypair,
    },
    locktime::absolute::LockTime,
    secp256k1::{rand, All, Keypair, Message, Secp256k1, SecretKey},
    sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType},
    taproot::{
        self, LeafVersion, TapLeafHash, TaprootBuilder, TAPROOT_CONTROL_BASE_SIZE,
        TAPROOT_CONTROL_NODE_SIZE,
    },
    transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, str::FromStr};

use ns_protocol::ns::{Name, MAX_NAME_BYTES};

use crate::bitcoin::{BitCoinRPCOptions, BitcoinRPC};

pub struct InscriberOptions {
    pub bitcoin: BitCoinRPCOptions,
}

pub struct Inscriber {
    secp: Secp256k1<All>,
    pub bitcoin: BitcoinRPC,
    pub network: Network,
}

#[derive(Clone, PartialEq, Debug)]
pub struct UnspentTxOut {
    pub txid: Txid,
    pub vout: u32,
    pub amount: Amount,
    pub script_pubkey: ScriptBuf,
}

impl Inscriber {
    pub fn new(opts: &InscriberOptions) -> anyhow::Result<Self> {
        let secp = Secp256k1::new();

        Ok(Self {
            secp,
            bitcoin: BitcoinRPC::new(&opts.bitcoin)?,
            network: opts.bitcoin.network,
        })
    }

    pub async fn inscribe(
        &self,
        names: &Vec<Name>,
        fee_rate: Amount,
        secret: &SecretKey,
        unspent_txout: &UnspentTxOut,
    ) -> anyhow::Result<Txid> {
        let (signed_commit_tx, signed_reveal_tx) = self
            .build_signed_inscription(names, fee_rate, secret, unspent_txout)
            .await?;

        let commit = self.bitcoin.send_transaction(&signed_commit_tx).await?;
        let reveal = self
            .bitcoin
            .send_transaction(&signed_reveal_tx)
            .await
            .map_err(|err| {
                anyhow::anyhow!("failed to send reveal transaction: {err}\ncommit tx: {commit}")
            })?;

        Ok(reveal)
    }

    pub async fn build_signed_inscription(
        &self,
        names: &Vec<Name>,
        fee_rate: Amount,
        secret: &SecretKey,
        unspent_txout: &UnspentTxOut,
    ) -> anyhow::Result<(Transaction, Transaction)> {
        let keypair = Keypair::from_secret_key(&self.secp, secret);

        let (unsigned_commit_tx, signed_reveal_tx) = self
            .build_inscription_transactions(names, fee_rate, unspent_txout, Some(keypair))
            .await?;

        let mut signed_commit_tx = unsigned_commit_tx;
        // sigh commit_tx
        if unspent_txout.script_pubkey.is_p2tr() {
            let mut sighasher = SighashCache::new(&mut signed_commit_tx);
            let prevouts = vec![TxOut {
                value: unspent_txout.amount,
                script_pubkey: unspent_txout.script_pubkey.clone(),
            }];
            let sighash = sighasher
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )
                .expect("failed to construct sighash");

            let tweaked: TweakedKeypair = keypair.tap_tweak(&self.secp, None);
            let sig = self.secp.sign_schnorr(
                &Message::from_digest(sighash.to_byte_array()),
                &tweaked.to_inner(),
            );

            let signature = taproot::Signature {
                sig,
                hash_ty: TapSighashType::Default,
            };

            sighasher
                .witness_mut(0)
                .expect("getting mutable witness reference should work")
                .push(&signature.to_vec());
        } else if unspent_txout.script_pubkey.is_p2wpkh() {
            let mut sighasher = SighashCache::new(&mut signed_commit_tx);
            let sighash = sighasher
                .p2wpkh_signature_hash(
                    0,
                    &unspent_txout.script_pubkey,
                    unspent_txout.amount,
                    EcdsaSighashType::All,
                )
                .expect("failed to create sighash");

            let sig = self
                .secp
                .sign_ecdsa(&Message::from(sighash), &keypair.secret_key());
            let signature = ecdsa::Signature {
                sig,
                hash_ty: EcdsaSighashType::All,
            };
            signed_commit_tx.input[0].witness = Witness::p2wpkh(&signature, &keypair.public_key());
        } else {
            anyhow::bail!("unsupported script_pubkey");
        }

        let test_txs = self
            .bitcoin
            .test_mempool_accept(&[&signed_commit_tx, &signed_reveal_tx])
            .await?;
        for r in &test_txs {
            if !r.allowed {
                anyhow::bail!("failed to accept transaction: {:?}", &test_txs);
            }
        }

        Ok((signed_commit_tx, signed_reveal_tx))
    }

    pub async fn send_sats(
        &self,
        fee_rate: Amount,
        secret: &SecretKey,
        unspent_txout: &UnspentTxOut,
        to: &Address<NetworkChecked>,
        amount: Amount,
    ) -> anyhow::Result<Txid> {
        let keypair = Keypair::from_secret_key(&self.secp, secret);

        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: unspent_txout.txid,
                    vout: unspent_txout.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: amount,
                    script_pubkey: to.script_pubkey(),
                },
                TxOut {
                    // change
                    value: unspent_txout.amount, // will update later
                    script_pubkey: unspent_txout.script_pubkey.clone(),
                },
            ],
        };

        let fee = {
            let mut v_tx = tx.clone();
            v_tx.input[0].witness = Witness::from_slice(&[&[0; SCHNORR_SIGNATURE_SIZE]]);
            fee_rate
                .checked_mul(v_tx.vsize() as u64)
                .expect("should compute commit_tx fee")
        };

        let change_value = unspent_txout
            .amount
            .checked_sub(amount)
            .ok_or_else(|| anyhow::anyhow!("should compute amount"))?;
        if change_value > fee {
            tx.output[1].value = change_value - fee;
        } else {
            tx.output.pop(); // no change
        }

        if unspent_txout.script_pubkey.is_p2tr() {
            let mut sighasher = SighashCache::new(&mut tx);
            let prevouts = vec![TxOut {
                value: unspent_txout.amount,
                script_pubkey: unspent_txout.script_pubkey.clone(),
            }];
            let sighash = sighasher
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )
                .expect("failed to construct sighash");

            let tweaked: TweakedKeypair = keypair.tap_tweak(&self.secp, None);
            let sig = self.secp.sign_schnorr(
                &Message::from_digest(sighash.to_byte_array()),
                &tweaked.to_inner(),
            );

            let signature = taproot::Signature {
                sig,
                hash_ty: TapSighashType::Default,
            };

            sighasher
                .witness_mut(0)
                .expect("getting mutable witness reference should work")
                .push(&signature.to_vec());
        } else if unspent_txout.script_pubkey.is_p2wpkh() {
            let mut sighasher = SighashCache::new(&mut tx);
            let sighash = sighasher
                .p2wpkh_signature_hash(
                    0,
                    &unspent_txout.script_pubkey,
                    unspent_txout.amount,
                    EcdsaSighashType::All,
                )
                .expect("failed to create sighash");

            let sig = self
                .secp
                .sign_ecdsa(&Message::from(sighash), &keypair.secret_key());
            let signature = ecdsa::Signature {
                sig,
                hash_ty: EcdsaSighashType::All,
            };
            tx.input[0].witness = Witness::p2wpkh(&signature, &keypair.public_key());
        } else {
            anyhow::bail!("unsupported script_pubkey");
        }

        let test_txs = self.bitcoin.test_mempool_accept(&[&tx]).await?;
        for r in &test_txs {
            if !r.allowed {
                anyhow::bail!("failed to accept transaction: {:?}", &test_txs);
            }
        }

        let txid = self.bitcoin.send_transaction(&tx).await?;
        Ok(txid)
    }

    pub async fn collect_sats(
        &self,
        fee_rate: Amount,
        unspent_txouts: &[(SecretKey, UnspentTxOut)],
        to: &Address<NetworkChecked>,
    ) -> anyhow::Result<Txid> {
        let amount = unspent_txouts.iter().map(|(_, v)| v.amount).sum::<Amount>();

        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: unspent_txouts
                .iter()
                .map(|(_, v)| TxIn {
                    previous_output: OutPoint {
                        txid: v.txid,
                        vout: v.vout,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: amount,
                script_pubkey: to.script_pubkey(),
            }],
        };

        let fee = {
            let mut v_tx = tx.clone();
            for input in v_tx.input.iter_mut() {
                input.witness = Witness::from_slice(&[&[0; SCHNORR_SIGNATURE_SIZE]]);
            }
            fee_rate
                .checked_mul(v_tx.vsize() as u64)
                .expect("should compute commit_tx fee")
        };

        let change_value = amount
            .checked_sub(fee)
            .ok_or_else(|| anyhow::anyhow!("should compute change value"))?;
        tx.output[0].value = change_value;

        let mut sighasher = SighashCache::new(&mut tx);

        for (i, (secret, unspent_txout)) in unspent_txouts.iter().enumerate() {
            let keypair = Keypair::from_secret_key(&self.secp, secret);

            if unspent_txout.script_pubkey.is_p2tr() {
                let tweaked: TweakedKeypair = keypair.tap_tweak(&self.secp, None);
                let sighash = sighasher
                    .taproot_key_spend_signature_hash(
                        0,
                        &Prevouts::All(&[TxOut {
                            value: unspent_txout.amount,
                            script_pubkey: unspent_txout.script_pubkey.clone(),
                        }]),
                        TapSighashType::Default,
                    )
                    .expect("failed to construct sighash");

                let sig = self.secp.sign_schnorr(
                    &Message::from_digest(sighash.to_byte_array()),
                    &tweaked.to_inner(),
                );

                let signature = taproot::Signature {
                    sig,
                    hash_ty: TapSighashType::Default,
                };

                sighasher
                    .witness_mut(i)
                    .expect("getting mutable witness reference should work")
                    .push(&signature.to_vec());
            } else if unspent_txout.script_pubkey.is_p2wpkh() {
                let sighash = sighasher
                    .p2wpkh_signature_hash(
                        0,
                        &unspent_txout.script_pubkey,
                        unspent_txout.amount,
                        EcdsaSighashType::All,
                    )
                    .expect("failed to create sighash");

                let sig = self
                    .secp
                    .sign_ecdsa(&Message::from(sighash), &keypair.secret_key());
                let signature = ecdsa::Signature {
                    sig,
                    hash_ty: EcdsaSighashType::All,
                };
                *sighasher
                    .witness_mut(i)
                    .expect("getting mutable witness reference should work") =
                    Witness::p2wpkh(&signature, &keypair.public_key());
            } else {
                anyhow::bail!("unsupported script_pubkey");
            }
        }

        let test_txs = self.bitcoin.test_mempool_accept(&[&tx]).await?;
        for r in &test_txs {
            if !r.allowed {
                anyhow::bail!("failed to accept transaction: {:?}", &test_txs);
            }
        }

        let txid = self.bitcoin.send_transaction(&tx).await?;
        Ok(txid)
    }

    // return (to_spent_tx_out, unsigned_commit_tx, signed_reveal_tx)
    pub async fn build_inscription_transactions(
        &self,
        names: &Vec<Name>,
        fee_rate: Amount,
        unspent_txout: &UnspentTxOut,
        inscription_keypair: Option<Keypair>,
    ) -> anyhow::Result<(Transaction, Transaction)> {
        if names.is_empty() {
            anyhow::bail!("no names to inscribe");
        }
        if fee_rate.to_sat() == 0 {
            anyhow::bail!("fee rate cannot be zero");
        }

        if let Some(name) = check_duplicate(names) {
            anyhow::bail!("duplicate name {}", name);
        }

        for name in names {
            if let Err(err) = name.validate() {
                anyhow::bail!("invalid name {}: {}", name.name, err);
            }
        }

        let keypair = inscription_keypair
            .unwrap_or_else(|| Keypair::new(&self.secp, &mut rand::thread_rng()));

        let (unsigned_commit_tx, signed_reveal_tx) =
            self.create_inscription_transactions(names, fee_rate, unspent_txout, &keypair)?;
        Ok((unsigned_commit_tx, signed_reveal_tx))
    }

    pub fn preview_inscription_transactions(
        names: &Vec<Name>,
        fee_rate: Amount,
    ) -> anyhow::Result<(Transaction, Transaction, Amount)> {
        if let Some(name) = check_duplicate(names) {
            anyhow::bail!("duplicate name {}", name);
        }

        let mut reveal_script = ScriptBuf::builder()
            .push_slice([0; SCHNORR_PUBLIC_KEY_SIZE])
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .push_opcode(opcodes::OP_FALSE)
            .push_opcode(opcodes::all::OP_IF);
        for name in names {
            let data = name.to_bytes()?;
            if data.len() > MAX_NAME_BYTES {
                anyhow::bail!("name {} is too large", name.name);
            }
            reveal_script = reveal_script.push_slice(PushBytesBuf::try_from(data)?);
        }
        let reveal_script = reveal_script
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script();

        let dust_value = reveal_script.dust_value();
        let dust_value = fee_rate
            .checked_mul(42)
            .expect("should compute amount")
            .checked_add(dust_value)
            .expect("should compute amount");

        let mut witness = Witness::default();
        witness.push(
            taproot::Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
                .unwrap()
                .to_vec(),
        );
        witness.push(reveal_script);
        witness.push([0; TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE]);
        let script_pubkey = ScriptBuf::from_bytes([0; SCHNORR_PUBLIC_KEY_SIZE].to_vec());
        let p_reveal_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::default(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness,
            }],
            output: vec![TxOut {
                value: dust_value,
                script_pubkey: script_pubkey.clone(),
            }],
        };

        let reveal_tx_fee = fee_rate
            .checked_mul(p_reveal_tx.vsize() as u64)
            .expect("should compute reveal_tx fee");
        let total_value = reveal_tx_fee
            .checked_add(dust_value)
            .expect("should compute amount");

        let p_commit_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::from_slice(&[&[0; SCHNORR_SIGNATURE_SIZE]]),
            }],
            output: vec![TxOut {
                value: total_value,
                script_pubkey: script_pubkey.clone(),
            }],
        };
        let total_value = fee_rate
            .checked_mul(p_commit_tx.vsize() as u64)
            .expect("should compute amount")
            .checked_add(total_value)
            .expect("should compute amount");

        Ok((p_commit_tx, p_reveal_tx, total_value))
    }

    // return (unsigned_commit_tx, signed_reveal_tx)
    fn create_inscription_transactions(
        &self,
        names: &Vec<Name>,
        fee_rate: Amount,
        unspent_txout: &UnspentTxOut,
        keypair: &Keypair,
    ) -> anyhow::Result<(Transaction, Transaction)> {
        // or use one-time KeyPair

        let (public_key, _parity) = keypair.x_only_public_key();

        let mut reveal_script = ScriptBuf::builder()
            .push_slice(public_key.serialize())
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .push_opcode(opcodes::OP_FALSE)
            .push_opcode(opcodes::all::OP_IF);
        for name in names {
            let data = name.to_bytes()?;
            if data.len() > MAX_NAME_BYTES {
                anyhow::bail!("name {} is too large", name.name);
            }
            reveal_script = reveal_script.push_slice(PushBytesBuf::try_from(data)?);
        }
        let reveal_script = reveal_script
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script();

        let dust_value = reveal_script.dust_value();

        let taproot_spend_info = TaprootBuilder::new()
            .add_leaf(0, reveal_script.clone())
            .expect("adding leaf should work")
            .finalize(&self.secp, public_key)
            .expect("finalizing taproot builder should work");

        let control_block = taproot_spend_info
            .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
            .expect("should compute control block");
        let control_block_bytes = &control_block.serialize();

        let commit_tx_address =
            Address::p2tr_tweaked(taproot_spend_info.output_key(), self.network);

        let mut reveal_tx = Transaction {
            version: Version::TWO,     // Post BIP-68.
            lock_time: LockTime::ZERO, // Ignore the locktime.
            input: vec![TxIn {
                previous_output: OutPoint::null(), // Filled in after signing.
                script_sig: ScriptBuf::default(),  // For a p2tr script_sig is empty.
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(), // Filled in after signing.
            }],
            output: vec![TxOut {
                value: unspent_txout.amount,
                script_pubkey: unspent_txout.script_pubkey.clone(),
            }],
        };

        let reveal_tx_fee = {
            let mut v_reveal_tx = reveal_tx.clone();
            let mut witness = Witness::default();
            witness.push(
                taproot::Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
                    .unwrap()
                    .to_vec(),
            );
            witness.push(reveal_script.clone());
            witness.push(control_block_bytes);
            v_reveal_tx.input[0].witness = witness;
            fee_rate
                .checked_mul(v_reveal_tx.vsize() as u64)
                .expect("should compute reveal_tx fee")
        };

        let mut commit_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: unspent_txout.txid,
                    vout: unspent_txout.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: unspent_txout.amount,
                script_pubkey: commit_tx_address.script_pubkey(),
            }],
        };

        let commit_tx_fee = {
            let mut v_commit_tx = commit_tx.clone();
            v_commit_tx.input[0].witness = Witness::from_slice(&[&[0; SCHNORR_SIGNATURE_SIZE]]);
            fee_rate
                .checked_mul(v_commit_tx.vsize() as u64)
                .expect("should compute commit_tx fee")
        };
        let change_value = unspent_txout
            .amount
            .checked_sub(commit_tx_fee)
            .ok_or_else(|| anyhow::anyhow!("should compute commit_tx fee"))?;

        commit_tx.output[0].value = change_value;

        let change_value = change_value
            .checked_sub(reveal_tx_fee)
            .ok_or_else(|| anyhow::anyhow!("should compute reveal_tx fee"))?;
        if change_value < dust_value {
            anyhow::bail!(
                "input value is too small, need another {} sats",
                dust_value - change_value
            );
        }

        reveal_tx.output[0].value = change_value;
        reveal_tx.input[0].previous_output = OutPoint {
            txid: commit_tx.txid(),
            vout: 0,
        };

        // sigh reveal_tx
        {
            let mut sighasher = SighashCache::new(&mut reveal_tx);
            let prevouts = vec![commit_tx.output[0].clone()];
            let sighash = sighasher
                .taproot_script_spend_signature_hash(
                    0,
                    &Prevouts::All(&prevouts),
                    TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
                    TapSighashType::Default,
                )
                .expect("failed to construct sighash");

            let sig = self
                .secp
                .sign_schnorr(&Message::from_digest(sighash.to_byte_array()), keypair);

            let witness = sighasher
                .witness_mut(0)
                .expect("getting mutable witness reference should work");
            witness.push(
                taproot::Signature {
                    sig,
                    hash_ty: TapSighashType::Default,
                }
                .to_vec(),
            );
            witness.push(reveal_script);
            witness.push(control_block_bytes);
        }

        Ok((commit_tx, reveal_tx))
    }
}

pub fn check_duplicate(names: &Vec<Name>) -> Option<String> {
    let mut set: HashSet<String> = HashSet::new();
    for name in names {
        if set.contains(&name.name) {
            return Some(name.name.clone());
        }
        set.insert(name.name.clone());
    }
    None
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct UnspentTxOutJSON {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: String,
}

impl UnspentTxOutJSON {
    pub fn to(&self) -> anyhow::Result<UnspentTxOut> {
        Ok(UnspentTxOut {
            txid: Txid::from_str(&self.txid)?,
            vout: self.vout,
            amount: Amount::from_sat(self.amount),
            script_pubkey: ScriptBuf::from_hex(&self.script_pubkey)?,
        })
    }

    pub fn from(tx: UnspentTxOut) -> Self {
        Self {
            txid: tx.txid.to_string(),
            vout: tx.vout,
            amount: tx.amount.to_sat(),
            script_pubkey: tx.script_pubkey.to_hex_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use serde_json::to_value;

    use ns_indexer::envelope::Envelope;
    use ns_protocol::{
        ed25519,
        ns::{Bytes32, Operation, PublicKeyParams, Service, ThresholdLevel, Value},
    };

    fn get_name(name: &str) -> Name {
        let secret_key = Bytes32(hex!(
            "7ef3811aabb916dc2f646ef1a371b90adec91bc07992cd4d44c156c42fc1b300"
        ));
        let public_key = Bytes32(hex!(
            "ee90735ac719e85dc2f3e5974036387fdf478af7d9d1f8480e97eee601890266"
        ));
        let params = PublicKeyParams {
            public_keys: vec![public_key],
            threshold: Some(1),
            kind: None,
        };

        let signer = ed25519::SigningKey::from_bytes(&secret_key.0);
        let signers = vec![signer];

        let mut name = Name {
            name: name.to_string(),
            sequence: 0,
            service: Service {
                code: 0,
                operations: vec![Operation {
                    subcode: 1,
                    params: Value::from(&params),
                }],
                approver: None,
            },
            signatures: vec![],
        };
        name.sign(&params, ThresholdLevel::Default, &signers)
            .unwrap();
        assert!(name.validate().is_ok());
        name
    }

    #[test]
    fn unspent_txout_json_works() {
        let json_str = serde_json::json!({
            "txid": "8e9d3e0d762c1d2348a2ca046b36f8de001f740c976b09c046ee1f09a8680131",
            "vout": 0,
            "amount": 4929400,
            "script_pubkey": "0014d37960b3783772f0b6e5a0917f163fa642b3a7fc"
        });
        let json: UnspentTxOutJSON = serde_json::from_value(json_str).unwrap();
        let tx = json.to().unwrap();
        let json2 = UnspentTxOutJSON::from(tx);
        assert_eq!(json, json2)
    }

    #[test]
    fn preview_inscription_transactions_works() {
        let names = vec![get_name("0"), get_name("a")];
        let fee_rate = Amount::from_sat(10);
        let (commit_tx, reveal_tx, total_value) =
            Inscriber::preview_inscription_transactions(&names, fee_rate).unwrap();

        assert!(fee_rate.checked_mul(commit_tx.vsize() as u64).unwrap() > Amount::from_sat(0));
        assert!(fee_rate.checked_mul(reveal_tx.vsize() as u64).unwrap() > Amount::from_sat(0));
        assert!(total_value > Amount::from_sat(0));

        let envelopes = Envelope::from_transaction(&commit_tx);
        assert!(envelopes.is_empty());

        let envelopes = Envelope::from_transaction(&reveal_tx);

        assert_eq!(1, envelopes.len());
        assert_eq!(reveal_tx.txid(), envelopes[0].txid);
        assert_eq!(0, envelopes[0].vin);
        assert_eq!(names, envelopes[0].payload);
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore]
    async fn inscriber_works() {
        dotenvy::from_filename("sample.env").expect(".env file not found");

        let rpcurl = std::env::var("BITCOIN_RPC_URL").unwrap();
        let rpcuser = std::env::var("BITCOIN_RPC_USER").unwrap_or_default();
        let rpcpassword = std::env::var("BITCOIN_RPC_PASSWORD").unwrap_or_default();
        let rpctoken = std::env::var("BITCOIN_RPC_TOKEN").unwrap_or_default();
        let network = Network::from_core_arg(&std::env::var("BITCOIN_NETWORK").unwrap_or_default())
            .unwrap_or(Network::Regtest);

        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut rand::thread_rng());
        let (public_key, _parity) = keypair.x_only_public_key();
        let script_pubkey = ScriptBuf::new_p2tr(&secp, public_key, None);
        let address: Address<NetworkChecked> =
            Address::from_script(&script_pubkey, network).unwrap();

        println!("rpcurl: {}, network: {}", rpcurl, network);
        println!("address: {}", address);

        let inscriber = Inscriber::new(&InscriberOptions {
            bitcoin: BitCoinRPCOptions {
                rpcurl,
                rpcuser,
                rpcpassword,
                rpctoken,
                network,
            },
        })
        .unwrap();

        inscriber.bitcoin.ping().await.unwrap();

        // wallet
        // bitcoind -regtest -txindex -rpcuser=test -rpcpassword=123456 -fallbackfee=0.00001
        let _ = inscriber
            .bitcoin
            .call::<serde_json::Value>("createwallet", &["testwallet".into()])
            .await;
        let _ = inscriber
            .bitcoin
            .call::<serde_json::Value>("loadwallet", &["testwallet".into()])
            .await;
        let _ = inscriber
            .bitcoin
            .call::<serde_json::Value>(
                "generatetoaddress",
                &[1.into(), to_value(&address).unwrap()],
            )
            .await
            .unwrap();
        let txid: Txid = inscriber
            .bitcoin
            .call("sendtoaddress", &[to_value(&address).unwrap(), 1.into()])
            .await
            .unwrap();

        // load unspent from wallet
        let tx = inscriber.bitcoin.get_transaction(&txid).await.unwrap();
        println!("tx: {:?}", tx);

        let unspent_txs = tx
            .output
            .iter()
            .enumerate()
            .filter_map(|(i, v)| {
                if v.script_pubkey == address.script_pubkey() {
                    Some(UnspentTxOut {
                        txid: tx.txid(),
                        vout: i as u32,
                        amount: v.value,
                        script_pubkey: v.script_pubkey.clone(),
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        println!("unspent_txs: {:#?}", unspent_txs);

        let names = vec![get_name("0")];
        let fee_rate = Amount::from_sat(20);
        let txid = inscriber
            .inscribe(
                &names,
                fee_rate,
                &keypair.secret_key(),
                unspent_txs.first().unwrap(),
            )
            .await
            .unwrap();
        println!("txid: {}", txid);

        // load inscription tx
        let tx = inscriber.bitcoin.get_transaction(&txid).await.unwrap();
        println!("tx: {:?}", tx);

        let envelopes = Envelope::from_transaction(&tx);
        assert_eq!(1, envelopes.len());
        assert_eq!(txid, envelopes[0].txid);
        assert_eq!(0, envelopes[0].vin);
        assert_eq!(names, envelopes[0].payload);

        // trigger block building
        let _ = inscriber
            .bitcoin
            .call::<serde_json::Value>(
                "generatetoaddress",
                &[1.into(), to_value(&address).unwrap()],
            )
            .await
            .unwrap();

        let tx_info = inscriber.bitcoin.get_transaction_info(&txid).await.unwrap();
        println!("tx_info: {:?}", tx_info);
        assert!(tx_info.blockhash.is_some());

        // inscribe from previous inscription tx
        let unspent_txs = tx
            .output
            .iter()
            .enumerate()
            .filter_map(|(i, v)| {
                if v.script_pubkey == address.script_pubkey() {
                    Some(UnspentTxOut {
                        txid: tx.txid(),
                        vout: i as u32,
                        amount: v.value,
                        script_pubkey: v.script_pubkey.clone(),
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        println!("unspent_txs: {:#?}", unspent_txs);

        let names = "0123456789abcdefghijklmnopqrstuvwxyz"
            .split("")
            .skip(1)
            .take(36)
            .map(get_name)
            .collect::<Vec<_>>();
        assert_eq!(36, names.len());
        assert_eq!("0", names[0].name);
        assert_eq!("z", names[35].name);

        let txid = inscriber
            .inscribe(
                &names,
                fee_rate,
                &keypair.secret_key(),
                unspent_txs.first().unwrap(),
            )
            .await
            .unwrap();
        println!("txid: {}", txid);

        // trigger block building
        let _ = inscriber
            .bitcoin
            .call::<serde_json::Value>(
                "generatetoaddress",
                &[1.into(), to_value(&address).unwrap()],
            )
            .await
            .unwrap();

        let tx_info = inscriber.bitcoin.get_transaction_info(&txid).await.unwrap();
        assert!(tx_info.blockhash.is_some());
    }
}
