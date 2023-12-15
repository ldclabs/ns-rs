use bitcoin::{
    address::NetworkChecked,
    blockdata::{opcodes, script::PushBytesBuf},
    hashes::Hash,
    key::{
        constants::{SCHNORR_PUBLIC_KEY_SIZE, SCHNORR_SIGNATURE_SIZE},
        TapTweak, TweakedKeypair,
    },
    locktime::absolute::LockTime,
    secp256k1::{rand, All, Keypair, Message, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{
        LeafVersion, Signature, TapLeafHash, TaprootBuilder, TAPROOT_CONTROL_BASE_SIZE,
        TAPROOT_CONTROL_NODE_SIZE,
    },
    transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};

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
        unspent_txouts: &Vec<UnspentTxOut>,
        inscription_key_pair: Option<Keypair>, // safe to use one-time KeyPair
    ) -> anyhow::Result<Txid> {
        let keypair = Keypair::from_secret_key(&self.secp, secret);
        let (internal_key, _parity) = keypair.x_only_public_key();
        let script_pubkey = ScriptBuf::new_p2tr(&self.secp, internal_key, None);
        let address: Address<NetworkChecked> = Address::from_script(&script_pubkey, self.network)?;

        let (input, unsigned_commit_tx, signed_reveal_tx) = self
            .build_inscription_transactions(
                names,
                fee_rate,
                address,
                unspent_txouts,
                inscription_key_pair,
            )
            .await?;

        let mut signed_commit_tx = unsigned_commit_tx;
        // sigh commit_tx
        {
            let prevouts = vec![input];
            let mut sighasher = SighashCache::new(&mut signed_commit_tx);
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

            sighasher
                .witness_mut(0)
                .expect("getting mutable witness reference should work")
                .push(
                    &Signature {
                        sig,
                        hash_ty: TapSighashType::Default,
                    }
                    .to_vec(),
                );
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

        let commit = self.bitcoin.send_transaction(&signed_commit_tx).await?;
        let reveal = self.bitcoin.send_transaction(&signed_reveal_tx).await
        .map_err(|err| anyhow::anyhow!("failed to send reveal transaction: {err}\ncommit tx {commit} will be recovered once mined"
          ))?;

        Ok(reveal)
    }

    // return (to_spent_tx_out, unsigned_commit_tx, signed_reveal_tx)
    pub async fn build_inscription_transactions(
        &self,
        names: &Vec<Name>,
        fee_rate: Amount,
        unspent_address: Address<NetworkChecked>,
        unspent_txouts: &Vec<UnspentTxOut>,
        inscription_key_pair: Option<Keypair>,
    ) -> anyhow::Result<(TxOut, Transaction, Transaction)> {
        if names.is_empty() {
            anyhow::bail!("no names to inscribe");
        }
        if fee_rate.to_sat() == 0 {
            anyhow::bail!("fee rate cannot be zero");
        }
        if unspent_address.network() != &self.network {
            anyhow::bail!("unspent address is not on the same network as the inscriber");
        }
        if unspent_txouts.is_empty() {
            anyhow::bail!("no unspent transaction out");
        }

        for name in names {
            if let Err(err) = name.validate() {
                anyhow::bail!("invalid name {}: {}", name.name, err);
            }
        }

        let (_, _, p_value) = Inscriber::preview_inscription_transactions(names, fee_rate)?;
        let mut unspent_tx = &unspent_txouts[0];
        // select a befitting unspent transaction out
        for tx in unspent_txouts {
            if tx.amount > p_value && tx.amount < unspent_tx.amount {
                unspent_tx = &tx;
            }
        }

        let input = TxOut {
            value: unspent_tx.amount,
            script_pubkey: unspent_address.script_pubkey(),
        };

        let (unsigned_commit_tx, signed_reveal_tx) = self.create_inscription_transactions(
            names,
            fee_rate,
            input.clone(),
            OutPoint {
                txid: unspent_tx.txid,
                vout: unspent_tx.vout,
            },
            inscription_key_pair,
        )?;
        Ok((input, unsigned_commit_tx, signed_reveal_tx))
    }

    pub fn preview_inscription_transactions(
        names: &Vec<Name>,
        fee_rate: Amount,
    ) -> anyhow::Result<(Transaction, Transaction, Amount)> {
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
            Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
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
        input: TxOut,
        input_point: OutPoint,
        inscription_key_pair: Option<Keypair>,
    ) -> anyhow::Result<(Transaction, Transaction)> {
        // or use one-time KeyPair
        let key_pair = inscription_key_pair
            .unwrap_or_else(|| Keypair::new(&self.secp, &mut rand::thread_rng()));
        let (public_key, _parity) = key_pair.x_only_public_key();

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
                value: input.value,
                script_pubkey: input.script_pubkey.clone(),
            }],
        };

        let reveal_tx_fee = {
            let mut v_reveal_tx = reveal_tx.clone();
            let mut witness = Witness::default();
            witness.push(
                Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
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
                previous_output: input_point,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: input.value,
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
        let change_value = input
            .value
            .checked_sub(commit_tx_fee)
            .ok_or_else(|| anyhow::anyhow!("should compute commit_tx fee"))?;

        commit_tx.output[0].value = change_value;

        let change_value = input
            .value
            .checked_sub(reveal_tx_fee)
            .ok_or_else(|| anyhow::anyhow!("should compute commit_tx fee"))?;
        if change_value <= dust_value {
            anyhow::bail!("input value is too small");
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
                .sign_schnorr(&Message::from_digest(sighash.to_byte_array()), &key_pair);

            let witness = sighasher
                .witness_mut(0)
                .expect("getting mutable witness reference should work");
            witness.push(
                Signature {
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

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use serde_json::to_value;

    use ns_indexer::envelope::Envelope;
    use ns_protocol::ns::{Operation, PublicKeyParams, Service, ThresholdLevel, Value};

    fn get_name(name: &str) -> Name {
        let secret_key = hex!("7ef3811aabb916dc2f646ef1a371b90adec91bc07992cd4d44c156c42fc1b300");
        let public_key = hex!("ee90735ac719e85dc2f3e5974036387fdf478af7d9d1f8480e97eee601890266");
        let params = PublicKeyParams {
            public_keys: vec![public_key.to_vec()],
            threshold: Some(1),
            kind: None,
        };

        let mut name = Name {
            name: name.to_string(),
            sequence: 0,
            payload: Service {
                code: 0,
                operations: vec![Operation {
                    subcode: 1,
                    params: Value::from(&params),
                }],
                approver: None,
            },
            signatures: vec![],
        };
        name.sign(&params, ThresholdLevel::Default, &[secret_key.to_vec()])
            .unwrap();
        assert!(name.validate().is_ok());
        name
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
        dotenvy::from_filename(".env.sample").expect(".env file not found");

        let rpcurl = std::env::var("BITCOIN_RPC_URL").unwrap();
        let rpcuser = std::env::var("BITCOIN_RPC_USER").unwrap();
        let rpcpassword = std::env::var("BITCOIN_RPC_PASSWORD").unwrap();

        let secp = Secp256k1::new();
        let key_pair = Keypair::new(&secp, &mut rand::thread_rng());
        let (public_key, _parity) = key_pair.x_only_public_key();
        let script_pubkey = ScriptBuf::new_p2tr(&secp, public_key, None);
        let address: Address<NetworkChecked> =
            Address::from_script(&script_pubkey, Network::Regtest).unwrap();

        println!("address: {}", address);

        let inscriber = Inscriber::new(&InscriberOptions {
            bitcoin: BitCoinRPCOptions {
                rpcurl,
                rpcuser,
                rpcpassword,
                network: Network::Regtest,
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
            .inscribe(&names, fee_rate, &key_pair.secret_key(), &unspent_txs, None)
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
                &key_pair.secret_key(),
                &unspent_txs,
                Some(key_pair),
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
