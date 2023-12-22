use bitcoin::{
    blockdata::{
        opcodes,
        script::Instruction::{Op, PushBytes},
    },
    hash_types::Txid,
    Transaction, Witness,
};

use ns_protocol::ns::Name;

#[derive(Clone, PartialEq, Debug)]
pub struct Envelope {
    pub txid: Txid,
    pub vin: u8,
    pub payload: Vec<Name>,
}

impl Envelope {
    pub fn from_transaction(transaction: &Transaction) -> Vec<Self> {
        let mut envelopes = Vec::new();
        let txid = transaction.txid();

        for (i, input) in transaction.input.iter().take(i8::MAX as usize).enumerate() {
            if let Ok(names) = Self::from_witness(&input.witness) {
                if !names.is_empty() {
                    envelopes.push(Envelope {
                        txid,
                        vin: i as u8,
                        payload: names,
                    });
                }
            }
        }

        envelopes
    }

    fn from_witness(witness: &Witness) -> anyhow::Result<Vec<Name>> {
        if let Some(tapscript) = witness.tapscript() {
            let mut names = Vec::new();
            let mut instructions = tapscript.instructions();
            while let Some(instruction) = instructions.next().transpose()? {
                if instruction == PushBytes((&[]).into()) {
                    if let Some(instruction) = instructions.next().transpose()? {
                        if instruction == Op(opcodes::all::OP_IF) {
                            loop {
                                match instructions.next().transpose()? {
                                    None => return Ok(vec![]),
                                    Some(Op(opcodes::all::OP_ENDIF)) => {
                                        return Ok(names);
                                    }
                                    Some(PushBytes(data)) => {
                                        let data = data.as_bytes();
                                        if let Ok(name) = Name::from_bytes(data) {
                                            names.push(name);
                                        } else {
                                            return Ok(vec![]);
                                        }
                                    }
                                    Some(_) => return Ok(vec![]),
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::blockdata::script::{Builder, PushBytesBuf};
    use ciborium::Value;
    use hex_literal::hex;
    use ns_protocol::{
        ed25519,
        ns::{Operation, PublicKeyParams, Service, ThresholdLevel},
    };

    #[test]
    fn names_from_witness() {
        let secret_key = hex!("7ef3811aabb916dc2f646ef1a371b90adec91bc07992cd4d44c156c42fc1b300");
        let public_key = hex!("ee90735ac719e85dc2f3e5974036387fdf478af7d9d1f8480e97eee601890266");
        let params = PublicKeyParams {
            public_keys: vec![public_key.to_vec()],
            threshold: Some(1),
            kind: None,
        };
        let signer = ed25519::SigningKey::try_from(&secret_key).unwrap();
        let signers = vec![signer];

        let mut name1 = Name {
            name: "a".to_string(),
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
        name1
            .sign(&params, ThresholdLevel::Default, &signers)
            .unwrap();
        assert!(name1.validate().is_ok());

        let mut name2 = Name {
            name: "aa".to_string(),
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
        name2
            .sign(&params, ThresholdLevel::Default, &signers)
            .unwrap();
        assert!(name2.validate().is_ok());

        let script = Builder::new()
            .push_slice(hex!(
                "ee90735ac719e85dc2f3e5974036387fdf478af7d9d1f8480e97eee601890266"
            ))
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .push_opcode(opcodes::OP_FALSE)
            .push_opcode(opcodes::all::OP_IF)
            .push_slice(PushBytesBuf::try_from(name1.to_bytes().unwrap()).unwrap())
            .push_slice(PushBytesBuf::try_from(name2.to_bytes().unwrap()).unwrap())
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script();
        let witness = Witness::from_slice(&[script.into_bytes(), Vec::new()]);
        let names = Envelope::from_witness(&witness).unwrap();
        assert_eq!(2, names.len());
        assert_eq!(name1, names[0]);
        assert_eq!(name2, names[1]);
    }

    #[test]
    fn check_witness() {
        let tx_data = "02000000000101b39fec8d54aef6bc23dcaa24a54a75f08bb6a6780e16dbd7f220f888969b78620000000000fdffffff022202000000000000225120f1308dd106e1fa3e9433638e186d317c0880cafeb9aa7c68c82244cecff0cc069106000000000000160014c67514f86a1b378786b847d6e02118a2d706ab530340e59486119096c7dde7b5306eda6ece48956babf3a989dbc7f907f16527404b27abbfdf4181ad611bf5e33a80052583379c296a85237fe67f4bb956b31b04b6ca97207d0548d6afc9d85ba2cd2a3e43cfff02ae3f32a1e38b9bc47e6cecebdc67d074ac0063036f7264010118746578742f706c61696e3b636861727365743d7574662d38004c507b2270223a226272632d3230222c226f70223a226465706c6f79222c227469636b223a22444f4f48222c226d6178223a2239333935353530313133222c226c696d223a2239333935353530313133227d6821c00a2fbb317fffcab46c93b74701ba776483fc31b8e18b55f0d28d618806d3b8d900000000";
        let tx: Transaction = crate::bitcoin::decode_hex(tx_data).unwrap();
        println!("Transaction: {:#?}", &tx);

        for input in &tx.input {
            println!("witness: {:#?}", &input.witness);
            if let Some(tapscript) = input.witness.tapscript() {
                println!("tapscript: {:#?}", &tapscript);
                println!("tapscript: {:?}", tapscript.to_bytes());
            }
        }
    }
}
