use bitcoin::{hashes::Hash, BlockHash, Transaction};
use futures::future::Shared;
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    future::Future,
    sync::Arc,
};
use tokio::{
    sync::RwLock,
    time::{sleep, Duration},
};

use ns_protocol::{
    ns::{Name, PublicKeyParams, ThresholdLevel},
    state::{
        hash_sha3, Inscription, InvalidInscription, NameState, ServiceProtocol, ServiceState,
        NAME_EXPIRE_SECONDS, NAME_STALE_SECONDS,
    },
};

use crate::db::{
    self,
    scylladb::{ScyllaDB, ScyllaDBOptions},
};
use crate::envelope::Envelope;
use crate::utxo::UTXO;

const ACCEPTED_DISTANCE: u64 = 5; // 6 confirmations

pub struct IndexerOptions {
    pub scylla: ScyllaDBOptions,
    pub index_utxo: bool,
}

#[derive(Clone)]
pub struct Indexer {
    pub(crate) scylla: Arc<ScyllaDB>,
    pub(crate) state: Arc<IndexerState>,
    index_utxo: bool,
}

type InscriptionState = (NameState, ServiceState, Option<ServiceProtocol>);
// (block_height, spents, unspents)
type UTXOState = (u64, Vec<UTXO>, Vec<(Vec<u8>, UTXO)>);

pub struct IndexerState {
    pub(crate) last_accepted_height: RwLock<u64>,
    pub(crate) last_accepted: RwLock<Option<Inscription>>,
    pub(crate) best_inscriptions: RwLock<VecDeque<Inscription>>,
    // protocols: RwLock<BTreeMap<u64, ServiceProtocol>>,
    pub(crate) confirming_names: RwLock<BTreeMap<String, VecDeque<InscriptionState>>>,
    pub(crate) confirming_utxos: RwLock<VecDeque<UTXOState>>,
}

impl Indexer {
    pub async fn new(opts: &IndexerOptions) -> anyhow::Result<Self> {
        let scylla = ScyllaDB::new(&opts.scylla).await?;
        Ok(Self {
            scylla: Arc::new(scylla),
            state: Arc::new(IndexerState {
                last_accepted_height: RwLock::new(0),
                last_accepted: RwLock::new(None),
                best_inscriptions: RwLock::new(VecDeque::with_capacity(1024)),
                // protocols: RwLock::new(BTreeMap::new()),
                confirming_names: RwLock::new(BTreeMap::new()),
                confirming_utxos: RwLock::new(VecDeque::with_capacity(1024)),
            }),
            index_utxo: opts.index_utxo,
        })
    }

    // return last_accepted block height if exists
    pub async fn initialize(&self) -> anyhow::Result<u64> {
        let last_accepted_height = db::Checkpoint::get_last_accepted_height(&self.scylla).await?;
        {
            let mut last_accepted_height_state = self.state.last_accepted_height.write().await;
            *last_accepted_height_state = last_accepted_height.block_height as u64;
        }

        if let Some(checkpoint) = db::Checkpoint::get_last_accepted(&self.scylla).await? {
            let mut inscription =
                db::Inscription::with_pk(checkpoint.name.clone(), checkpoint.sequence);
            inscription.get_one(&self.scylla, vec![]).await?;

            let last_accepted = inscription.to_index()?;
            let last_checkpoint = inscription.to_checkpoint(last_accepted.hash()?)?;
            if last_checkpoint != checkpoint {
                anyhow::bail!(
                    "last accepted inscription is not match with checkpoint:\n{:#?}\n{:#?}",
                    last_checkpoint,
                    checkpoint
                );
            }
            {
                let mut last_accepted_state = self.state.last_accepted.write().await;
                *last_accepted_state = Some(last_accepted.clone());
            }
        }
        Ok(last_accepted_height.block_height as u64)
    }

    pub async fn scan_last_accepted<S>(&self, signal: Shared<S>) -> anyhow::Result<()>
    where
        S: Future<Output = ()>,
    {
        let mut height = 0i64;

        loop {
            tokio::select! {
                _ = signal.clone() => {
                    log::warn!(target: "ns-indexer", "Received signal to stop indexing");
                    return Ok(());
                },
                _ = async {
                        sleep(Duration::from_secs(3)).await;
                } => {},
            };

            if let Some(checkpoint) = db::Checkpoint::get_last_accepted(&self.scylla).await? {
                log::info!(target: "ns-indexer",
                    action = "scan_last_accepted",
                    last_accepted = checkpoint.name.clone(),
                    new_last_accepted = checkpoint.height > height,
                    height = checkpoint.height,
                    block_height = checkpoint.block_height;
                    "",
                );

                if checkpoint.height > height {
                    let mut inscription =
                        db::Inscription::with_pk(checkpoint.name.clone(), checkpoint.sequence);
                    inscription.get_one(&self.scylla, vec![]).await?;

                    let last_accepted = inscription.to_index()?;
                    let last_checkpoint = inscription.to_checkpoint(last_accepted.hash()?)?;
                    if last_checkpoint != checkpoint {
                        anyhow::bail!(
                            "last accepted inscription is not match with checkpoint:\n{:#?}\n{:#?}",
                            last_checkpoint,
                            checkpoint
                        );
                    }
                    {
                        let mut last_accepted_state = self.state.last_accepted.write().await;
                        *last_accepted_state = Some(last_accepted.clone());
                    }

                    height = checkpoint.height;
                }
            }
        }
    }

    pub async fn index(
        &self,
        block_hash: &BlockHash,
        block_height: u64,
        block_time: u64,
        tx: Transaction,
    ) -> anyhow::Result<()> {
        let accepted_height = {
            let last_accepted_height_state = self.state.last_accepted_height.read().await;
            if *last_accepted_height_state + ACCEPTED_DISTANCE < block_height {
                block_height - ACCEPTED_DISTANCE
            } else {
                0
            }
        };

        if accepted_height > 0 {
            self.save_accepted(accepted_height).await?;
        }

        for envelope in Envelope::from_transaction(&tx) {
            for name in envelope.payload {
                let is_new_name = name.sequence == 0;
                match self.index_name(block_height, block_time, &name).await {
                    Err(err) => {
                        if !name.name.is_empty() {
                            let hash = hash_sha3(&name).expect("hash_sha3(name) should not fail");
                            let invalid_inscription = InvalidInscription {
                                name: name.name.clone(),
                                block_height,
                                hash,
                                reason: err.to_string(),
                                data: name,
                            };
                            if let Err(err) =
                                db::InvalidInscription::from_index(&invalid_inscription)
                                    .expect("InvalidInscription::from_index should not fail")
                                    .save(&self.scylla)
                                    .await
                            {
                                log::error!(target: "ns-indexer",
                              "failed to save invalid inscription: {}", err);
                            }
                        }
                    }

                    Ok((name_state_hash, service_state_hash, service_protocol_hash)) => {
                        let mut inscription = Inscription {
                            name: name.name.clone(),
                            sequence: name.sequence,
                            height: 0,
                            name_height: 0,
                            previous_hash: vec![],
                            name_hash: name_state_hash,
                            service_hash: service_state_hash,
                            protocol_hash: service_protocol_hash,
                            block_hash: block_hash.to_byte_array().to_vec(),
                            block_height,
                            txid: envelope.txid.to_byte_array().to_vec(),
                            vin: envelope.vin,
                            data: name,
                        };
                        {
                            let mut best_inscriptions_state =
                                self.state.best_inscriptions.write().await;

                            match best_inscriptions_state.back() {
                                Some(prev_best_inscription) => {
                                    inscription.height = prev_best_inscription.height + 1;
                                    inscription.name_height = if is_new_name {
                                        prev_best_inscription.name_height + 1
                                    } else {
                                        prev_best_inscription.name_height
                                    };
                                    inscription.previous_hash = prev_best_inscription
                                        .hash()
                                        .expect("hash_sha3(inscription) should not fail");
                                }
                                None => match *self.state.last_accepted.read().await {
                                    Some(ref last_accepted_state) => {
                                        inscription.height = last_accepted_state.height + 1;
                                        inscription.name_height = if is_new_name {
                                            last_accepted_state.name_height + 1
                                        } else {
                                            last_accepted_state.name_height
                                        };
                                        inscription.previous_hash = last_accepted_state
                                            .hash()
                                            .expect("hash_sha3(inscription) should not fail");
                                    }
                                    None => {
                                        // this is the first inscription
                                        inscription.height = 1;
                                        inscription.name_height = 1;
                                        inscription.previous_hash = [0u8; 32].to_vec();
                                    }
                                },
                            }

                            best_inscriptions_state.push_back(inscription);
                        }
                    }
                }
            }
        }

        if self.index_utxo {
            let (spent, unspent) = UTXO::from_transaction(&tx);
            let mut confirming_utxos = self.state.confirming_utxos.write().await;
            confirming_utxos.push_back((block_height, spent, unspent));
        }

        Ok(())
    }

    // return (name_state_hash, service_state_hash, Option<service_protocol_hash>)
    async fn index_name(
        &self,
        block_height: u64,
        block_time: u64,
        name: &Name,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)> {
        name.validate()?;
        // default protocol is Name service
        let mut service_protocol = ServiceProtocol::default();
        if name.service.code > 0 {
            // try to get latest service protocol from db
            let protocol =
                db::ServiceProtocol::get_latest(&self.scylla, name.service.code as i64, vec![])
                    .await
                    .map_err(|err| {
                        anyhow::anyhow!(
                            "failed to get latest service protocol, code: {}, err: {}",
                            name.service.code,
                            err
                        )
                    })?;
            service_protocol = protocol.to_index()?;
        };
        service_protocol.validate(&name.service)?;

        if let Some(ref approver) = name.service.approver {
            let mut approver_state = db::NameState::with_pk(approver.clone());
            approver_state
                .get_one(&self.scylla, vec![])
                .await
                .map_err(|err| {
                    anyhow::anyhow!(
                        "failed to get approver state, name: {}, err: {}",
                        approver,
                        err
                    )
                })?;
            let approver_state = approver_state.to_index()?;
            name.verify(&approver_state.public_key_params(), ThresholdLevel::Default)?;
        }

        // pre-check state cache in read lock
        let mut prev_state: (Option<NameState>, Option<ServiceState>) = {
            let confirming_names = self.state.confirming_names.read().await;
            if let Some(names) = confirming_names.get(&name.name) {
                let prev_name_state = names.back().map(|(name_state, _, _)| name_state);
                let prev_service_state = names
                    .iter()
                    .filter_map(|(_, service_state, _)| {
                        if service_state.code == name.service.code {
                            Some(service_state)
                        } else {
                            None
                        }
                    })
                    .last();
                (prev_name_state.cloned(), prev_service_state.cloned())
            } else {
                (None, None)
            }
        };

        if prev_state.0.is_none() {
            // try to get accepted state from db
            let mut name_state = db::NameState::with_pk(name.name.clone());
            if name_state.get_one(&self.scylla, vec![]).await.is_ok() {
                prev_state.0 = Some(name_state.to_index()?);
            }
        };

        if prev_state.0.is_some() && prev_state.1.is_none() {
            // try to get accepted state from db
            let mut service_state =
                db::ServiceState::with_pk(name.name.clone(), name.service.code as i64);
            if service_state.get_one(&self.scylla, vec![]).await.is_ok() {
                prev_state.1 = Some(service_state.to_index()?);
            }
        };

        if let Some(prev_name_state) = prev_state.0 {
            let name_state = prev_name_state.verify_the_next(block_height, block_time, name)?;

            let service_state = if let Some(prev_service_state) = prev_state.1 {
                prev_service_state.verify_the_next(name)?
            } else {
                ServiceState {
                    name: name.name.clone(),
                    code: name.service.code,
                    sequence: name.sequence,
                    data: name
                        .service
                        .operations
                        .iter()
                        .map(|op| (op.subcode, op.params.clone()))
                        .collect(),
                }
            };

            let mut confirming_names = self.state.confirming_names.write().await;
            if !confirming_names.contains_key(&name.name) {
                confirming_names.insert(name.name.clone(), VecDeque::new());
            }

            let names = confirming_names
                .get_mut(&name.name)
                .expect("names state cache should be exist");

            let name_state_hash = name_state.hash()?;
            let service_state_hash = service_state.hash()?;
            names.push_back((name_state, service_state, None));
            return Ok((name_state_hash, service_state_hash, None));
        }

        // no prev_state for this name, it is new!
        if name.sequence != 0 {
            anyhow::bail!(
                "invalid sequence for new name, expected: 0, got: {}",
                name.sequence
            );
        }
        if name.service.code != 0 {
            anyhow::bail!(
                "invalid code for new name, expected: 0, got: {}",
                name.service.code
            );
        }
        if name.service.operations.len() != 1 {
            anyhow::bail!(
                "invalid operations length for new name, expected: 1, got: {}",
                name.service.operations.len()
            );
        }
        let op = &name.service.operations[0];
        if op.subcode != 1 {
            anyhow::bail!(
                "invalid operation subcode for new name, expected: 1, got: {}",
                op.subcode
            );
        }
        let public_key_params = PublicKeyParams::try_from(&op.params)?;
        public_key_params.validate()?;
        name.verify(&public_key_params, ThresholdLevel::All)?;
        let name_state = NameState {
            name: name.name.clone(),
            sequence: 0,
            block_height,
            block_time,
            stale_time: block_time + NAME_STALE_SECONDS,
            expire_time: block_time + NAME_EXPIRE_SECONDS,
            threshold: public_key_params
                .threshold
                .unwrap_or(public_key_params.public_keys.len() as u8),
            key_kind: public_key_params.kind.unwrap_or(0),
            public_keys: public_key_params.public_keys,
            next_public_keys: None,
        };
        let service_state = ServiceState {
            name: name.name.clone(),
            code: 0,
            sequence: 0,
            data: vec![(1, op.params.clone())],
        };

        let name_state_hash = name_state.hash()?;
        let service_state_hash = service_state.hash()?;
        let mut confirming_names = self.state.confirming_names.write().await;
        confirming_names.insert(
            name.name.clone(),
            VecDeque::from([(name_state, service_state, None)]),
        );

        Ok((name_state_hash, service_state_hash, None))
    }

    async fn save_accepted(&self, accepted_height: u64) -> anyhow::Result<()> {
        let mut name_states: Vec<NameState> = vec![];
        let mut service_states: Vec<ServiceState> = vec![];
        let mut protocol_states: Vec<ServiceProtocol> = vec![];
        let mut inscriptions: Vec<Inscription> = vec![];

        {
            let mut confirming_names = self.state.confirming_names.write().await;

            let mut empty_names: Vec<String> = Vec::new();
            for (name, names) in confirming_names.iter_mut() {
                while let Some(head) = names.front() {
                    if head.0.block_height > accepted_height {
                        break;
                    }

                    if let Some((name_state, service_state, protocol_state)) = names.pop_front() {
                        name_states.push(name_state);
                        service_states.push(service_state);
                        if let Some(protocol_state) = protocol_state {
                            protocol_states.push(protocol_state);
                        }
                    }
                }

                if names.is_empty() {
                    empty_names.push(name.clone());
                }
            }

            if !empty_names.is_empty() {
                for name in empty_names {
                    confirming_names.remove(&name);
                }
            }
        }

        {
            let mut best_inscriptions_state = self.state.best_inscriptions.write().await;
            while let Some(inscription) = best_inscriptions_state.front() {
                if inscription.block_height > accepted_height {
                    break;
                }
                if let Some(inscription) = best_inscriptions_state.pop_front() {
                    inscriptions.push(inscription);
                }
            }
        }

        let mut fresh_name_index: BTreeMap<String, u64> = BTreeMap::new();
        let mut fresh_name_with_public_keys: HashSet<(String, Vec<Vec<u8>>)> = HashSet::new();
        let mut captured_name_with_public_keys: HashSet<(String, Vec<Vec<u8>>)> = HashSet::new();
        let mut stale_name_with_public_keys: HashSet<(String, Vec<Vec<u8>>)> = HashSet::new();
        let mut fresh_pubkey_names: HashSet<(Vec<u8>, String)> = HashSet::new();
        let mut stale_pubkey_names: HashSet<(Vec<u8>, String)> = HashSet::new();
        if !inscriptions.is_empty() {
            for name in &name_states {
                fresh_name_index.insert(name.name.clone(), name.block_time);
                fresh_name_with_public_keys.insert((name.name.clone(), name.public_keys.clone()));
            }

            let npks = db::NameState::capture_name_with_public_keys(
                &self.scylla,
                fresh_name_index.keys().collect::<Vec<&String>>(),
            )
            .await?;
            for npk in npks {
                captured_name_with_public_keys.insert((npk.name.clone(), npk.public_keys.clone()));
            }
            for npk in &captured_name_with_public_keys {
                if fresh_name_with_public_keys.contains(npk) {
                    fresh_name_with_public_keys.remove(npk); // not changed, ignore
                } else {
                    stale_name_with_public_keys.insert(npk.clone()); // changed, need to update
                }
            }
            for npk in &fresh_name_with_public_keys {
                for pk in npk.1.iter() {
                    fresh_pubkey_names.insert((pk.clone(), npk.0.clone()));
                }
            }
            for npk in &stale_name_with_public_keys {
                for pk in npk.1.iter() {
                    let pkn = (pk.clone(), npk.0.clone());
                    if fresh_pubkey_names.contains(&pkn) {
                        fresh_pubkey_names.remove(&pkn); // not changed, ignore
                    } else {
                        stale_pubkey_names.insert(pkn); // outdated, need to remove
                    }
                }
            }

            db::Inscription::save_checkpoint(
                &self.scylla,
                &name_states,
                &service_states,
                &protocol_states,
                &inscriptions,
            )
            .await?;

            log::info!(target: "ns-indexer",
                action = "save_accepted",
                block_height = accepted_height,
                name_states = name_states.len(),
                service_states = service_states.len(),
                protocol_states = protocol_states.len(),
                inscriptions = inscriptions.len();
                "",
            );

            {
                let mut last_accepted_state = self.state.last_accepted.write().await;
                *last_accepted_state = Some(inscriptions.last().unwrap().clone());
            }
        }

        {
            let mut last_accepted_height_state = self.state.last_accepted_height.write().await;
            *last_accepted_height_state = accepted_height;
        }

        db::Checkpoint::save_last_accepted_height(&self.scylla, accepted_height).await?;

        if !fresh_name_index.is_empty() {
            db::NameState::batch_update_name_indexs(&self.scylla, fresh_name_index).await?;
        }
        if !stale_pubkey_names.is_empty() {
            db::NameState::batch_remove_pubkey_names(&self.scylla, stale_pubkey_names).await?;
        }
        if !fresh_pubkey_names.is_empty() {
            db::NameState::batch_add_pubkey_names(&self.scylla, fresh_pubkey_names).await?;
        }

        let mut utxos: Vec<UTXOState> = Vec::new();
        if self.index_utxo {
            let mut confirming_utxos = self.state.confirming_utxos.write().await;

            while let Some(utxo) = confirming_utxos.front() {
                if utxo.0 > accepted_height {
                    break;
                }
                if let Some(utxo) = confirming_utxos.pop_front() {
                    utxos.push(utxo);
                }
            }
        }
        if !utxos.is_empty() {
            for utxo in utxos {
                db::Utxo::handle_utxo(&self.scylla, &utxo.1, &utxo.2).await?;
            }
        }

        Ok(())
    }
}
