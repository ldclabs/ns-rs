use async_stream::try_stream;
use bloomfilter::Bloom;
use futures_core::stream::Stream;

use ns_protocol::state::{Inscription, NameState, ServiceProtocol, ServiceState};

use crate::indexer::Client;

pub type InscriptionState = (
    Inscription,
    Option<(NameState, ServiceState, Option<ServiceProtocol>)>,
);

// fetches all inscriptions and states from last accepted to bottom_height.
// The lowest height is 1 (the first inscription).
pub fn fetch_desc(
    cli: Client,
    bottom_height: u64,
) -> impl Stream<Item = anyhow::Result<InscriptionState>> {
    try_stream! {
        let last_accepted: Inscription = cli.get_last_accepted_inscription().await?;
        let name_state: NameState = cli.get_name_state(&last_accepted.name).await?;
        let service_state: ServiceState = cli.get_service_state(&last_accepted.name, last_accepted.data.service.code).await?;

        let mut bloom = Bloom::new_for_fp_rate(last_accepted.height as usize, 0.0001);
        let mut head_height = last_accepted.height;
        let mut head_inscription = last_accepted.clone();

        bloom.set(&head_inscription.name);
        yield (last_accepted, Some((name_state, service_state, None)));

        loop {
            if head_height <= 1 || head_height < bottom_height {
                break;
            }

            head_height -= 1;
            let inscription: Inscription = cli.get_inscription_by_height(head_height).await?;

            if head_inscription.previous_hash != inscription.hash()? {
                Err(anyhow::anyhow!("inscription({}): previous hash mismatch", inscription.height))?;
            }

            head_inscription = inscription.clone();
            if bloom.check(&inscription.name) {
                // latest name & service state returned in previous iteration
                yield (inscription, None);
                continue;
            }

            let name_state: NameState = cli.get_name_state(&inscription.name).await?;
            let service_state: ServiceState = cli.get_service_state(&inscription.name, inscription.data.service.code).await?;

            bloom.set(&head_inscription.name);
            // false positives are possible from bloom, but it's ok
            if name_state.sequence > inscription.sequence {
                yield (inscription, None);
                continue;
            }

            if name_state.sequence != inscription.sequence {
                Err(anyhow::anyhow!("inscription({}): name_state sequence mismatch, expected {}, got {}", inscription.height, inscription.sequence, name_state.sequence))?;
            }
            if inscription.name_hash != name_state.hash()? {
                Err(anyhow::anyhow!("inscription({}): name_hash mismatch", inscription.height))?;
            }

            if service_state.sequence != inscription.sequence {
                Err(anyhow::anyhow!("inscription({}): service_state sequence mismatch, expected {}, got {}", inscription.height, inscription.sequence, service_state.sequence))?;
            }
            if inscription.service_hash != service_state.hash()? {
                Err(anyhow::anyhow!("inscription({}): service_hash mismatch", inscription.height))?;
            }

            yield (inscription, Some((name_state, service_state, None)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{pin_mut, stream::StreamExt};

    use crate::indexer::ClientOptions;

    #[tokio::test(flavor = "current_thread")]
    #[ignore]
    async fn fetcher_works() {
        let endpoint = std::env::var("INDEXER_ENDPOINT").unwrap_or_default();
        // let endpoint = "http://192.168.1.80:8080".to_string();
        if endpoint.is_empty() {
            return;
        }

        let cli = Client::new(&ClientOptions { endpoint }).await.unwrap();

        let s = fetch_desc(cli, 1);
        pin_mut!(s); // needed for iteration

        // first item is always the last accepted inscription
        let (last_accepted, state) = s.next().await.unwrap().unwrap();
        assert!(last_accepted.height > 0);
        assert!(state.is_some());
        let (name_state, service_state, _) = state.unwrap();
        assert_eq!(last_accepted.name, name_state.name);
        assert_eq!(last_accepted.sequence, name_state.sequence);
        assert_eq!(last_accepted.name, service_state.name);
        assert_eq!(last_accepted.sequence, service_state.sequence);
        assert_eq!(last_accepted.name_hash, name_state.hash().unwrap());
        assert_eq!(last_accepted.service_hash, service_state.hash().unwrap());

        let mut state_exists = false;
        let mut head_ins = last_accepted.clone();
        while let Some(res) = s.next().await {
            let (ins, state) = res.unwrap();
            println!("got {}, {}, {}", ins.height, ins.name, ins.sequence);
            assert_eq!(head_ins.previous_hash, ins.hash().unwrap());
            head_ins = ins.clone();
            if let Some((name_state, service_state, _)) = state {
                assert_eq!(ins.name, name_state.name);
                assert_eq!(ins.sequence, name_state.sequence);
                assert_eq!(ins.name, service_state.name);
                assert_eq!(ins.sequence, service_state.sequence);
                assert_eq!(ins.name_hash, name_state.hash().unwrap());
                assert_eq!(ins.service_hash, service_state.hash().unwrap());
                state_exists = true;
            }
        }

        assert!(state_exists);
    }
}
