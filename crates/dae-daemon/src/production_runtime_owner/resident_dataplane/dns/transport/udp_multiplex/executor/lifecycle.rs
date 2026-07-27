use futures_util::{StreamExt, stream::FuturesUnordered};

use super::super::{ResidentDnsUdpActorCompletion, ResidentDnsUdpActorLifecycle};

pub(super) struct ResidentDnsUdpActorTask {
    pub(super) lifecycle: std::sync::Weak<ResidentDnsUdpActorLifecycle>,
    pub(super) completion: std::sync::Arc<ResidentDnsUdpActorCompletion>,
    pub(super) task: tokio::task::JoinHandle<bool>,
}

pub(super) async fn join_dns_udp_actor_tasks(
    actors: &mut Vec<ResidentDnsUdpActorTask>,
    deadline: tokio::time::Instant,
) -> (usize, usize, usize) {
    let abort_handles = actors
        .iter()
        .map(|actor| actor.task.abort_handle())
        .collect::<Vec<_>>();
    let mut pending = actors
        .drain(..)
        .map(|actor| async move {
            let result = actor.task.await;
            actor.completion.finish();
            result
        })
        .collect::<FuturesUnordered<_>>();
    let mut joined = 0_usize;
    let mut panicked = 0_usize;
    loop {
        match tokio::time::timeout_at(deadline, pending.next()).await {
            Ok(Some(Ok(_))) => joined = joined.saturating_add(1),
            Ok(Some(Err(_))) => panicked = panicked.saturating_add(1),
            Ok(None) => return (joined, panicked, 0),
            Err(_) => {
                let timed_out = pending.len();
                for abort in &abort_handles {
                    abort.abort();
                }
                while pending.next().await.is_some() {}
                return (joined, panicked, timed_out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deadline_abort_reaps_every_dns_udp_actor_task() {
        let completion = ResidentDnsUdpActorCompletion::new();
        let mut actors = vec![ResidentDnsUdpActorTask {
            lifecycle: std::sync::Weak::<ResidentDnsUdpActorLifecycle>::new(),
            completion: std::sync::Arc::clone(&completion),
            task: tokio::spawn(std::future::pending::<bool>()),
        }];

        let (joined, panicked, timed_out) =
            join_dns_udp_actor_tasks(&mut actors, tokio::time::Instant::now()).await;

        assert_eq!(joined, 0);
        assert_eq!(panicked, 0);
        assert_eq!(timed_out, 1);
        assert!(actors.is_empty());
        assert!(completion.wait(tokio::time::Instant::now()).await);
    }
}
