use futures_util::{StreamExt, stream::FuturesUnordered};

use super::*;

pub(super) async fn join_udp_tasks_until_deadline<T>(
    tasks: &mut Vec<JoinHandle<T>>,
    deadline: time::Instant,
) -> (usize, usize, usize) {
    let abort_handles = tasks
        .iter()
        .map(JoinHandle::abort_handle)
        .collect::<Vec<_>>();
    let mut pending = tasks.drain(..).collect::<FuturesUnordered<_>>();
    let mut joined = 0_usize;
    let mut panicked = 0_usize;

    loop {
        match time::timeout_at(deadline, pending.next()).await {
            Ok(Some(Ok(_))) => joined = joined.saturating_add(1),
            Ok(Some(Err(_))) => panicked = panicked.saturating_add(1),
            Ok(None) => return (joined, panicked, 0),
            Err(_) => {
                let timed_out = pending.len();
                for handle in &abort_handles {
                    handle.abort();
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
    async fn task_join_uses_one_shared_deadline_and_aborts_remaining_tasks() {
        let mut tasks = vec![
            tokio::spawn(std::future::pending::<()>()),
            tokio::spawn(async {}),
        ];
        let deadline = time::Instant::now() + Duration::from_millis(10);
        let (joined, panicked, timed_out) =
            join_udp_tasks_until_deadline(&mut tasks, deadline).await;
        assert_eq!(joined, 1);
        assert_eq!(panicked, 0);
        assert_eq!(timed_out, 1);
        assert!(tasks.is_empty());
    }
}
