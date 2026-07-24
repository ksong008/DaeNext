use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use super::candidate_error::{SocketAddressResolutionError, SocketCandidateAttemptError};

pub(super) const SOCKET_CANDIDATE_ERROR_DETAIL_LIMIT: usize = 8;

pub(in crate::production_runtime_owner::resident_dataplane) async fn resolve_socket_addr_candidates(
    authority: &str,
    timeout: Duration,
    context: &str,
) -> Result<Vec<SocketAddr>, SocketAddressResolutionError> {
    if let Ok(addr) = authority.parse::<SocketAddr>() {
        return Ok(vec![addr]);
    }
    let resolved = tokio::time::timeout(timeout, tokio::net::lookup_host(authority))
        .await
        .map_err(|_| SocketAddressResolutionError::timed_out(context, authority))?
        .map_err(|err| SocketAddressResolutionError::resolve(context, authority, err))?;
    let candidates = unique_socket_addr_candidates(resolved);
    if candidates.is_empty() {
        return Err(SocketAddressResolutionError::no_address(context, authority));
    }
    Ok(candidates)
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn try_socket_addr_candidates<
    T,
    F,
    Fut,
    E,
>(
    candidates: &[SocketAddr],
    context: &str,
    mut attempt: F,
) -> Result<(SocketAddr, T), SocketCandidateAttemptError>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: fmt::Display,
{
    if candidates.is_empty() {
        return Err(SocketCandidateAttemptError::empty(context));
    }
    let mut failures =
        Vec::with_capacity(candidates.len().min(SOCKET_CANDIDATE_ERROR_DETAIL_LIMIT));
    for &candidate in candidates {
        match attempt(candidate).await {
            Ok(value) => return Ok((candidate, value)),
            Err(err) if failures.len() < SOCKET_CANDIDATE_ERROR_DETAIL_LIMIT => {
                failures.push((candidate, err.to_string()));
            }
            Err(_) => {}
        }
    }
    Err(SocketCandidateAttemptError::all_failed(
        context,
        candidates.len(),
        failures,
    ))
}

fn unique_socket_addr_candidates(
    candidates: impl IntoIterator<Item = SocketAddr>,
) -> Vec<SocketAddr> {
    let mut unique = Vec::new();
    for candidate in candidates {
        if !unique.contains(&candidate) {
            unique.push(candidate);
        }
    }
    unique
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_deduplication_preserves_resolver_order() {
        let first = "[2001:db8::1]:443".parse().unwrap();
        let second = "192.0.2.1:443".parse().unwrap();
        assert_eq!(
            unique_socket_addr_candidates([first, second, first]),
            vec![first, second]
        );
    }

    #[tokio::test]
    async fn candidate_attempts_fall_back_without_reordering() {
        let first = "[2001:db8::2]:443".parse().unwrap();
        let second = "192.0.2.2:443".parse().unwrap();
        let attempted = std::sync::Mutex::new(Vec::new());
        let (selected, value) =
            try_socket_addr_candidates(&[first, second], "test candidate fallback", |candidate| {
                attempted.lock().unwrap().push(candidate);
                async move {
                    if candidate == first {
                        Err("injected first-candidate failure".to_owned())
                    } else {
                        Ok("connected")
                    }
                }
            })
            .await
            .unwrap();

        assert_eq!(selected, second);
        assert_eq!(value, "connected");
        assert_eq!(*attempted.lock().unwrap(), vec![first, second]);
    }

    #[tokio::test]
    async fn candidate_failure_retains_bounded_typed_details() {
        let candidates = (1..=10)
            .map(|last| SocketAddr::from(([192, 0, 2, last], 443)))
            .collect::<Vec<_>>();
        let error =
            try_socket_addr_candidates(&candidates, "connect fixture", |candidate| async move {
                Err::<(), _>(format!("injected failure for {}", candidate.ip()))
            })
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            SocketCandidateAttemptError::AllFailed {
                candidate_count: 10,
                omitted: 2,
                ..
            }
        ));
        let message = error.to_string();
        assert!(message.starts_with("connect fixture: all 10 resolved address candidates failed"));
        assert!(message.contains("192.0.2.1:443: injected failure for 192.0.2.1"));
        assert!(message.ends_with("2 additional failures omitted"));
    }
}
