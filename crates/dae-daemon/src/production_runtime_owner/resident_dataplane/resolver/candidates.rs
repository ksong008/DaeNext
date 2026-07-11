use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

const SOCKET_CANDIDATE_ERROR_DETAIL_LIMIT: usize = 8;

pub(in crate::production_runtime_owner::resident_dataplane) async fn resolve_socket_addr_candidates(
    authority: &str,
    timeout: Duration,
    context: &str,
) -> Result<Vec<SocketAddr>, String> {
    if let Ok(addr) = authority.parse::<SocketAddr>() {
        return Ok(vec![addr]);
    }
    let resolved = tokio::time::timeout(timeout, tokio::net::lookup_host(authority))
        .await
        .map_err(|_| format!("{context} {authority}: resolution timed out"))?
        .map_err(|err| format!("{context} {authority}: resolve failed: {err}"))?;
    let candidates = unique_socket_addr_candidates(resolved);
    if candidates.is_empty() {
        return Err(format!("{context} {authority}: no IP address"));
    }
    Ok(candidates)
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn try_socket_addr_candidates<
    T,
    F,
    Fut,
>(
    candidates: &[SocketAddr],
    context: &str,
    mut attempt: F,
) -> Result<(SocketAddr, T), String>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    if candidates.is_empty() {
        return Err(format!("{context}: no resolved address candidates"));
    }
    let mut failures =
        Vec::with_capacity(candidates.len().min(SOCKET_CANDIDATE_ERROR_DETAIL_LIMIT));
    for &candidate in candidates {
        match attempt(candidate).await {
            Ok(value) => return Ok((candidate, value)),
            Err(err) if failures.len() < SOCKET_CANDIDATE_ERROR_DETAIL_LIMIT => {
                failures.push(format!("{candidate}: {err}"));
            }
            Err(_) => {}
        }
    }
    let omitted = candidates.len().saturating_sub(failures.len());
    let mut message = format!(
        "{context}: all {} resolved address candidates failed",
        candidates.len()
    );
    if !failures.is_empty() {
        message.push_str(": ");
        message.push_str(&failures.join("; "));
    }
    if omitted > 0 {
        message.push_str(&format!("; {omitted} additional failures omitted"));
    }
    Err(message)
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
}
