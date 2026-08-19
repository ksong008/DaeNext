use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use futures_util::stream::{FuturesUnordered, StreamExt};

use super::candidate_error::SocketCandidateAttemptError;
use super::candidates::SOCKET_CANDIDATE_ERROR_DETAIL_LIMIT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpCandidateRacePolicy {
    attempt_delay: Duration,
    deadline: Duration,
    max_in_flight: usize,
}

impl TcpCandidateRacePolicy {
    pub const fn new(attempt_delay: Duration, deadline: Duration, max_in_flight: usize) -> Self {
        Self {
            attempt_delay,
            deadline,
            max_in_flight,
        }
    }
}

pub async fn try_tcp_socket_addr_candidates<T, F, Fut, E>(
    candidates: &[SocketAddr],
    context: &str,
    policy: TcpCandidateRacePolicy,
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
    if let [candidate] = candidates {
        return attempt(*candidate)
            .await
            .map(|value| (*candidate, value))
            .map_err(|err| {
                SocketCandidateAttemptError::all_failed(
                    context,
                    1,
                    vec![(*candidate, err.to_string())],
                )
            });
    }
    let candidates = interleave_address_families(candidates);
    let max_in_flight = policy.max_in_flight.clamp(1, candidates.len());
    let deadline = Instant::now() + policy.deadline;
    let mut next_index = 0_usize;
    let mut attempted_count = 0_usize;
    let mut next_launch = Instant::now();
    let mut attempts = FuturesUnordered::new();
    let mut failures =
        Vec::with_capacity(candidates.len().min(SOCKET_CANDIDATE_ERROR_DETAIL_LIMIT));

    loop {
        let now = Instant::now();
        if attempts.is_empty() && next_index < candidates.len() {
            next_launch = now;
        }
        while next_index < candidates.len() && attempts.len() < max_in_flight && now >= next_launch
        {
            let candidate = candidates[next_index];
            next_index += 1;
            attempted_count += 1;
            attempts.push(run_candidate_attempt(candidate, attempt(candidate)));
            next_launch = Instant::now() + policy.attempt_delay;
        }

        if attempts.is_empty() {
            return Err(SocketCandidateAttemptError::all_failed(
                context,
                candidates.len(),
                failures,
            ));
        }

        let launch_ready = next_index < candidates.len() && attempts.len() < max_in_flight;
        tokio::select! {
            result = attempts.next() => {
                let Some((candidate, result)) = result else {
                    continue;
                };
                match result {
                    Ok(value) => return Ok((candidate, value)),
                    Err(err) if failures.len() < SOCKET_CANDIDATE_ERROR_DETAIL_LIMIT => {
                        failures.push((candidate, err.to_string()));
                    }
                    Err(_) => {}
                }
            }
            _ = tokio::time::sleep_until(next_launch.into()), if launch_ready => {}
            _ = tokio::time::sleep_until(deadline.into()) => {
                return Err(SocketCandidateAttemptError::deadline(
                    context,
                    candidates.len(),
                    attempted_count,
                    failures,
                ));
            }
        }
    }
}

async fn run_candidate_attempt<T, Fut, E>(
    candidate: SocketAddr,
    attempt: Fut,
) -> (SocketAddr, Result<T, E>)
where
    Fut: Future<Output = Result<T, E>>,
{
    (candidate, attempt.await)
}

fn interleave_address_families(candidates: &[SocketAddr]) -> Vec<SocketAddr> {
    let first_is_ipv6 = candidates[0].is_ipv6();
    let mut ipv4 = candidates.iter().copied().filter(SocketAddr::is_ipv4);
    let mut ipv6 = candidates.iter().copied().filter(SocketAddr::is_ipv6);
    let mut ordered = Vec::with_capacity(candidates.len());
    let mut prefer_ipv6 = first_is_ipv6;
    while ordered.len() < candidates.len() {
        let next = if prefer_ipv6 {
            ipv6.next().or_else(|| ipv4.next())
        } else {
            ipv4.next().or_else(|| ipv6.next())
        };
        let Some(next) = next else {
            break;
        };
        ordered.push(next);
        prefer_ipv6 = !next.is_ipv6();
    }
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn candidate_order_alternates_families_without_reordering_each_family() {
        let v6_first = "[2001:db8::1]:443".parse().unwrap();
        let v6_second = "[2001:db8::2]:443".parse().unwrap();
        let v4_first = "192.0.2.1:443".parse().unwrap();
        let v4_second = "192.0.2.2:443".parse().unwrap();
        assert_eq!(
            interleave_address_families(&[v6_first, v6_second, v4_first, v4_second]),
            [v6_first, v4_first, v6_second, v4_second]
        );
    }

    #[tokio::test]
    async fn successful_candidate_closes_the_losing_tcp_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first = listener.local_addr().unwrap();
        let second = "127.0.0.1:9".parse().unwrap();
        let result = try_tcp_socket_addr_candidates(
            &[first, second],
            "race TCP candidates",
            TcpCandidateRacePolicy::new(Duration::from_millis(5), Duration::from_secs(1), 2),
            move |candidate| async move {
                if candidate == first {
                    let _stream = tokio::net::TcpStream::connect(candidate)
                        .await
                        .map_err(|err| err.to_string())?;
                    std::future::pending::<Result<&'static str, String>>().await
                } else {
                    Ok("connected")
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(result, (second, "connected"));
        let (mut accepted, _) = listener.accept().await.unwrap();
        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), accepted.read(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, 0);
    }
}
