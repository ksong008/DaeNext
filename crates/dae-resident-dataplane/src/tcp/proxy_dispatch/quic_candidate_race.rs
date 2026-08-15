use std::collections::VecDeque;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Instant;

use dae_runtime_control::{AbsoluteDeadline, OwnerCancellation, OwnerCancellationSignal};
use futures_util::stream::{FuturesUnordered, StreamExt};

use crate::{QuicCandidateRaceResourceProfile, RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE};

const QUIC_CANDIDATE_FAILURE_DETAIL_LIMIT: usize = 8;

#[derive(Debug)]
pub(crate) enum QuicCandidateAttemptFailure<E> {
    Retryable(E),
    Terminal(E),
}

#[derive(Debug)]
pub(crate) enum QuicCandidateRaceFailure<E> {
    Empty,
    Exhausted {
        candidate_count: usize,
        failures: Vec<(SocketAddr, E)>,
    },
    Deadline {
        candidate_count: usize,
        started_count: usize,
        failures: Vec<(SocketAddr, E)>,
    },
    Cancelled(OwnerCancellation),
    Terminal {
        candidate: SocketAddr,
        error: E,
    },
}

type QuicCandidateAttemptFuture<'a, T, E> = Pin<
    Box<dyn Future<Output = (SocketAddr, Result<T, QuicCandidateAttemptFailure<E>>)> + Send + 'a>,
>;

pub(crate) async fn race_quic_candidates<'a, T, E, F, Fut>(
    candidates: &[SocketAddr],
    deadline: AbsoluteDeadline,
    cancellation: &OwnerCancellationSignal,
    resources: QuicCandidateRaceResourceProfile,
    mut attempt: F,
) -> Result<T, QuicCandidateRaceFailure<E>>
where
    T: Send + 'a,
    E: Send + 'a,
    F: FnMut(SocketAddr, AbsoluteDeadline, OwnerCancellationSignal) -> Fut,
    Fut: Future<Output = Result<T, QuicCandidateAttemptFailure<E>>> + Send + 'a,
{
    if candidates.is_empty() {
        return Err(QuicCandidateRaceFailure::Empty);
    }

    let candidate_count = candidates.len();
    let max_in_flight = resources.max_in_flight().max(1).min(candidate_count);
    let candidate_wave_count = candidate_count.div_ceil(max_in_flight);
    let attempt_timeout = deadline
        .remaining_at(Instant::now())
        .and_then(|remaining| {
            remaining.checked_div(u32::try_from(candidate_wave_count).unwrap_or(u32::MAX))
        })
        .unwrap_or_default();
    let mut remaining = candidates.iter().copied().collect::<VecDeque<_>>();
    let mut attempts = FuturesUnordered::<QuicCandidateAttemptFuture<'a, T, E>>::new();
    let mut attempt_cancellations = Vec::with_capacity(max_in_flight);
    let mut failures = Vec::with_capacity(candidate_count.min(QUIC_CANDIDATE_FAILURE_DETAIL_LIMIT));
    let mut started_count = 0_usize;

    start_next_candidate(
        &mut remaining,
        &mut attempts,
        &mut attempt_cancellations,
        &mut attempt,
        deadline,
        attempt_timeout,
    );
    started_count += 1;
    let mut next_launch_at = Instant::now() + resources.stagger();

    loop {
        if attempts.is_empty() {
            if remaining.is_empty() {
                return Err(QuicCandidateRaceFailure::Exhausted {
                    candidate_count,
                    failures,
                });
            }
            start_next_candidate(
                &mut remaining,
                &mut attempts,
                &mut attempt_cancellations,
                &mut attempt,
                deadline,
                attempt_timeout,
            );
            started_count += 1;
            next_launch_at = Instant::now() + resources.stagger();
        }

        let can_launch = attempts.len() < max_in_flight && !remaining.is_empty();
        let launch_deadline = tokio::time::Instant::from_std(next_launch_at);
        let absolute_deadline = tokio::time::Instant::from_std(deadline.instant());
        tokio::select! {
            reason = cancellation.cancelled() => {
                cancel_and_drain_candidate_attempts(
                    &mut attempts,
                    &attempt_cancellations,
                    OwnerCancellation::CallerCancelled,
                ).await;
                return Err(QuicCandidateRaceFailure::Cancelled(reason));
            }
            _ = tokio::time::sleep_until(absolute_deadline) => {
                cancel_and_drain_candidate_attempts(
                    &mut attempts,
                    &attempt_cancellations,
                    OwnerCancellation::DeadlineElapsed,
                ).await;
                return Err(QuicCandidateRaceFailure::Deadline {
                    candidate_count,
                    started_count,
                    failures,
                });
            }
            _ = tokio::time::sleep_until(launch_deadline), if can_launch => {
                start_next_candidate(
                    &mut remaining,
                    &mut attempts,
                    &mut attempt_cancellations,
                    &mut attempt,
                    deadline,
                    attempt_timeout,
                );
                started_count += 1;
                next_launch_at = Instant::now() + resources.stagger();
            }
            result = attempts.next() => {
                let Some((candidate, result)) = result else {
                    continue;
                };
                match result {
                    Ok(value) => {
                        cancel_and_drain_candidate_attempts(
                            &mut attempts,
                            &attempt_cancellations,
                            OwnerCancellation::CallerCancelled,
                        ).await;
                        return Ok(value);
                    }
                    Err(QuicCandidateAttemptFailure::Retryable(error)) => {
                        if failures.len() < QUIC_CANDIDATE_FAILURE_DETAIL_LIMIT {
                            failures.push((candidate, error));
                        }
                        if attempts.is_empty() && !remaining.is_empty() {
                            start_next_candidate(
                                &mut remaining,
                                &mut attempts,
                                &mut attempt_cancellations,
                                &mut attempt,
                                deadline,
                                attempt_timeout,
                            );
                            started_count += 1;
                            next_launch_at = Instant::now() + resources.stagger();
                        }
                    }
                    Err(QuicCandidateAttemptFailure::Terminal(error)) => {
                        cancel_and_drain_candidate_attempts(
                            &mut attempts,
                            &attempt_cancellations,
                            OwnerCancellation::CallerCancelled,
                        ).await;
                        return Err(QuicCandidateRaceFailure::Terminal { candidate, error });
                    }
                }
            }
        }
    }
}

fn start_next_candidate<'a, T, E, F, Fut>(
    remaining: &mut VecDeque<SocketAddr>,
    attempts: &mut FuturesUnordered<QuicCandidateAttemptFuture<'a, T, E>>,
    cancellations: &mut Vec<OwnerCancellationSignal>,
    attempt: &mut F,
    deadline: AbsoluteDeadline,
    attempt_timeout: std::time::Duration,
) -> bool
where
    T: Send + 'a,
    E: Send + 'a,
    F: FnMut(SocketAddr, AbsoluteDeadline, OwnerCancellationSignal) -> Fut,
    Fut: Future<Output = Result<T, QuicCandidateAttemptFailure<E>>> + Send + 'a,
{
    let Some(candidate) = remaining.pop_front() else {
        return false;
    };
    let cancellation = OwnerCancellationSignal::new();
    let now = Instant::now();
    let attempt_deadline = AbsoluteDeadline::at(
        now.checked_add(attempt_timeout)
            .unwrap_or_else(|| deadline.instant())
            .min(deadline.instant()),
    );
    let future = attempt(candidate, attempt_deadline, cancellation.clone());
    cancellations.push(cancellation);
    attempts.push(Box::pin(async move { (candidate, future.await) }));
    true
}

async fn cancel_and_drain_candidate_attempts<T, E>(
    attempts: &mut FuturesUnordered<QuicCandidateAttemptFuture<'_, T, E>>,
    cancellations: &[OwnerCancellationSignal],
    reason: OwnerCancellation,
) {
    for cancellation in cancellations {
        cancellation.cancel(reason);
    }
    let _ = tokio::time::timeout(RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE, async {
        while attempts.next().await.is_some() {}
    })
    .await;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn staggered_candidate_race_uses_healthy_second_candidate_and_cancels_loser() {
        let first = SocketAddr::from(([192, 0, 2, 1], 443));
        let second = SocketAddr::from(([192, 0, 2, 2], 443));
        let loser_cancelled = Arc::new(AtomicUsize::new(0));
        let cancellation = OwnerCancellationSignal::new();
        let resources = QuicCandidateRaceResourceProfile::for_test(2, Duration::from_millis(5));

        let selected = race_quic_candidates(
            &[first, second],
            AbsoluteDeadline::from_now(Instant::now(), Duration::from_secs(1)),
            &cancellation,
            resources,
            {
                let loser_cancelled = Arc::clone(&loser_cancelled);
                move |candidate, _attempt_deadline, attempt_cancellation| {
                    let loser_cancelled = Arc::clone(&loser_cancelled);
                    async move {
                        if candidate == first {
                            attempt_cancellation.cancelled().await;
                            loser_cancelled.fetch_add(1, Ordering::Relaxed);
                            Err(QuicCandidateAttemptFailure::Retryable("cancelled"))
                        } else {
                            Ok(candidate)
                        }
                    }
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(selected, second);
        assert_eq!(loser_cancelled.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn candidate_race_never_exceeds_configured_width() {
        let candidates = (1..=4)
            .map(|last| SocketAddr::from(([192, 0, 2, last], 443)))
            .collect::<Vec<_>>();
        let active = Arc::new(AtomicUsize::new(0));
        let high_water = Arc::new(AtomicUsize::new(0));
        let cancellation = OwnerCancellationSignal::new();
        let resources = QuicCandidateRaceResourceProfile::for_test(2, Duration::from_millis(1));

        let error = race_quic_candidates(
            &candidates,
            AbsoluteDeadline::from_now(Instant::now(), Duration::from_millis(25)),
            &cancellation,
            resources,
            {
                let active = Arc::clone(&active);
                let high_water = Arc::clone(&high_water);
                move |_candidate, _attempt_deadline, attempt_cancellation| {
                    let active = Arc::clone(&active);
                    let high_water = Arc::clone(&high_water);
                    async move {
                        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                        high_water.fetch_max(current, Ordering::SeqCst);
                        attempt_cancellation.cancelled().await;
                        active.fetch_sub(1, Ordering::SeqCst);
                        Err::<SocketAddr, _>(QuicCandidateAttemptFailure::Retryable("cancelled"))
                    }
                }
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(error, QuicCandidateRaceFailure::Deadline { .. }));
        assert!(high_water.load(Ordering::SeqCst) <= 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}
