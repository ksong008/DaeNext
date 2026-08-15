use std::future::Future;
use std::pin::Pin;

use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::time;

use super::{ObservedQuicEndpoint, QuicEndpointReleaseProbe};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct QuicEndpointDrainReport {
    requested: usize,
    idle_completed: usize,
    released: usize,
    forced_released: usize,
}

impl QuicEndpointDrainReport {
    pub(crate) const fn requested(self) -> usize {
        self.requested
    }

    pub(crate) const fn completed(self) -> usize {
        self.released
    }

    pub(crate) const fn idle_completed(self) -> usize {
        self.idle_completed
    }

    pub(crate) const fn forced_released(self) -> usize {
        self.forced_released
    }

    pub(crate) const fn timed_out(self) -> usize {
        self.requested.saturating_sub(self.released)
    }

    pub(crate) const fn is_complete(self) -> bool {
        self.requested == self.released
    }
}

type QuicEndpointIdleFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
type IndexedQuicEndpointFuture = Pin<Box<dyn Future<Output = usize> + Send>>;

pub(crate) fn quic_endpoint_drain_deadlines(
    started: time::Instant,
    resource_grace: std::time::Duration,
) -> (time::Instant, time::Instant) {
    // Reserve half of the existing bounded cleanup contract for verified local release after the
    // peer notification window. This does not enlarge the caller's transport-task join budget.
    let peer_close_deadline = started + resource_grace / 2;
    let resource_release_deadline = started + resource_grace;
    (peer_close_deadline, resource_release_deadline)
}

pub(crate) async fn wait_quic_endpoints_idle_until(
    endpoints: Vec<ObservedQuicEndpoint>,
    deadline: time::Instant,
) -> QuicEndpointDrainReport {
    let requested = endpoints.len();
    let waits = endpoints
        .into_iter()
        .map(|endpoint| {
            Box::pin(async move {
                endpoint.wait_idle().await;
            }) as QuicEndpointIdleFuture
        })
        .collect();
    let idle_completed = wait_quic_endpoint_idle_futures_until(waits, deadline).await;
    QuicEndpointDrainReport {
        requested,
        idle_completed,
        released: idle_completed,
        forced_released: 0,
    }
}

pub(crate) async fn wait_quic_endpoints_idle_or_released_until(
    endpoints: Vec<ObservedQuicEndpoint>,
    peer_close_deadline: time::Instant,
    resource_release_deadline: time::Instant,
) -> QuicEndpointDrainReport {
    let requested = endpoints.len();
    let probes = endpoints
        .iter()
        .map(ObservedQuicEndpoint::release_probe)
        .collect::<Vec<_>>();
    let idle = endpoints
        .into_iter()
        .enumerate()
        .map(|(index, endpoint)| {
            Box::pin(async move {
                endpoint.wait_idle().await;
                index
            }) as IndexedQuicEndpointFuture
        })
        .collect::<Vec<_>>();
    let released = probes
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, probe)| release_future(index, probe))
        .collect::<Vec<_>>();
    wait_quic_endpoint_release_futures_until(
        requested,
        idle,
        released,
        peer_close_deadline.min(resource_release_deadline),
        resource_release_deadline,
        move |idle_by_index| {
            for (index, probe) in probes.iter().enumerate() {
                if !idle_by_index[index] {
                    probe.force_driver_release();
                }
            }
        },
    )
    .await
}

fn release_future(index: usize, probe: QuicEndpointReleaseProbe) -> IndexedQuicEndpointFuture {
    Box::pin(async move {
        probe.released().await;
        index
    })
}

async fn wait_quic_endpoint_idle_futures_until(
    waits: Vec<QuicEndpointIdleFuture>,
    deadline: time::Instant,
) -> usize {
    let mut completed = 0_usize;
    let mut pending = waits.into_iter().collect::<FuturesUnordered<_>>();
    while !pending.is_empty() {
        match time::timeout_at(deadline, pending.next()).await {
            Ok(Some(())) => completed = completed.saturating_add(1),
            Ok(None) => break,
            Err(_) => break,
        }
    }
    drop(pending);
    completed
}

async fn wait_quic_endpoint_release_futures_until<F>(
    requested: usize,
    idle: Vec<IndexedQuicEndpointFuture>,
    released: Vec<IndexedQuicEndpointFuture>,
    peer_close_deadline: time::Instant,
    resource_release_deadline: time::Instant,
    on_peer_close_phase_complete: F,
) -> QuicEndpointDrainReport
where
    F: FnOnce(&[bool]),
{
    debug_assert_eq!(requested, idle.len());
    debug_assert_eq!(requested, released.len());
    let mut idle_by_index = vec![false; requested];
    let mut pending_idle = idle.into_iter().collect::<FuturesUnordered<_>>();
    while !pending_idle.is_empty() {
        match time::timeout_at(peer_close_deadline, pending_idle.next()).await {
            Ok(Some(index)) => idle_by_index[index] = true,
            Ok(None) => break,
            Err(_) => break,
        }
    }

    // Dropping the remaining wait futures drops their Endpoint handles. The per-Endpoint release
    // signals below complete only after Quinn's driver and abstract UDP socket have also dropped.
    drop(pending_idle);
    on_peer_close_phase_complete(&idle_by_index);

    let mut released_by_index = vec![false; requested];
    let mut pending_releases = released.into_iter().collect::<FuturesUnordered<_>>();
    while !pending_releases.is_empty() {
        match time::timeout_at(resource_release_deadline, pending_releases.next()).await {
            Ok(Some(index)) => released_by_index[index] = true,
            Ok(None) => break,
            Err(_) => break,
        }
    }
    drop(pending_releases);

    let idle_completed = idle_by_index.iter().filter(|completed| **completed).count();
    let released = released_by_index
        .iter()
        .filter(|completed| **completed)
        .count();
    let forced_released = released_by_index
        .iter()
        .zip(idle_by_index.iter())
        .filter(|(released, idle)| **released && !**idle)
        .count();
    QuicEndpointDrainReport {
        requested,
        idle_completed,
        released,
        forced_released,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn indexed_future(index: usize, delay: Duration) -> IndexedQuicEndpointFuture {
        Box::pin(async move {
            if !delay.is_zero() {
                time::sleep(delay).await;
            }
            index
        })
    }

    #[test]
    fn peer_close_and_resource_release_share_the_existing_bounded_grace() {
        let started = time::Instant::now();
        let grace = Duration::from_millis(1_500);
        let (peer_close, resource_release) = quic_endpoint_drain_deadlines(started, grace);

        assert_eq!(peer_close.duration_since(started), grace / 2);
        assert_eq!(resource_release.duration_since(started), grace);
        assert!(peer_close < resource_release);
    }

    #[tokio::test]
    async fn concurrent_idle_and_release_complete_under_the_shared_deadline() {
        let idle = (0..16)
            .map(|index| indexed_future(index, Duration::from_millis(30)))
            .collect();
        let released = (0..16)
            .map(|index| indexed_future(index, Duration::ZERO))
            .collect();
        let started = time::Instant::now();
        let report = wait_quic_endpoint_release_futures_until(
            16,
            idle,
            released,
            started + Duration::from_millis(100),
            started + Duration::from_millis(150),
            |_| {},
        )
        .await;

        assert_eq!(report.requested(), 16);
        assert_eq!(report.idle_completed(), 16);
        assert_eq!(report.completed(), 16);
        assert_eq!(report.forced_released(), 0);
        assert_eq!(report.timed_out(), 0);
        assert!(report.is_complete());
    }

    #[tokio::test]
    async fn peer_close_timeout_is_distinct_from_verified_local_release() {
        let idle = vec![
            indexed_future(0, Duration::ZERO),
            indexed_future(1, Duration::from_millis(10)),
            indexed_future(2, Duration::from_secs(1)),
        ];
        let released = (0..3)
            .map(|index| indexed_future(index, Duration::ZERO))
            .collect();
        let started = time::Instant::now();
        let report = wait_quic_endpoint_release_futures_until(
            3,
            idle,
            released,
            started + Duration::from_millis(50),
            started + Duration::from_millis(100),
            |_| {},
        )
        .await;

        assert_eq!(report.idle_completed(), 2);
        assert_eq!(report.completed(), 3);
        assert_eq!(report.forced_released(), 1);
        assert_eq!(report.timed_out(), 0);
        assert!(report.is_complete());
    }

    #[tokio::test]
    async fn unreleased_local_resource_still_fails_the_resource_deadline() {
        let idle = vec![indexed_future(0, Duration::from_secs(1))];
        let released = vec![indexed_future(0, Duration::from_secs(1))];
        let started = time::Instant::now();
        let report = wait_quic_endpoint_release_futures_until(
            1,
            idle,
            released,
            started + Duration::from_millis(10),
            started + Duration::from_millis(30),
            |_| {},
        )
        .await;

        assert_eq!(report.idle_completed(), 0);
        assert_eq!(report.completed(), 0);
        assert_eq!(report.forced_released(), 0);
        assert_eq!(report.timed_out(), 1);
        assert!(!report.is_complete());
    }
}
