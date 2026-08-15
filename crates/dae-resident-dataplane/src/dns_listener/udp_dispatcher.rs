use std::future::Future;

use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::sync::mpsc;

use super::*;

pub(super) struct ResidentDnsUdpBindJob {
    pub(super) peer: SocketAddr,
    pub(super) dns: Arc<ResidentDnsPlan>,
    pub(super) metrics: Arc<ResidentDataplaneMetrics>,
    pub(super) request: Vec<u8>,
    pub(super) flow_stop: SharedResidentStopSignal,
    pub(super) permit: tokio::sync::OwnedSemaphorePermit,
}

pub(super) struct ResidentDnsUdpBindDispatcher {
    senders: Vec<mpsc::Sender<ResidentDnsUdpBindJob>>,
    workers: tokio::task::JoinSet<usize>,
    next_shard: usize,
}

impl ResidentDnsUdpBindDispatcher {
    pub(super) fn start(
        socket: Arc<TokioUdpSocket>,
        local_addr: SocketAddr,
        event_file: PathBuf,
        event_lock: Arc<Mutex<()>>,
        requested_shards: usize,
        max_inflight: usize,
    ) -> Self {
        let max_inflight = max_inflight.max(1);
        let shard_count = requested_shards.max(1).min(max_inflight);
        let shard_capacity = Self::shard_capacity(max_inflight, shard_count);
        let mut senders = Vec::with_capacity(shard_count);
        let mut workers = tokio::task::JoinSet::new();
        for _ in 0..shard_count {
            let (sender, receiver) = mpsc::channel(shard_capacity);
            senders.push(sender);
            workers.spawn(run_resident_dns_udp_bind_worker_async(
                receiver,
                shard_capacity,
                Arc::clone(&socket),
                local_addr,
                event_file.clone(),
                Arc::clone(&event_lock),
            ));
        }
        Self {
            senders,
            workers,
            next_shard: 0,
        }
    }

    pub(super) fn shard_count(&self) -> usize {
        self.senders.len()
    }

    pub(super) fn try_dispatch(
        &mut self,
        job: ResidentDnsUdpBindJob,
    ) -> Result<(), ResidentDnsUdpBindJob> {
        try_dispatch_round_robin(&self.senders, &mut self.next_shard, job)
    }

    pub(super) async fn shutdown(&mut self, grace: Duration) -> ResidentTaskSetShutdown {
        self.senders.clear();
        shutdown_resident_task_set(&mut self.workers, grace).await
    }

    fn shard_capacity(max_inflight: usize, shard_count: usize) -> usize {
        let shard_count = shard_count.max(1);
        max_inflight
            .max(1)
            .saturating_add(shard_count.saturating_sub(1))
            / shard_count
    }
}

fn try_dispatch_round_robin<T>(
    senders: &[mpsc::Sender<T>],
    next_shard: &mut usize,
    mut value: T,
) -> Result<(), T> {
    if senders.is_empty() {
        return Err(value);
    }
    let start = *next_shard % senders.len();
    for offset in 0..senders.len() {
        let shard = (start + offset) % senders.len();
        match senders[shard].try_send(value) {
            Ok(()) => {
                *next_shard = (shard + 1) % senders.len();
                return Ok(());
            }
            Err(mpsc::error::TrySendError::Full(returned))
            | Err(mpsc::error::TrySendError::Closed(returned)) => value = returned,
        }
    }
    Err(value)
}

async fn run_resident_dns_udp_bind_worker_async(
    receiver: mpsc::Receiver<ResidentDnsUdpBindJob>,
    concurrency: usize,
    socket: Arc<TokioUdpSocket>,
    local_addr: SocketAddr,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
) -> usize {
    run_bounded_udp_bind_futures(receiver, concurrency, move |job| {
        let ResidentDnsUdpBindJob {
            peer,
            dns,
            metrics,
            request,
            flow_stop,
            permit,
        } = job;
        let socket = Arc::clone(&socket);
        let event_file = event_file.clone();
        let event_lock = Arc::clone(&event_lock);
        async move {
            let _ = run_until_resident_stop(
                &flow_stop,
                handle_resident_dns_udp_bind_packet_async(
                    socket, local_addr, peer, dns, metrics, request, event_file, event_lock, permit,
                ),
            )
            .await;
        }
    })
    .await
}

async fn run_bounded_udp_bind_futures<Request, Handler, RequestFuture>(
    mut receiver: mpsc::Receiver<Request>,
    concurrency: usize,
    mut handler: Handler,
) -> usize
where
    Handler: FnMut(Request) -> RequestFuture,
    RequestFuture: Future<Output = ()>,
{
    let concurrency = concurrency.max(1);
    let mut in_flight = FuturesUnordered::new();
    let mut receiver_closed = false;
    let mut completed = 0_usize;
    loop {
        if receiver_closed && in_flight.is_empty() {
            return completed;
        }
        tokio::select! {
            biased;
            Some(()) = in_flight.next(), if !in_flight.is_empty() => {
                completed = completed.saturating_add(1);
            }
            request = receiver.recv(), if !receiver_closed && in_flight.len() < concurrency => {
                match request {
                    Some(request) => in_flight.push(handler(request)),
                    None => receiver_closed = true,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    #[test]
    fn shard_capacity_covers_without_expanding_the_global_contract() {
        for (inflight, shards) in [(256, 1), (256, 4), (1_024, 4), (4_096, 4), (5, 2)] {
            let capacity = ResidentDnsUdpBindDispatcher::shard_capacity(inflight, shards);
            let aggregate = capacity * shards;
            assert!(aggregate >= inflight);
            assert!(aggregate - inflight < shards);
        }
    }

    #[tokio::test]
    async fn round_robin_dispatch_uses_each_bounded_shard_before_rejecting() {
        let (first_sender, mut first_receiver) = mpsc::channel(1);
        let (second_sender, mut second_receiver) = mpsc::channel(1);
        let senders = vec![first_sender, second_sender];
        let mut next_shard = 0;

        assert_eq!(
            try_dispatch_round_robin(&senders, &mut next_shard, 1),
            Ok(())
        );
        assert_eq!(
            try_dispatch_round_robin(&senders, &mut next_shard, 2),
            Ok(())
        );
        assert_eq!(
            try_dispatch_round_robin(&senders, &mut next_shard, 3),
            Err(3)
        );
        assert_eq!(first_receiver.recv().await, Some(1));
        assert_eq!(second_receiver.recv().await, Some(2));
    }

    #[tokio::test]
    async fn bounded_worker_overlaps_slow_requests_without_exceeding_concurrency() {
        let (sender, receiver) = mpsc::channel(8);
        for request in 0_u8..8 {
            sender.try_send(request).unwrap();
        }
        drop(sender);
        let gate = Arc::new(Semaphore::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let worker_gate = Arc::clone(&gate);
        let worker_active = Arc::clone(&active);
        let worker_maximum = Arc::clone(&maximum);

        let worker = tokio::spawn(run_bounded_udp_bind_futures(receiver, 3, move |_| {
            let gate = Arc::clone(&worker_gate);
            let active = Arc::clone(&worker_active);
            let maximum = Arc::clone(&worker_maximum);
            async move {
                let current = active.fetch_add(1, Ordering::Relaxed) + 1;
                maximum.fetch_max(current, Ordering::Relaxed);
                let permit = gate.acquire().await.unwrap();
                permit.forget();
                active.fetch_sub(1, Ordering::Relaxed);
            }
        }));

        time::timeout(Duration::from_secs(1), async {
            while maximum.load(Ordering::Relaxed) < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(maximum.load(Ordering::Relaxed), 3);
        gate.add_permits(8);
        assert_eq!(worker.await.unwrap(), 8);
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }
}
