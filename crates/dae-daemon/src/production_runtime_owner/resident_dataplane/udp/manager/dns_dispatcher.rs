use std::future::Future;

use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use super::*;

struct ResidentDnsFastPathRequest {
    packet: UdpOriginalDstPacket,
    original_dst: SocketAddr,
}

struct ResidentDnsFastPathActiveGuard {
    metrics: Arc<ResidentDataplaneMetrics>,
    finished: bool,
}

impl ResidentDnsFastPathActiveGuard {
    fn new(metrics: Arc<ResidentDataplaneMetrics>) -> Self {
        metrics.dns_fast_path_started();
        Self {
            metrics,
            finished: false,
        }
    }

    fn finish(mut self, failed: bool) {
        self.metrics.dns_fast_path_finished(failed);
        self.finished = true;
    }
}

impl Drop for ResidentDnsFastPathActiveGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.metrics.dns_fast_path_cancelled();
        }
    }
}

#[derive(Clone)]
pub(super) struct ResidentDnsFastPathHandle {
    sender: mpsc::Sender<ResidentDnsFastPathRequest>,
    closing: Arc<AtomicBool>,
    metrics: Arc<ResidentDataplaneMetrics>,
    udp_reply: UdpReplyHandle,
}

pub(super) struct ResidentDnsFastPathDispatcher {
    handle: ResidentDnsFastPathHandle,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<usize>,
}

impl ResidentDnsFastPathDispatcher {
    pub(super) fn start(
        dns: Arc<ResidentDnsPlan>,
        udp_reply: UdpReplyHandle,
        metrics: Arc<ResidentDataplaneMetrics>,
        concurrency: usize,
        queue_depth: usize,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(queue_depth.max(1));
        let (stop, stop_receiver) = oneshot::channel();
        let closing = Arc::new(AtomicBool::new(false));
        let task_metrics = Arc::clone(&metrics);
        let task_reply = udp_reply.clone();
        let task = tokio::spawn(async move {
            run_resident_dns_fast_path_dispatcher(
                dns,
                task_reply,
                task_metrics,
                receiver,
                stop_receiver,
                concurrency.max(1),
            )
            .await
        });
        Self {
            handle: ResidentDnsFastPathHandle {
                sender,
                closing,
                metrics,
                udp_reply,
            },
            stop: Some(stop),
            task,
        }
    }

    pub(super) fn handle(&self) -> ResidentDnsFastPathHandle {
        self.handle.clone()
    }

    pub(super) async fn shutdown(mut self, deadline: time::Instant) -> Result<usize, String> {
        self.handle.closing.store(true, Ordering::Release);
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match time::timeout_at(deadline, &mut self.task).await {
            Ok(Ok(completed)) => Ok(completed),
            Ok(Err(err)) => Err(format!(
                "resident DNS fast-path dispatcher join failed: {err}"
            )),
            Err(_) => {
                self.task.abort();
                let _ = (&mut self.task).await;
                Err(
                    "resident DNS fast-path dispatcher exceeded the generation shutdown deadline"
                        .to_owned(),
                )
            }
        }
    }
}

impl ResidentDnsFastPathHandle {
    pub(super) fn try_dispatch(
        &self,
        packet: UdpOriginalDstPacket,
        original_dst: SocketAddr,
    ) -> bool {
        self.metrics.add_upload(packet.payload.len());
        let request = ResidentDnsFastPathRequest {
            packet,
            original_dst,
        };
        if self.closing.load(Ordering::Acquire) {
            self.reject(request);
            return false;
        }
        match self.sender.try_send(request) {
            Ok(()) => {
                self.metrics.dns_fast_path_queued();
                true
            }
            Err(mpsc::error::TrySendError::Full(request))
            | Err(mpsc::error::TrySendError::Closed(request)) => {
                self.reject(request);
                false
            }
        }
    }

    fn reject(&self, request: ResidentDnsFastPathRequest) {
        self.metrics.dns_fast_path_rejected();
        let Ok(response) = build_dns_server_failure_response(&request.packet.payload) else {
            return;
        };
        let _ = self.udp_reply.try_send_detached(
            request.original_dst,
            request.packet.peer,
            response,
            true,
        );
    }
}

async fn run_resident_dns_fast_path_dispatcher(
    dns: Arc<ResidentDnsPlan>,
    udp_reply: UdpReplyHandle,
    metrics: Arc<ResidentDataplaneMetrics>,
    receiver: mpsc::Receiver<ResidentDnsFastPathRequest>,
    stop: oneshot::Receiver<()>,
    concurrency: usize,
) -> usize {
    run_bounded_dns_futures(receiver, stop, concurrency, move |request| {
        run_resident_dns_fast_path_request(
            Arc::clone(&dns),
            udp_reply.clone(),
            Arc::clone(&metrics),
            request,
        )
    })
    .await
}

async fn run_bounded_dns_futures<Request, Handler, RequestFuture>(
    mut receiver: mpsc::Receiver<Request>,
    mut stop: oneshot::Receiver<()>,
    concurrency: usize,
    mut handler: Handler,
) -> usize
where
    Handler: FnMut(Request) -> RequestFuture,
    RequestFuture: Future<Output = ()>,
{
    let mut in_flight = FuturesUnordered::new();
    let mut stopping = false;
    let mut completed = 0_usize;
    loop {
        if stopping && receiver.is_empty() && in_flight.is_empty() {
            break;
        }
        tokio::select! {
            biased;
            _ = &mut stop, if !stopping => {
                stopping = true;
                receiver.close();
            }
            Some(()) = in_flight.next(), if !in_flight.is_empty() => {
                completed = completed.saturating_add(1);
            }
            request = receiver.recv(), if in_flight.len() < concurrency => {
                match request {
                    Some(request) => {
                        in_flight.push(handler(request));
                    }
                    None => stopping = true,
                }
            }
        }
    }
    completed
}

async fn run_resident_dns_fast_path_request(
    dns: Arc<ResidentDnsPlan>,
    udp_reply: UdpReplyHandle,
    metrics: Arc<ResidentDataplaneMetrics>,
    request: ResidentDnsFastPathRequest,
) {
    let active = ResidentDnsFastPathActiveGuard::new(Arc::clone(&metrics));
    let mut failed = false;
    let response = match time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        handle_resident_dns_udp_async(&dns, request.original_dst, &request.packet.payload),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(_)) | Err(_) => {
            failed = true;
            match build_dns_server_failure_response(&request.packet.payload) {
                Ok(response) => response,
                Err(_) => {
                    active.finish(true);
                    return;
                }
            }
        }
    };
    let response_len = response.len();
    if udp_reply
        .send(request.original_dst, request.packet.peer, response)
        .await
        .is_ok()
    {
        metrics.add_download(response_len);
    } else {
        failed = true;
    }
    active.finish(failed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_request_guard_releases_active_capacity() {
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        {
            let _active = ResidentDnsFastPathActiveGuard::new(Arc::clone(&metrics));
            assert_eq!(metrics.snapshot()["dnsFastPathActive"], 1);
        }
        assert_eq!(metrics.snapshot()["dnsFastPathActive"], 0);
        assert_eq!(metrics.snapshot()["dnsFastPathCancelled"], 1);
    }

    #[tokio::test]
    async fn bounded_dispatcher_runs_requests_concurrently_without_exceeding_limit() {
        let (sender, receiver) = mpsc::channel(8);
        for request in 0_u8..8 {
            sender.try_send(request).unwrap();
        }
        drop(sender);
        let (_stop, stop_receiver) = oneshot::channel();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let task_gate = Arc::clone(&gate);
        let task_active = Arc::clone(&active);
        let task_maximum = Arc::clone(&maximum);

        let task = tokio::spawn(run_bounded_dns_futures(
            receiver,
            stop_receiver,
            3,
            move |_| {
                let gate = Arc::clone(&task_gate);
                let active = Arc::clone(&task_active);
                let maximum = Arc::clone(&task_maximum);
                async move {
                    let current = active.fetch_add(1, Ordering::Relaxed) + 1;
                    maximum.fetch_max(current, Ordering::Relaxed);
                    let permit = gate.acquire().await.unwrap();
                    permit.forget();
                    active.fetch_sub(1, Ordering::Relaxed);
                }
            },
        ));

        time::timeout(Duration::from_secs(1), async {
            while maximum.load(Ordering::Relaxed) < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(maximum.load(Ordering::Relaxed), 3);
        gate.add_permits(8);
        assert_eq!(task.await.unwrap(), 8);
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "explicit scheduler microbenchmark"]
    async fn dns_dispatcher_scheduler_microbenchmark() {
        const REQUESTS: usize = 50_000;
        const CONCURRENCY: usize = 512;
        const QUEUE_DEPTH: usize = 1_024;

        let dispatcher_elapsed =
            benchmark_bounded_dispatcher(REQUESTS, CONCURRENCY, QUEUE_DEPTH).await;
        let spawned_elapsed = benchmark_spawn_per_request(REQUESTS, CONCURRENCY).await;
        eprintln!(
            "dns_dispatcher_scheduler_benchmark {}",
            json!({
                "requests": REQUESTS,
                "concurrency": CONCURRENCY,
                "queueDepth": QUEUE_DEPTH,
                "boundedDispatcherNsPerRequest": dispatcher_elapsed.as_nanos() / REQUESTS as u128,
                "spawnPerRequestNsPerRequest": spawned_elapsed.as_nanos() / REQUESTS as u128,
            })
        );
    }

    async fn benchmark_bounded_dispatcher(
        requests: usize,
        concurrency: usize,
        queue_depth: usize,
    ) -> Duration {
        let (sender, receiver) = mpsc::channel(queue_depth);
        let (_stop, stop_receiver) = oneshot::channel();
        let actor = tokio::spawn(run_bounded_dns_futures(
            receiver,
            stop_receiver,
            concurrency,
            |_| async {},
        ));
        let started = Instant::now();
        for request in 0..requests {
            sender.send(request).await.unwrap();
        }
        drop(sender);
        assert_eq!(actor.await.unwrap(), requests);
        started.elapsed()
    }

    async fn benchmark_spawn_per_request(requests: usize, concurrency: usize) -> Duration {
        let permits = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let mut tasks = tokio::task::JoinSet::new();
        let started = Instant::now();
        for _ in 0..requests {
            let permit = Arc::clone(&permits).acquire_owned().await.unwrap();
            tasks.spawn(async move {
                drop(permit);
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        started.elapsed()
    }
}
