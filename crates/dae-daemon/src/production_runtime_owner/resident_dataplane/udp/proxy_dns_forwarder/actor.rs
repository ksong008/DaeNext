use std::collections::{HashMap, VecDeque};

use super::*;
use crate::production_runtime_owner::resident_dataplane::dns::{
    ResidentDnsUdpActorLifecycle, ResidentDnsUdpActorRegistration,
};

mod executor_state;
mod pending;
mod transaction;

use self::executor_state::{reset_proxy_dns_udp_executor, wait_proxy_dns_udp_response};
use self::pending::{
    expire_proxy_dns_udp_requests, fail_proxy_dns_udp_requests, fail_queued_proxy_dns_udp_requests,
    next_proxy_dns_udp_deadline, wait_proxy_dns_udp_deadline,
};
use self::transaction::{
    PendingProxyDnsDeadline, PendingProxyDnsUdpRequest, handle_proxy_dns_udp_request,
    handle_proxy_dns_udp_response,
};

#[derive(Clone)]
pub(super) struct ResidentProxyDnsUdpActorHandle {
    sender: tokio::sync::mpsc::Sender<ResidentProxyDnsUdpRequest>,
    lifecycle: Arc<ResidentDnsUdpActorLifecycle>,
    metrics: Arc<ResidentDataplaneMetrics>,
    attempt_timeout: Duration,
}

pub(super) struct ResidentProxyDnsUdpRequest {
    pub(super) payload: Vec<u8>,
    pub(super) response: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
}

struct ResidentProxyDnsUdpActorMetricGuard {
    metrics: Arc<ResidentDataplaneMetrics>,
    fatal: bool,
}

impl Drop for ResidentProxyDnsUdpActorMetricGuard {
    fn drop(&mut self) {
        self.metrics.dns_udp_actor_closed(self.fatal);
    }
}

enum ResidentProxyDnsUdpActorEvent {
    Stop,
    Request(Option<ResidentProxyDnsUdpRequest>),
    Response(Result<Option<(&'static str, UdpExchangeResult)>, String>),
    Deadline,
}

pub(super) fn start_proxy_dns_udp_actor(
    proxy: Arc<ResidentProxyPlan>,
    original_dst: SocketAddr,
    runtime_config: ResidentDnsUdpRuntimeConfig,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> ResidentDnsUdpActorRegistration<ResidentProxyDnsUdpActorHandle> {
    let (sender, receiver) = tokio::sync::mpsc::channel(runtime_config.queue_depth.max(1));
    let (lifecycle, stop_receiver) = ResidentDnsUdpActorLifecycle::new();
    metrics.dns_udp_actor_opened();
    let task_metrics = Arc::clone(&metrics);
    let actor_config = runtime_config.clone();
    let task = tokio::spawn(async move {
        let mut metric_guard = ResidentProxyDnsUdpActorMetricGuard {
            metrics: task_metrics,
            fatal: false,
        };
        metric_guard.fatal = run_proxy_dns_udp_actor(
            proxy,
            original_dst,
            receiver,
            stop_receiver,
            actor_config,
            Arc::clone(&metric_guard.metrics),
        )
        .await;
        metric_guard.fatal
    });
    ResidentDnsUdpActorRegistration {
        handle: ResidentProxyDnsUdpActorHandle {
            sender,
            lifecycle: Arc::clone(&lifecycle),
            metrics,
            attempt_timeout: runtime_config.attempt_timeout,
        },
        lifecycle: Arc::downgrade(&lifecycle),
        task,
    }
}

impl ResidentProxyDnsUdpActorHandle {
    pub(super) fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    pub(super) fn close(&self) {
        self.lifecycle.stop();
    }

    pub(super) async fn wait_closed(&self, deadline: time::Instant) -> bool {
        if self.is_closed() {
            return true;
        }
        time::timeout_at(deadline, self.sender.closed())
            .await
            .is_ok()
    }

    pub(super) async fn exchange_once(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        match time::timeout(
            self.attempt_timeout,
            self.sender.send(ResidentProxyDnsUdpRequest {
                payload: payload.to_vec(),
                response: response_tx,
            }),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err("proxied DNS UDP actor is closed".to_owned()),
            Err(_) => {
                self.metrics.dns_udp_queue_wait_timeout();
                return Err("proxied DNS UDP actor queue wait timeout".to_owned());
            }
        }
        time::timeout(self.attempt_timeout, response_rx)
            .await
            .map_err(|_| "proxied DNS UDP actor exchange timeout".to_owned())?
            .map_err(|_| "proxied DNS UDP actor dropped response".to_owned())?
    }
}

async fn run_proxy_dns_udp_actor(
    proxy: Arc<ResidentProxyPlan>,
    original_dst: SocketAddr,
    mut receiver: tokio::sync::mpsc::Receiver<ResidentProxyDnsUdpRequest>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
    runtime_config: ResidentDnsUdpRuntimeConfig,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> bool {
    let pending_limit = runtime_config.pending_limit.max(1);
    let mut pending = HashMap::<u16, PendingProxyDnsUdpRequest>::new();
    let mut deadlines = VecDeque::<PendingProxyDnsDeadline>::new();
    let mut id_allocator = UdpRequestIdAllocator::new(runtime_config.attempt_timeout);
    let mut executor = None::<UdpSessionExecutor>;
    let mut next_generation = 1_u64;
    loop {
        expire_proxy_dns_udp_requests(&mut pending, &mut deadlines, &mut id_allocator, &metrics);
        if receiver.is_closed() && pending.is_empty() {
            break;
        }
        let deadline = next_proxy_dns_udp_deadline(&mut deadlines, &pending);
        let event = tokio::select! {
            biased;
            _ = &mut stop => ResidentProxyDnsUdpActorEvent::Stop,
            response = wait_proxy_dns_udp_response(&mut executor, !pending.is_empty()) => {
                ResidentProxyDnsUdpActorEvent::Response(response)
            }
            request = receiver.recv(), if pending.len() < pending_limit => {
                ResidentProxyDnsUdpActorEvent::Request(request)
            }
            _ = wait_proxy_dns_udp_deadline(deadline) => ResidentProxyDnsUdpActorEvent::Deadline,
        };
        match event {
            ResidentProxyDnsUdpActorEvent::Stop => {
                receiver.close();
                let failed = fail_proxy_dns_udp_requests(
                    &mut pending,
                    &mut id_allocator,
                    "proxied DNS UDP actor is shutting down".to_owned(),
                    &metrics,
                )
                .saturating_add(fail_queued_proxy_dns_udp_requests(
                    &mut receiver,
                    "proxied DNS UDP actor is shutting down",
                ));
                metrics.dns_udp_shutdown_failed_requests(failed);
                break;
            }
            ResidentProxyDnsUdpActorEvent::Request(Some(request)) => {
                if let Err(err) = handle_proxy_dns_udp_request(
                    &proxy,
                    original_dst,
                    request,
                    &mut pending,
                    &mut deadlines,
                    &mut id_allocator,
                    &mut next_generation,
                    &mut executor,
                    &runtime_config,
                    &metrics,
                )
                .await
                {
                    fail_proxy_dns_udp_requests(&mut pending, &mut id_allocator, err, &metrics);
                    reset_proxy_dns_udp_executor(
                        &mut executor,
                        runtime_config.attempt_timeout,
                        &metrics,
                    )
                    .await;
                }
            }
            ResidentProxyDnsUdpActorEvent::Request(None) => {
                if pending.is_empty() {
                    break;
                }
            }
            ResidentProxyDnsUdpActorEvent::Response(Ok(Some((_, response)))) => {
                handle_proxy_dns_udp_response(
                    &mut pending,
                    &mut id_allocator,
                    &response.payload,
                    &metrics,
                );
            }
            ResidentProxyDnsUdpActorEvent::Response(Ok(None)) => {
                tokio::task::yield_now().await;
            }
            ResidentProxyDnsUdpActorEvent::Response(Err(err)) => {
                fail_proxy_dns_udp_requests(
                    &mut pending,
                    &mut id_allocator,
                    format!("receive proxied DNS UDP response: {err}"),
                    &metrics,
                );
                reset_proxy_dns_udp_executor(
                    &mut executor,
                    runtime_config.attempt_timeout,
                    &metrics,
                )
                .await;
            }
            ResidentProxyDnsUdpActorEvent::Deadline => {
                expire_proxy_dns_udp_requests(
                    &mut pending,
                    &mut deadlines,
                    &mut id_allocator,
                    &metrics,
                );
            }
        }
    }
    if let Some(mut executor) = executor {
        let _ = time::timeout(runtime_config.attempt_timeout, executor.shutdown()).await;
    }
    false
}
