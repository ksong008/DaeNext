use std::collections::{HashMap, VecDeque};

use super::*;
use crate::production_runtime_owner::resident_dataplane::dns::{
    ProxyDnsQueuedRequestBytes, ProxyDnsRequestContext, ProxyDnsRequestError,
    ProxyDnsRequestFailure, ProxyDnsRequestStage, ProxyDnsResponseBytes,
    ResidentDnsUdpActorCompletion, ResidentDnsUdpActorLifecycle, ResidentDnsUdpActorRegistration,
};
use crate::production_runtime_owner::udp_payload_admission::ResidentUdpPayloadAdmission;

mod executor_state;
mod pending;
mod transaction;

use self::executor_state::{reset_proxy_dns_udp_executor, wait_proxy_dns_udp_response};
use self::pending::{
    expire_proxy_dns_udp_requests, fail_proxy_dns_udp_requests, fail_queued_proxy_dns_udp_requests,
    insert_proxy_dns_udp_deadline, next_proxy_dns_udp_deadline, remove_proxy_dns_udp_deadline,
    wait_proxy_dns_udp_cancellation, wait_proxy_dns_udp_deadline,
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
    payload_admission: ResidentUdpPayloadAdmission,
    task_id: tokio::task::Id,
    completion: Arc<ResidentDnsUdpActorCompletion>,
}

pub(super) struct ResidentProxyDnsUdpRequest {
    pub(super) payload: Vec<u8>,
    pub(super) context: ProxyDnsRequestContext,
    pub(super) bytes: ProxyDnsQueuedRequestBytes,
    pub(super) response:
        tokio::sync::oneshot::Sender<Result<ProxyDnsResponseBytes, ProxyDnsRequestError>>,
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
    Cancelled,
    Deadline,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn start_proxy_dns_udp_actor(
    binding: ResidentProxyBinding,
    original_dst: SocketAddr,
    runtime_config: ResidentDnsUdpRuntimeConfig,
    metrics: Arc<ResidentDataplaneMetrics>,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
) -> ResidentDnsUdpActorRegistration<ResidentProxyDnsUdpActorHandle> {
    let (sender, receiver) = tokio::sync::mpsc::channel(runtime_config.queue_depth.max(1));
    let (lifecycle, stop_receiver) = ResidentDnsUdpActorLifecycle::new();
    let completion = ResidentDnsUdpActorCompletion::new();
    metrics.dns_udp_actor_opened();
    let task_metrics = Arc::clone(&metrics);
    let actor_config = runtime_config.clone();
    let task = tokio::spawn(async move {
        let mut metric_guard = ResidentProxyDnsUdpActorMetricGuard {
            metrics: task_metrics,
            fatal: false,
        };
        metric_guard.fatal = run_proxy_dns_udp_actor(
            binding,
            original_dst,
            receiver,
            stop_receiver,
            actor_config,
            Arc::clone(&metric_guard.metrics),
            hysteria2_owner_registry,
            tuic_owner_registry,
            juicity_owner_registry,
            anytls_owner_registry,
        )
        .await;
        metric_guard.fatal
    });
    let task_id = task.id();
    ResidentDnsUdpActorRegistration {
        handle: ResidentProxyDnsUdpActorHandle {
            sender,
            lifecycle: Arc::clone(&lifecycle),
            metrics,
            payload_admission: runtime_config.payload_admission.clone(),
            task_id,
            completion: Arc::clone(&completion),
        },
        lifecycle: Arc::downgrade(&lifecycle),
        completion,
        task,
    }
}

impl ResidentProxyDnsUdpActorHandle {
    pub(super) fn task_id(&self) -> tokio::task::Id {
        self.task_id
    }

    pub(super) fn completion(&self) -> Arc<ResidentDnsUdpActorCompletion> {
        Arc::clone(&self.completion)
    }

    pub(super) fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    pub(super) fn close(&self) {
        self.lifecycle.stop();
    }

    pub(super) async fn exchange_once(
        &self,
        payload: &[u8],
        context: ProxyDnsRequestContext,
    ) -> Result<Vec<u8>, ProxyDnsRequestError> {
        context.ensure(ProxyDnsRequestStage::Enqueue)?;
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        let payload_admission = self
            .payload_admission
            .try_acquire(payload.len())
            .map_err(|error| {
                ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::Enqueue,
                    ProxyDnsRequestFailure::Capacity,
                    format!(
                    "proxied DNS UDP queued payload byte limit reached: requested={}, current={}, limit={}",
                    error.requested, error.current, error.limit
                    ),
                )
            })?;
        let mut bytes = ProxyDnsQueuedRequestBytes::new(
            payload_admission,
            Arc::clone(&self.metrics),
            payload.len(),
            context,
        );
        let queue_permit = match time::timeout_at(context.deadline(), self.sender.reserve()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(error)) => {
                bytes.mark_rejected();
                return Err(ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::Enqueue,
                    ProxyDnsRequestFailure::Network,
                    format!("proxied DNS UDP actor is closed: {error}"),
                ));
            }
            Err(_) => {
                self.metrics.dns_udp_queue_wait_timeout();
                bytes.mark_expired();
                return Err(ProxyDnsRequestError::deadline(
                    ProxyDnsRequestStage::Enqueue,
                ));
            }
        };
        queue_permit.send(ResidentProxyDnsUdpRequest {
            payload: payload.to_vec(),
            context,
            bytes,
            response: response_tx,
        });
        match time::timeout_at(context.deadline(), response_rx).await {
            Ok(Ok(result)) => result.map(ProxyDnsResponseBytes::into_payload),
            Ok(Err(_)) => Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Read,
                ProxyDnsRequestFailure::Network,
                "proxied DNS UDP actor dropped response",
            )),
            Err(_) => Err(ProxyDnsRequestError::deadline(ProxyDnsRequestStage::Read)),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_proxy_dns_udp_actor(
    binding: ResidentProxyBinding,
    original_dst: SocketAddr,
    mut receiver: tokio::sync::mpsc::Receiver<ResidentProxyDnsUdpRequest>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
    runtime_config: ResidentDnsUdpRuntimeConfig,
    metrics: Arc<ResidentDataplaneMetrics>,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
) -> bool {
    let pending_limit = runtime_config.pending_limit.max(1);
    let mut pending = HashMap::<u16, PendingProxyDnsUdpRequest>::new();
    let mut deadlines = VecDeque::<PendingProxyDnsDeadline>::new();
    let mut id_allocator = UdpRequestIdAllocator::new(runtime_config.attempt_timeout);
    // Protocol executors contain mutually exclusive transport state. Keep the selected
    // executor off the actor worker stack so adding one protocol variant cannot silently
    // raise the stack requirement of every DNS UDP worker.
    let mut executor = None::<Box<UdpSessionExecutor>>;
    let mut next_generation = 1_u64;
    loop {
        expire_proxy_dns_udp_requests(&mut pending, &mut deadlines, &mut id_allocator);
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
            _ = wait_proxy_dns_udp_cancellation(&mut pending), if !pending.is_empty() => {
                ResidentProxyDnsUdpActorEvent::Cancelled
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
                    &mut deadlines,
                    &mut id_allocator,
                    ProxyDnsRequestError::new(
                        ProxyDnsRequestStage::Cleanup,
                        ProxyDnsRequestFailure::Network,
                        "proxied DNS UDP actor is shutting down",
                    ),
                )
                .saturating_add(fail_queued_proxy_dns_udp_requests(
                    &mut receiver,
                    "proxied DNS UDP actor is shutting down",
                ));
                metrics.dns_udp_shutdown_failed_requests(failed);
                break;
            }
            ResidentProxyDnsUdpActorEvent::Request(Some(request)) => {
                let request_deadline = request.context.deadline();
                if let Err(err) = handle_proxy_dns_udp_request(
                    &binding,
                    original_dst,
                    request,
                    &mut pending,
                    &mut deadlines,
                    &mut id_allocator,
                    &mut next_generation,
                    &mut executor,
                    &runtime_config,
                    &metrics,
                    hysteria2_owner_registry.as_ref(),
                    tuic_owner_registry.as_ref(),
                    juicity_owner_registry.as_ref(),
                    anytls_owner_registry.as_ref(),
                )
                .await
                {
                    let shared_error = ProxyDnsRequestError::new(
                        ProxyDnsRequestStage::Cleanup,
                        ProxyDnsRequestFailure::Network,
                        format!("proxied DNS UDP executor reset after request failure: {err}"),
                    );
                    fail_proxy_dns_udp_requests(
                        &mut pending,
                        &mut deadlines,
                        &mut id_allocator,
                        shared_error,
                    );
                    reset_proxy_dns_udp_executor(&mut executor, request_deadline, &metrics).await;
                }
            }
            ResidentProxyDnsUdpActorEvent::Request(None) => {
                if pending.is_empty() {
                    break;
                }
            }
            ResidentProxyDnsUdpActorEvent::Response(Ok(Some((_, response)))) => {
                if let Err(error) = handle_proxy_dns_udp_response(
                    &mut pending,
                    &mut deadlines,
                    &mut id_allocator,
                    original_dst,
                    response,
                    &metrics,
                    &runtime_config.payload_admission,
                ) {
                    let reset_deadline = pending
                        .values()
                        .map(|request| request.context.deadline())
                        .min()
                        .unwrap_or_else(time::Instant::now);
                    fail_proxy_dns_udp_requests(
                        &mut pending,
                        &mut deadlines,
                        &mut id_allocator,
                        error,
                    );
                    reset_proxy_dns_udp_executor(&mut executor, reset_deadline, &metrics).await;
                }
            }
            ResidentProxyDnsUdpActorEvent::Response(Ok(None)) => {
                tokio::task::yield_now().await;
            }
            ResidentProxyDnsUdpActorEvent::Response(Err(err)) => {
                let reset_deadline = pending
                    .values()
                    .map(|request| request.context.deadline())
                    .min()
                    .unwrap_or_else(time::Instant::now);
                fail_proxy_dns_udp_requests(
                    &mut pending,
                    &mut deadlines,
                    &mut id_allocator,
                    ProxyDnsRequestError::new(
                        ProxyDnsRequestStage::Read,
                        ProxyDnsRequestFailure::Network,
                        format!("receive proxied DNS UDP response: {err}"),
                    ),
                );
                reset_proxy_dns_udp_executor(&mut executor, reset_deadline, &metrics).await;
            }
            ResidentProxyDnsUdpActorEvent::Cancelled => {
                expire_proxy_dns_udp_requests(&mut pending, &mut deadlines, &mut id_allocator);
            }
            ResidentProxyDnsUdpActorEvent::Deadline => {
                expire_proxy_dns_udp_requests(&mut pending, &mut deadlines, &mut id_allocator);
            }
        }
    }
    if let Some(mut executor) = executor {
        let _ = time::timeout(runtime_config.attempt_timeout, executor.shutdown()).await;
    }
    false
}
