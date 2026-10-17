use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

use super::*;
use crate::{
    ProxyDnsQueuedRequestBytes, ProxyDnsRequestContext, ProxyDnsRequestError,
    ProxyDnsRequestFailure, ProxyDnsRequestStage, ProxyDnsResponseBytes,
    ResidentDnsUdpActorCompletion, ResidentDnsUdpActorLifecycle, ResidentDnsUdpActorRegistration,
    ResidentUdpPayloadAdmission,
};

mod executor_state;
mod pending;
mod send;
mod transaction;
use self::send::{
    ActiveProxyDnsSend, ProxyDnsSendCompletion, ProxyDnsSendOperation,
    mark_send_response_delivered, wait_proxy_dns_send,
};

use self::executor_state::{reset_proxy_dns_udp_executor, wait_proxy_dns_udp_response};
use self::pending::{
    cancel_abandoned_proxy_dns_udp_requests, expire_proxy_dns_udp_requests,
    fail_proxy_dns_udp_requests, fail_queued_proxy_dns_udp_requests, insert_proxy_dns_udp_deadline,
    next_proxy_dns_udp_deadline, wait_proxy_dns_udp_deadline,
};
use self::transaction::{
    PendingProxyDnsDeadline, PendingProxyDnsUdpRequest, ProxyDnsRequestRelease,
    handle_proxy_dns_udp_response, prepare_proxy_dns_udp_request,
};

#[derive(Clone)]
pub(super) struct ResidentProxyDnsUdpActorHandle {
    sender: tokio::sync::mpsc::Sender<ResidentProxyDnsUdpRequest>,
    cancellation_notify: Arc<tokio::sync::Notify>,
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

struct ResidentProxyDnsUdpCancellationGuard {
    notify: Arc<tokio::sync::Notify>,
    armed: bool,
}

impl Drop for ResidentProxyDnsUdpCancellationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.notify.notify_one();
        }
    }
}

impl Drop for ResidentProxyDnsUdpActorMetricGuard {
    fn drop(&mut self) {
        self.metrics.dns_udp_actor_closed(self.fatal);
    }
}

enum ResidentProxyDnsUdpActorEvent {
    Stop,
    Request(Option<ResidentProxyDnsUdpRequest>),
    Response(Result<Option<(ResidentEventKind, UdpExchangeResult)>, String>),
    Cancelled,
    Sent(ProxyDnsSendCompletion),
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
    start_proxy_dns_udp_actor_with_send(
        binding,
        original_dst,
        runtime_config,
        metrics,
        hysteria2_owner_registry,
        tuic_owner_registry,
        juicity_owner_registry,
        anytls_owner_registry,
        UdpSessionExecutor::begin_dns_send,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn start_proxy_dns_udp_actor_with_send(
    binding: ResidentProxyBinding,
    original_dst: SocketAddr,
    runtime_config: ResidentDnsUdpRuntimeConfig,
    metrics: Arc<ResidentDataplaneMetrics>,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    prepare_send: impl FnMut(
        &mut UdpSessionExecutor,
        &ResidentProxyBinding,
        SocketAddr,
        &[u8],
    ) -> Result<Option<dae_resident_udp::ProxyDnsUdpSend>, String>
    + Send
    + 'static,
) -> ResidentDnsUdpActorRegistration<ResidentProxyDnsUdpActorHandle> {
    let (sender, receiver) = tokio::sync::mpsc::channel(runtime_config.queue_depth.max(1));
    let cancellation_notify = Arc::new(tokio::sync::Notify::new());
    let (lifecycle, stop_receiver) = ResidentDnsUdpActorLifecycle::new();
    let completion = ResidentDnsUdpActorCompletion::new();
    metrics.dns_udp_actor_opened();
    let task_metrics = Arc::clone(&metrics);
    let actor_config = runtime_config.clone();
    let task_cancellation_notify = Arc::clone(&cancellation_notify);
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
            task_cancellation_notify,
            actor_config,
            Arc::clone(&metric_guard.metrics),
            hysteria2_owner_registry,
            tuic_owner_registry,
            juicity_owner_registry,
            anytls_owner_registry,
            prepare_send,
        )
        .await;
        metric_guard.fatal
    });
    let task_id = task.id();
    ResidentDnsUdpActorRegistration {
        handle: ResidentProxyDnsUdpActorHandle {
            sender,
            cancellation_notify,
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
        let mut cancellation = ResidentProxyDnsUdpCancellationGuard {
            notify: Arc::clone(&self.cancellation_notify),
            armed: true,
        };
        let result = time::timeout_at(context.deadline(), response_rx).await;
        if result.is_ok() {
            cancellation.armed = false;
        }
        match result {
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
    cancellation_notify: Arc<tokio::sync::Notify>,
    runtime_config: ResidentDnsUdpRuntimeConfig,
    metrics: Arc<ResidentDataplaneMetrics>,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    mut prepare_send: impl FnMut(
        &mut UdpSessionExecutor,
        &ResidentProxyBinding,
        SocketAddr,
        &[u8],
    ) -> Result<Option<dae_resident_udp::ProxyDnsUdpSend>, String>,
) -> bool {
    let pending_limit = runtime_config.pending_limit.max(1);
    let mut pending = HashMap::<u16, PendingProxyDnsUdpRequest>::new();
    let mut deadlines = BinaryHeap::<Reverse<PendingProxyDnsDeadline>>::new();
    let mut id_allocator = DnsRequestIdAllocator::new(runtime_config.attempt_timeout);
    // Protocol executors contain mutually exclusive transport state. Keep the selected
    // executor off the actor worker stack so adding one protocol variant cannot silently
    // raise the stack requirement of every DNS UDP worker.
    let mut executor = None::<Box<UdpSessionExecutor>>;
    let mut next_generation = 1_u64;
    let mut active = None::<ActiveProxyDnsSend>;
    let mut requests_done = false;
    loop {
        // A sending request retains its payload permit until the operation is
        // dropped/completed, independently of pending response metadata.
        let abort_send = active.as_ref().is_some_and(|send| {
            send.deadline <= time::Instant::now()
                || (!send.response_delivered
                    && pending
                        .get(&send.id)
                        .is_none_or(|request| request.generation != send.generation))
        });
        if abort_send {
            let send = active.take().expect("active send");
            let reset = send.reset_on_cancel();
            let deadline = send.deadline;
            if let Some(request) = pending.remove(&send.id) {
                id_allocator.release(send.id);
                request.deliver(
                    Err(ProxyDnsRequestError::deadline(send.stage)),
                    ProxyDnsRequestRelease::Expired,
                );
            }
            send.cancel(&mut executor).await;
            if reset {
                fail_proxy_dns_udp_requests(
                    &mut pending,
                    &mut deadlines,
                    &mut id_allocator,
                    ProxyDnsRequestError::new(
                        ProxyDnsRequestStage::Cleanup,
                        ProxyDnsRequestFailure::Network,
                        "proxied DNS UDP stream reset after an interrupted send; framing or codec state may have advanced",
                    ),
                );
                reset_proxy_dns_udp_executor(&mut executor, deadline, &metrics).await;
            }
        }
        expire_proxy_dns_udp_requests(&mut pending, &mut deadlines, &mut id_allocator);
        if requests_done && pending.is_empty() && active.is_none() {
            break;
        }
        let pending_deadline = next_proxy_dns_udp_deadline(&mut deadlines, &pending);
        let deadline = match (pending_deadline, active.as_ref().map(|send| send.deadline)) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (left, right) => left.or(right),
        };
        let event = tokio::select! {
            biased;
            _ = &mut stop => ResidentProxyDnsUdpActorEvent::Stop,
            _ = cancellation_notify.notified(), if !pending.is_empty() => ResidentProxyDnsUdpActorEvent::Cancelled,
            _ = wait_proxy_dns_udp_deadline(deadline) => ResidentProxyDnsUdpActorEvent::Deadline,
            // Every received packet leaves this select before re-entering it,
            // so a blocked writer never owns the receiver or its decoder.
            response = wait_proxy_dns_udp_response(&mut executor, !pending.is_empty()) => ResidentProxyDnsUdpActorEvent::Response(response),
            completed = wait_proxy_dns_send(&mut active) => ResidentProxyDnsUdpActorEvent::Sent(completed),
            request = receiver.recv(), if !requests_done && active.is_none() && pending.len() < pending_limit => ResidentProxyDnsUdpActorEvent::Request(request),
        };
        match event {
            ResidentProxyDnsUdpActorEvent::Stop => {
                receiver.close();
                if let Some(send) = active.take() {
                    send.cancel(&mut executor).await;
                }
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
                let Some(prepared) = prepare_proxy_dns_udp_request(
                    &binding,
                    original_dst,
                    request,
                    &pending,
                    &mut id_allocator,
                    &mut next_generation,
                    &runtime_config,
                    &metrics,
                ) else {
                    continue;
                };
                let mut transaction = prepared.transaction;
                let id = transaction.upstream_id;
                let generation = transaction.generation;
                let deadline = transaction.context.deadline();
                let opening = executor.is_none();
                if opening {
                    executor = Some(Box::new(
                        UdpSessionExecutor::new_proxy_packet_with_optional_transport_owner(
                            binding.clone(),
                            hysteria2_owner_registry.clone(),
                            tuic_owner_registry.clone(),
                            juicity_owner_registry.clone(),
                            anytls_owner_registry.clone(),
                        ),
                    ));
                    metrics.proxy_dns_udp_executor_opened();
                } else {
                    metrics.proxy_dns_udp_executor_reused();
                }
                let selected = executor.as_mut().expect("initialized proxy DNS executor");
                selected.set_owner_acquisition_deadline(dae_runtime_control::AbsoluteDeadline::at(
                    deadline.into_std(),
                ));
                let operation =
                    match prepare_send(selected, &binding, original_dst, &prepared.payload) {
                        Ok(Some(send)) => ProxyDnsSendOperation::Packet(send),
                        Ok(None) => {
                            // No established transport: this operation owns the
                            // executor during connect/handshake and is stop-aware.
                            let opening_executor =
                                Arc::new(tokio::sync::Mutex::new(executor.take()));
                            let selected = Arc::clone(&opening_executor);
                            let binding = binding.clone();
                            let payload = prepared.payload;
                            ProxyDnsSendOperation::Opening {
                                executor: opening_executor,
                                future: Box::pin(async move {
                                    let mut selected = selected.lock().await;
                                    selected
                                        .as_mut()
                                        .expect("opening executor")
                                        .execute_proxy_packet(&binding, original_dst, &payload)
                                        .await
                                }),
                            }
                        }
                        Err(error) => {
                            id_allocator.release(id);
                            transaction.deliver(
                                Err(ProxyDnsRequestError::new(
                                    ProxyDnsRequestStage::Send,
                                    ProxyDnsRequestFailure::Protocol,
                                    error,
                                )),
                                ProxyDnsRequestRelease::Completed,
                            );
                            // Stream preparation can advance an encryption nonce;
                            // retain the conservative reset boundary for that case.
                            if selected.dns_send_preparation_requires_reset() {
                                fail_proxy_dns_udp_requests(
                                    &mut pending,
                                    &mut deadlines,
                                    &mut id_allocator,
                                    ProxyDnsRequestError::new(
                                        ProxyDnsRequestStage::Cleanup,
                                        ProxyDnsRequestFailure::Network,
                                        "proxied DNS UDP stream preparation failed",
                                    ),
                                );
                                reset_proxy_dns_udp_executor(&mut executor, deadline, &metrics)
                                    .await;
                            }
                            continue;
                        }
                    };
                active = Some(ActiveProxyDnsSend {
                    id,
                    generation,
                    deadline,
                    stage: if opening {
                        ProxyDnsRequestStage::Connect
                    } else {
                        ProxyDnsRequestStage::Send
                    },
                    response_delivered: false,
                    permit: transaction.bytes.take_payload_permit(),
                    operation,
                });
                pending.insert(id, transaction);
                insert_proxy_dns_udp_deadline(
                    &mut deadlines,
                    PendingProxyDnsDeadline {
                        deadline,
                        generation,
                        id,
                    },
                );
            }
            ResidentProxyDnsUdpActorEvent::Request(None) => requests_done = true,
            ResidentProxyDnsUdpActorEvent::Sent(completed) => {
                let mut send = active.take().expect("completed active send");
                let (result, reset, response) = match completed {
                    ProxyDnsSendCompletion::Packet(mut completed) => {
                        executor
                            .as_mut()
                            .expect("packet executor")
                            .finish_dns_send(&mut completed);
                        (completed.result, completed.reset_session, None)
                    }
                    ProxyDnsSendCompletion::Opened((selected, result)) => {
                        executor = Some(selected);
                        match result {
                            Ok((_, response)) => (Ok(()), false, Some(response)),
                            Err(error) => (Err(error), true, None),
                        }
                    }
                };
                if let Some(request) = pending.get_mut(&send.id) {
                    request.bytes.restore_payload_permit(send.permit.take());
                }
                let send_failed = result.is_err();
                if let Err(error) = result
                    && let Some(request) = pending.remove(&send.id)
                {
                    id_allocator.release(send.id);
                    request.deliver(
                        Err(ProxyDnsRequestError::new(
                            send.stage,
                            ProxyDnsRequestFailure::Network,
                            error,
                        )),
                        ProxyDnsRequestRelease::Completed,
                    );
                }
                let response_error =
                    if let Some(response) = response.filter(|response| response.reply_forwarded) {
                        handle_proxy_dns_udp_response(
                            &mut pending,
                            &mut id_allocator,
                            original_dst,
                            response,
                            &metrics,
                            &runtime_config.payload_admission,
                        )
                        .err()
                    } else {
                        None
                    };
                // Keep older UDP replies on their original socket. Once no
                // request depends on it, a failed sender may reopen normally
                // and retry address candidates on the next request.
                if reset || response_error.is_some() || (send_failed && pending.is_empty()) {
                    fail_proxy_dns_udp_requests(
                        &mut pending,
                        &mut deadlines,
                        &mut id_allocator,
                        response_error.unwrap_or_else(|| {
                            ProxyDnsRequestError::new(
                                ProxyDnsRequestStage::Cleanup,
                                ProxyDnsRequestFailure::Network,
                                "proxied DNS UDP shared session failed during send",
                            )
                        }),
                    );
                    drop(send);
                    reset_proxy_dns_udp_executor(
                        &mut executor,
                        time::Instant::now() + runtime_config.attempt_timeout,
                        &metrics,
                    )
                    .await;
                }
            }
            ResidentProxyDnsUdpActorEvent::Response(Ok(Some((_, response)))) => {
                if let Err(error) = handle_proxy_dns_udp_response(
                    &mut pending,
                    &mut id_allocator,
                    original_dst,
                    response,
                    &metrics,
                    &runtime_config.payload_admission,
                ) {
                    if let Some(send) = active.take() {
                        send.cancel(&mut executor).await;
                    }
                    fail_proxy_dns_udp_requests(
                        &mut pending,
                        &mut deadlines,
                        &mut id_allocator,
                        error,
                    );
                    reset_proxy_dns_udp_executor(
                        &mut executor,
                        time::Instant::now() + runtime_config.attempt_timeout,
                        &metrics,
                    )
                    .await;
                } else {
                    mark_send_response_delivered(&mut active, &pending);
                }
            }
            ResidentProxyDnsUdpActorEvent::Response(Ok(None)) => tokio::task::yield_now().await,
            ResidentProxyDnsUdpActorEvent::Response(Err(error)) => {
                if let Some(send) = active.take() {
                    send.cancel(&mut executor).await;
                }
                fail_proxy_dns_udp_requests(
                    &mut pending,
                    &mut deadlines,
                    &mut id_allocator,
                    ProxyDnsRequestError::new(
                        ProxyDnsRequestStage::Read,
                        ProxyDnsRequestFailure::Network,
                        format!("receive proxied DNS UDP response: {error}"),
                    ),
                );
                reset_proxy_dns_udp_executor(
                    &mut executor,
                    time::Instant::now() + runtime_config.attempt_timeout,
                    &metrics,
                )
                .await;
            }
            ResidentProxyDnsUdpActorEvent::Cancelled => cancel_abandoned_proxy_dns_udp_requests(
                &mut pending,
                &mut deadlines,
                &mut id_allocator,
            ),
            ResidentProxyDnsUdpActorEvent::Deadline => {}
        }
    }
    if let Some(mut executor) = executor {
        let _ = time::timeout(runtime_config.attempt_timeout, executor.shutdown()).await;
    }
    false
}
