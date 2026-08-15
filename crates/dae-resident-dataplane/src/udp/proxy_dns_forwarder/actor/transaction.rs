use dae_dns::DnsPacketView;

use super::*;
use crate::dns::{
    ProxyDnsPendingRequestBytes, ProxyDnsRequestContext, ProxyDnsRequestError,
    ProxyDnsRequestFailure, ProxyDnsRequestOutcome, ProxyDnsRequestStage, ProxyDnsResponseBytes,
};

mod response;

pub(super) use self::response::handle_proxy_dns_udp_response;

pub(super) struct PendingProxyDnsUdpRequest {
    pub(super) upstream_id: u16,
    pub(super) original_id: u16,
    pub(super) generation: u64,
    pub(super) context: ProxyDnsRequestContext,
    questions: Vec<PendingProxyDnsQuestion>,
    pub(super) bytes: ProxyDnsPendingRequestBytes,
    pub(super) response:
        tokio::sync::oneshot::Sender<Result<ProxyDnsResponseBytes, ProxyDnsRequestError>>,
}

#[derive(Clone, Copy)]
pub(super) enum ProxyDnsRequestRelease {
    Completed,
    Expired,
    Abandoned,
}

impl PendingProxyDnsUdpRequest {
    pub(super) fn deliver(
        mut self,
        result: Result<ProxyDnsResponseBytes, ProxyDnsRequestError>,
        release: ProxyDnsRequestRelease,
    ) {
        match release {
            ProxyDnsRequestRelease::Completed => {
                if self.response.is_closed() {
                    self.bytes.mark_abandoned();
                }
            }
            ProxyDnsRequestRelease::Expired => self.bytes.mark_expired(),
            ProxyDnsRequestRelease::Abandoned => self.bytes.mark_abandoned(),
        }
        let response = self.response;
        drop(self.bytes);
        let _ = response.send(result);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingProxyDnsQuestion {
    qname_wire: Vec<u8>,
    qtype: u16,
    qclass: u16,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct PendingProxyDnsDeadline {
    pub(super) deadline: time::Instant,
    pub(super) generation: u64,
    pub(super) id: u16,
}

#[derive(Clone, Copy)]
enum QueuedProxyDnsRequestRelease {
    Expired,
    Rejected,
}

fn deliver_queued_proxy_dns_error(
    mut request: ResidentProxyDnsUdpRequest,
    error: ProxyDnsRequestError,
    release: QueuedProxyDnsRequestRelease,
) -> ProxyDnsRequestOutcome {
    match release {
        QueuedProxyDnsRequestRelease::Expired => request.bytes.mark_expired(),
        QueuedProxyDnsRequestRelease::Rejected => request.bytes.mark_rejected(),
    }
    let response = request.response;
    drop(request.bytes);
    let _ = response.send(Err(error));
    ProxyDnsRequestOutcome::ResponseForwarded
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_proxy_dns_udp_request(
    binding: &ResidentProxyBinding,
    original_dst: SocketAddr,
    mut request: ResidentProxyDnsUdpRequest,
    pending: &mut HashMap<u16, PendingProxyDnsUdpRequest>,
    deadlines: &mut BinaryHeap<Reverse<PendingProxyDnsDeadline>>,
    id_allocator: &mut DnsRequestIdAllocator,
    next_generation: &mut u64,
    executor: &mut Option<Box<UdpSessionExecutor>>,
    runtime_config: &ResidentDnsUdpRuntimeConfig,
    metrics: &Arc<ResidentDataplaneMetrics>,
    hysteria2_owner_registry: Option<&Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<&TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<&JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<&AnyTlsOwnerRegistryHandle>,
) -> Result<ProxyDnsRequestOutcome, ProxyDnsRequestError> {
    if let Err(error) = request.context.ensure(ProxyDnsRequestStage::Queued) {
        return Ok(deliver_queued_proxy_dns_error(
            request,
            error,
            QueuedProxyDnsRequestRelease::Expired,
        ));
    }
    if request.response.is_closed() {
        return Ok(ProxyDnsRequestOutcome::ResponseForwarded);
    }

    let pending_limit = runtime_config.pending_limit.max(1);
    if pending.len() >= pending_limit {
        metrics.dns_udp_pending_rejected();
        return Ok(deliver_queued_proxy_dns_error(
            request,
            ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Pending,
                ProxyDnsRequestFailure::Capacity,
                "proxied DNS UDP pending queue is full",
            ),
            QueuedProxyDnsRequestRelease::Rejected,
        ));
    }

    if let Err(error) = request.context.ensure(ProxyDnsRequestStage::Parse) {
        return Ok(deliver_queued_proxy_dns_error(
            request,
            error,
            QueuedProxyDnsRequestRelease::Expired,
        ));
    }
    let request_view = match DnsPacketView::parse(&request.payload) {
        Ok(request_view) => request_view,
        Err(error) => {
            return Ok(deliver_queued_proxy_dns_error(
                request,
                ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::Parse,
                    ProxyDnsRequestFailure::Protocol,
                    format!("parse proxied DNS UDP request: {error}"),
                ),
                QueuedProxyDnsRequestRelease::Rejected,
            ));
        }
    };
    let original_id = request_view.id();
    let questions = request_view
        .questions()
        .map(|question| PendingProxyDnsQuestion {
            qname_wire: question.qname_wire().to_vec(),
            qtype: question.qtype(),
            qclass: question.qclass(),
        })
        .collect::<Vec<_>>();
    let pending_metadata_bytes = std::mem::size_of::<PendingProxyDnsUdpRequest>()
        .saturating_add(std::mem::size_of::<PendingProxyDnsDeadline>())
        .saturating_add(
            questions
                .capacity()
                .saturating_mul(std::mem::size_of::<PendingProxyDnsQuestion>()),
        )
        .saturating_add(questions.iter().fold(0_usize, |bytes, question| {
            bytes.saturating_add(question.qname_wire.capacity())
        }));
    let pending_metadata_permit = match runtime_config
        .payload_admission
        .try_acquire(pending_metadata_bytes)
    {
        Ok(permit) => permit,
        Err(error) => {
            metrics.dns_udp_pending_rejected();
            return Ok(deliver_queued_proxy_dns_error(
                request,
                ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::Pending,
                    ProxyDnsRequestFailure::Capacity,
                    format!(
                        "proxied DNS UDP pending metadata byte limit reached: requested={}, current={}, limit={}",
                        error.requested, error.current, error.limit
                    ),
                ),
                QueuedProxyDnsRequestRelease::Rejected,
            ));
        }
    };

    if let Err(error) = request.context.ensure(ProxyDnsRequestStage::Identifier) {
        drop(pending_metadata_permit);
        return Ok(deliver_queued_proxy_dns_error(
            request,
            error,
            QueuedProxyDnsRequestRelease::Expired,
        ));
    }
    if request.response.is_closed() {
        return Ok(ProxyDnsRequestOutcome::ResponseForwarded);
    }
    let upstream_id = match id_allocator.allocate(pending_limit) {
        Ok(upstream_id) => upstream_id,
        Err(error) => {
            metrics.dns_udp_id_exhausted();
            drop(pending_metadata_permit);
            return Ok(deliver_queued_proxy_dns_error(
                request,
                ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::Identifier,
                    ProxyDnsRequestFailure::Capacity,
                    error,
                ),
                QueuedProxyDnsRequestRelease::Rejected,
            ));
        }
    };
    request.payload[0..2].copy_from_slice(&upstream_id.to_be_bytes());

    let generation = *next_generation;
    *next_generation = (*next_generation).wrapping_add(1).max(1);
    let deadline = request.context.deadline();
    let mut transaction = PendingProxyDnsUdpRequest {
        upstream_id,
        original_id,
        generation,
        context: request.context,
        questions,
        bytes: request
            .bytes
            .into_pending(pending_metadata_permit, pending_metadata_bytes),
        response: request.response,
    };

    if let Err(error) = transaction
        .context
        .ensure(ProxyDnsRequestStage::OwnerAcquire)
    {
        id_allocator.release(upstream_id);
        transaction.deliver(Err(error), ProxyDnsRequestRelease::Expired);
        return Ok(ProxyDnsRequestOutcome::ResponseForwarded);
    }
    if transaction.response.is_closed() {
        transaction.bytes.mark_abandoned();
        id_allocator.release(upstream_id);
        return Ok(ProxyDnsRequestOutcome::ResponseForwarded);
    }

    let opening_executor = executor.is_none();
    if opening_executor {
        *executor = Some(Box::new(
            UdpSessionExecutor::new_proxy_packet_with_optional_transport_owner(
                binding.clone(),
                hysteria2_owner_registry.cloned(),
                tuic_owner_registry.cloned(),
                juicity_owner_registry.cloned(),
                anytls_owner_registry.cloned(),
            ),
        ));
        metrics.proxy_dns_udp_executor_opened();
    } else {
        metrics.proxy_dns_udp_executor_reused();
    }
    let Some(executor) = executor.as_mut() else {
        id_allocator.release(upstream_id);
        let error = ProxyDnsRequestError::new(
            ProxyDnsRequestStage::OwnerAcquire,
            ProxyDnsRequestFailure::Network,
            "proxied DNS UDP executor was not initialized",
        );
        transaction.deliver(Err(error.clone()), ProxyDnsRequestRelease::Completed);
        return Err(error);
    };
    executor.set_owner_acquisition_deadline(dae_runtime_control::AbsoluteDeadline::at(
        transaction.context.deadline().into_std(),
    ));

    let execution_stage = if opening_executor {
        ProxyDnsRequestStage::Connect
    } else {
        ProxyDnsRequestStage::Send
    };
    let execution = executor.execute_proxy_packet(binding, original_dst, &request.payload);
    tokio::pin!(execution);
    let exchange = tokio::select! {
        biased;
        _ = transaction.response.closed() => {
            id_allocator.release(upstream_id);
            if transaction.context.ensure(execution_stage).is_err() {
                transaction.bytes.mark_expired();
                return Err(ProxyDnsRequestError::deadline(execution_stage));
            }
            transaction.bytes.mark_abandoned();
            return Err(ProxyDnsRequestError::cancelled(execution_stage));
        }
        _ = time::sleep_until(deadline) => {
            id_allocator.release(upstream_id);
            let error = ProxyDnsRequestError::deadline(execution_stage);
            transaction.deliver(Err(error.clone()), ProxyDnsRequestRelease::Expired);
            return Err(error);
        }
        result = &mut execution => result,
    };
    let (_, response) = match exchange {
        Ok(response) => response,
        Err(error) => {
            id_allocator.release(upstream_id);
            let error =
                ProxyDnsRequestError::new(execution_stage, ProxyDnsRequestFailure::Network, error);
            transaction.deliver(Err(error.clone()), ProxyDnsRequestRelease::Completed);
            return Err(error);
        }
    };

    if let Err(error) = transaction.context.ensure(ProxyDnsRequestStage::Pending) {
        id_allocator.release(upstream_id);
        transaction.deliver(Err(error), ProxyDnsRequestRelease::Expired);
        return Ok(ProxyDnsRequestOutcome::ResponseForwarded);
    }
    if transaction.response.is_closed() {
        transaction.bytes.mark_abandoned();
        id_allocator.release(upstream_id);
        return Ok(ProxyDnsRequestOutcome::ResponseForwarded);
    }

    pending.insert(upstream_id, transaction);
    insert_proxy_dns_udp_deadline(
        deadlines,
        PendingProxyDnsDeadline {
            id: upstream_id,
            generation,
            deadline,
        },
    );
    if response.reply_forwarded {
        handle_proxy_dns_udp_response(
            pending,
            id_allocator,
            original_dst,
            response,
            metrics,
            &runtime_config.payload_admission,
        )?;
    }
    if pending.contains_key(&upstream_id) {
        Ok(ProxyDnsRequestOutcome::Pending)
    } else {
        Ok(ProxyDnsRequestOutcome::ResponseForwarded)
    }
}
