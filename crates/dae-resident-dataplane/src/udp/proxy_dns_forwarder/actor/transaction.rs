use dae_dns::DnsPacketView;

use super::*;
use crate::{
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

pub(super) struct PreparedProxyDnsUdpRequest {
    pub(super) transaction: PendingProxyDnsUdpRequest,
    pub(super) payload: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_proxy_dns_udp_request(
    binding: &ResidentProxyBinding,
    original_dst: SocketAddr,
    mut request: ResidentProxyDnsUdpRequest,
    pending: &HashMap<u16, PendingProxyDnsUdpRequest>,
    id_allocator: &mut DnsRequestIdAllocator,
    next_generation: &mut u64,
    runtime_config: &ResidentDnsUdpRuntimeConfig,
    metrics: &Arc<ResidentDataplaneMetrics>,
) -> Option<PreparedProxyDnsUdpRequest> {
    if let Err(error) = request.context.ensure(ProxyDnsRequestStage::Queued) {
        deliver_queued_proxy_dns_error(request, error, QueuedProxyDnsRequestRelease::Expired);
        return None;
    }
    if request.response.is_closed() {
        return None;
    }

    if let Err(error) = UdpSessionExecutor::validate_datagram_payload_size(
        binding,
        original_dst,
        request.payload.len(),
    ) {
        deliver_queued_proxy_dns_error(
            request,
            ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Send,
                ProxyDnsRequestFailure::Capacity,
                error,
            ),
            QueuedProxyDnsRequestRelease::Rejected,
        );
        return None;
    }

    let pending_limit = runtime_config.pending_limit.max(1);
    if pending.len() >= pending_limit {
        metrics.dns_udp_pending_rejected();
        deliver_queued_proxy_dns_error(
            request,
            ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Pending,
                ProxyDnsRequestFailure::Capacity,
                "proxied DNS UDP pending queue is full",
            ),
            QueuedProxyDnsRequestRelease::Rejected,
        );
        return None;
    }

    if let Err(error) = request.context.ensure(ProxyDnsRequestStage::Parse) {
        deliver_queued_proxy_dns_error(request, error, QueuedProxyDnsRequestRelease::Expired);
        return None;
    }
    let request_view = match DnsPacketView::parse(&request.payload) {
        Ok(request_view) => request_view,
        Err(error) => {
            deliver_queued_proxy_dns_error(
                request,
                ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::Parse,
                    ProxyDnsRequestFailure::Protocol,
                    format!("parse proxied DNS UDP request: {error}"),
                ),
                QueuedProxyDnsRequestRelease::Rejected,
            );
            return None;
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
            deliver_queued_proxy_dns_error(
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
            );
            return None;
        }
    };

    if let Err(error) = request.context.ensure(ProxyDnsRequestStage::Identifier) {
        drop(pending_metadata_permit);
        deliver_queued_proxy_dns_error(request, error, QueuedProxyDnsRequestRelease::Expired);
        return None;
    }
    if request.response.is_closed() {
        return None;
    }
    let upstream_id = match id_allocator.allocate(pending_limit) {
        Ok(upstream_id) => upstream_id,
        Err(error) => {
            metrics.dns_udp_id_exhausted();
            drop(pending_metadata_permit);
            deliver_queued_proxy_dns_error(
                request,
                ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::Identifier,
                    ProxyDnsRequestFailure::Capacity,
                    error,
                ),
                QueuedProxyDnsRequestRelease::Rejected,
            );
            return None;
        }
    };
    request.payload[0..2].copy_from_slice(&upstream_id.to_be_bytes());

    let generation = *next_generation;
    *next_generation = (*next_generation).wrapping_add(1).max(1);
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
        return None;
    }
    if transaction.response.is_closed() {
        transaction.bytes.mark_abandoned();
        id_allocator.release(upstream_id);
        return None;
    }

    Some(PreparedProxyDnsUdpRequest {
        transaction,
        payload: request.payload,
    })
}
