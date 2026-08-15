use dae_dns::DnsPacketView;

use super::*;
use crate::udp::proxy_dns_forwarder::actor::transaction::ProxyDnsRequestRelease;
use crate::udp::{UdpFixedTargetPayload, UdpFixedTargetValidation, UdpResponseDropReason};

pub(in crate::udp::proxy_dns_forwarder::actor) fn handle_proxy_dns_udp_response(
    pending: &mut HashMap<u16, PendingProxyDnsUdpRequest>,
    deadlines: &mut VecDeque<PendingProxyDnsDeadline>,
    id_allocator: &mut DnsRequestIdAllocator,
    expected_source: SocketAddr,
    mut response: UdpExchangeResult,
    metrics: &Arc<ResidentDataplaneMetrics>,
    payload_admission: &ResidentUdpPayloadAdmission,
) -> Result<(), ProxyDnsRequestError> {
    let expectation = response.fixed_target_expectation(expected_source);
    let mut payload = match response.take_fixed_target_payload(expectation) {
        UdpFixedTargetPayload::Accepted {
            payload,
            validation,
        } => match validation {
            UdpFixedTargetValidation::Validated => {
                metrics.udp_response_validated();
                payload
            }
            UdpFixedTargetValidation::CompatibilityUnverified => {
                metrics.udp_response_compatibility_unverified();
                payload
            }
            UdpFixedTargetValidation::Dropped(reason) => {
                metrics.udp_response_dropped(payload.len());
                return Err(fixed_target_validation_error(reason));
            }
        },
        UdpFixedTargetPayload::Rejected {
            payload_len,
            reason,
        } => {
            metrics.udp_response_dropped(payload_len);
            return Err(fixed_target_validation_error(reason));
        }
    };

    let Some(id_bytes) = payload.get(0..2) else {
        return Ok(());
    };
    let response_id = u16::from_be_bytes([id_bytes[0], id_bytes[1]]);
    let Some(request) = pending.get(&response_id) else {
        return Ok(());
    };
    let response_view = match DnsPacketView::parse(&payload) {
        Ok(response_view) => response_view,
        Err(error) => {
            let Some(request) = pending.remove(&response_id) else {
                return Ok(());
            };
            remove_proxy_dns_udp_deadline(deadlines, response_id, request.generation);
            id_allocator.release(response_id);
            let error = ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Read,
                ProxyDnsRequestFailure::Protocol,
                format!("parse proxied DNS UDP response: {error}"),
            );
            request.deliver(Err(error), ProxyDnsRequestRelease::Completed);
            return Ok(());
        }
    };
    if !proxy_dns_udp_response_matches(request, &response_view) {
        return Ok(());
    }
    let Some(request) = pending.remove(&response_id) else {
        return Ok(());
    };
    remove_proxy_dns_udp_deadline(deadlines, response_id, request.generation);
    id_allocator.release(response_id);
    let response_permit = match payload_admission.try_acquire(payload.len()) {
        Ok(permit) => permit,
        Err(error) => {
            let result = Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Read,
                ProxyDnsRequestFailure::Capacity,
                format!(
                    "proxied DNS UDP response byte limit reached: requested={}, current={}, limit={}",
                    error.requested, error.current, error.limit
                ),
            ));
            request.deliver(result, ProxyDnsRequestRelease::Completed);
            return Ok(());
        }
    };
    let Some(id_bytes) = payload.get_mut(0..2) else {
        let result = Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Protocol,
            "proxied DNS UDP response is too short to restore request id",
        ));
        request.deliver(result, ProxyDnsRequestRelease::Completed);
        return Ok(());
    };
    id_bytes.copy_from_slice(&request.original_id.to_be_bytes());
    let restored = ProxyDnsResponseBytes::new(payload, response_permit, Arc::clone(metrics));
    request.deliver(Ok(restored), ProxyDnsRequestRelease::Completed);
    Ok(())
}

fn fixed_target_validation_error(reason: UdpResponseDropReason) -> ProxyDnsRequestError {
    ProxyDnsRequestError::new(
        ProxyDnsRequestStage::Read,
        ProxyDnsRequestFailure::Protocol,
        format!(
            "proxied DNS UDP response failed fixed-target validation: {}",
            reason.label()
        ),
    )
}

fn proxy_dns_udp_response_matches(
    request: &PendingProxyDnsUdpRequest,
    response: &DnsPacketView<'_>,
) -> bool {
    if !response.response() || response.id() != request.upstream_id {
        return false;
    }
    if request.questions.is_empty() {
        return true;
    }
    if response.question_count() != request.questions.len() {
        return false;
    }
    request
        .questions
        .iter()
        .zip(response.questions())
        .all(|(want, got)| {
            want.qtype == got.qtype()
                && want.qclass == got.qclass()
                && want.qname_wire.eq_ignore_ascii_case(got.qname_wire())
        })
}
