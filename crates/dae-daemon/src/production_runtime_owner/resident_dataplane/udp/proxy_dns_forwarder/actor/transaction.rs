use dae_dns::{DnsPacketView, restore_packed_response_request_id};

use super::*;

pub(super) struct PendingProxyDnsUdpRequest {
    pub(super) upstream_id: u16,
    pub(super) original_id: u16,
    pub(super) generation: u64,
    pub(super) deadline: time::Instant,
    questions: Vec<PendingProxyDnsQuestion>,
    pub(super) response: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingProxyDnsQuestion {
    qname_wire: Vec<u8>,
    qtype: u16,
    qclass: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PendingProxyDnsDeadline {
    pub(super) id: u16,
    pub(super) generation: u64,
    pub(super) deadline: time::Instant,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_proxy_dns_udp_request(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddr,
    mut request: ResidentProxyDnsUdpRequest,
    pending: &mut HashMap<u16, PendingProxyDnsUdpRequest>,
    deadlines: &mut VecDeque<PendingProxyDnsDeadline>,
    id_allocator: &mut UdpRequestIdAllocator,
    next_generation: &mut u64,
    executor: &mut Option<UdpSessionExecutor>,
    runtime_config: &ResidentDnsUdpRuntimeConfig,
    metrics: &ResidentDataplaneMetrics,
) -> Result<(), String> {
    if pending.len() >= runtime_config.pending_limit {
        metrics.dns_udp_pending_rejected();
        let _ = request
            .response
            .send(Err("proxied DNS UDP pending queue is full".to_owned()));
        return Ok(());
    }
    let request_view = match DnsPacketView::parse(&request.payload) {
        Ok(request_view) => request_view,
        Err(err) => {
            let _ = request
                .response
                .send(Err(format!("parse proxied DNS UDP request: {err}")));
            return Ok(());
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
    let upstream_id = match id_allocator.allocate(runtime_config.pending_limit) {
        Ok(upstream_id) => upstream_id,
        Err(err) => {
            metrics.dns_udp_id_exhausted();
            let _ = request.response.send(Err(err));
            return Ok(());
        }
    };
    request.payload[0..2].copy_from_slice(&upstream_id.to_be_bytes());
    let deadline = time::Instant::now() + runtime_config.attempt_timeout;
    let generation = *next_generation;
    *next_generation = (*next_generation).wrapping_add(1).max(1);
    pending.insert(
        upstream_id,
        PendingProxyDnsUdpRequest {
            upstream_id,
            original_id,
            generation,
            deadline,
            questions,
            response: request.response,
        },
    );
    metrics.dns_udp_pending_added();
    deadlines.push_back(PendingProxyDnsDeadline {
        id: upstream_id,
        generation,
        deadline,
    });
    if executor.is_none() {
        *executor = Some(UdpSessionExecutor::new_proxy_packet(proxy));
        metrics.proxy_dns_udp_executor_opened();
    } else {
        metrics.proxy_dns_udp_executor_reused();
    }
    let Some(executor) = executor.as_mut() else {
        return Err("proxied DNS UDP executor was not initialized".to_owned());
    };
    let (_, response) = executor
        .execute_proxy_packet(proxy, original_dst, &request.payload)
        .await?;
    if response.reply_forwarded {
        handle_proxy_dns_udp_response(pending, id_allocator, &response.payload, metrics);
    }
    Ok(())
}

pub(super) fn handle_proxy_dns_udp_response(
    pending: &mut HashMap<u16, PendingProxyDnsUdpRequest>,
    id_allocator: &mut UdpRequestIdAllocator,
    response: &[u8],
    metrics: &ResidentDataplaneMetrics,
) {
    let Some(id_bytes) = response.get(0..2) else {
        return;
    };
    let response_id = u16::from_be_bytes([id_bytes[0], id_bytes[1]]);
    let Some(request) = pending.get(&response_id) else {
        return;
    };
    let Ok(response_view) = DnsPacketView::parse(response) else {
        return;
    };
    if !proxy_dns_udp_response_matches(request, &response_view) {
        return;
    }
    let Some(request) = pending.remove(&response_id) else {
        return;
    };
    id_allocator.release(response_id);
    metrics.dns_udp_pending_removed(1);
    let restored = restore_packed_response_request_id(response, request.original_id)
        .ok_or_else(|| "proxied DNS UDP response is too short to restore request id".to_owned());
    let _ = request.response.send(restored);
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
