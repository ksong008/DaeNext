use super::*;
use crate::dns::{ProxyDnsRequestError, ProxyDnsRequestFailure, ProxyDnsRequestStage};
use crate::udp::proxy_dns_forwarder::actor::transaction::ProxyDnsRequestRelease;

#[cfg(test)]
mod tests;

pub(super) fn insert_proxy_dns_udp_deadline(
    deadlines: &mut BinaryHeap<Reverse<PendingProxyDnsDeadline>>,
    deadline: PendingProxyDnsDeadline,
) {
    deadlines.push(Reverse(deadline));
}

pub(super) fn expire_proxy_dns_udp_requests(
    pending: &mut HashMap<u16, PendingProxyDnsUdpRequest>,
    deadlines: &mut BinaryHeap<Reverse<PendingProxyDnsDeadline>>,
    id_allocator: &mut DnsRequestIdAllocator,
) {
    let now = time::Instant::now();
    while let Some(Reverse(deadline)) = deadlines.peek().copied() {
        let Some(request) = pending.get(&deadline.id) else {
            deadlines.pop();
            continue;
        };
        if request.generation != deadline.generation
            || request.context.deadline() != deadline.deadline
        {
            deadlines.pop();
            continue;
        }
        if deadline.deadline > now {
            break;
        }
        deadlines.pop();
        if let Some(request) = pending.remove(&deadline.id) {
            id_allocator.release(deadline.id);
            request.deliver(
                Err(ProxyDnsRequestError::deadline(ProxyDnsRequestStage::Read)),
                ProxyDnsRequestRelease::Expired,
            );
        }
    }
    compact_proxy_dns_udp_deadlines(deadlines, pending);
}

pub(super) fn cancel_abandoned_proxy_dns_udp_requests(
    pending: &mut HashMap<u16, PendingProxyDnsUdpRequest>,
    deadlines: &mut BinaryHeap<Reverse<PendingProxyDnsDeadline>>,
    id_allocator: &mut DnsRequestIdAllocator,
) {
    let abandoned = pending
        .iter()
        .filter_map(|(id, request)| request.response.is_closed().then_some(*id))
        .collect::<Vec<_>>();
    for id in abandoned {
        let Some(mut request) = pending.remove(&id) else {
            continue;
        };
        id_allocator.release(id);
        if request
            .context
            .ensure(ProxyDnsRequestStage::Cleanup)
            .is_err()
        {
            request.bytes.mark_expired();
        } else {
            request.bytes.mark_abandoned();
        }
    }
    compact_proxy_dns_udp_deadlines(deadlines, pending);
}

pub(super) fn fail_proxy_dns_udp_requests(
    pending: &mut HashMap<u16, PendingProxyDnsUdpRequest>,
    deadlines: &mut BinaryHeap<Reverse<PendingProxyDnsDeadline>>,
    id_allocator: &mut DnsRequestIdAllocator,
    error: ProxyDnsRequestError,
) -> usize {
    let pending = std::mem::take(pending);
    let failed = pending.len();
    for (id, request) in pending {
        id_allocator.release(id);
        let release = if request.response.is_closed() {
            if request
                .context
                .ensure(ProxyDnsRequestStage::Cleanup)
                .is_err()
            {
                ProxyDnsRequestRelease::Expired
            } else {
                ProxyDnsRequestRelease::Abandoned
            }
        } else {
            ProxyDnsRequestRelease::Completed
        };
        request.deliver(Err(error.clone()), release);
    }
    deadlines.clear();
    failed
}

pub(super) fn fail_queued_proxy_dns_udp_requests(
    receiver: &mut tokio::sync::mpsc::Receiver<ResidentProxyDnsUdpRequest>,
    error: &str,
) -> usize {
    let mut failed = 0_usize;
    while let Ok(mut request) = receiver.try_recv() {
        failed = failed.saturating_add(1);
        request.bytes.mark_rejected();
        let response = request.response;
        drop(request.bytes);
        let _ = response.send(Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Cleanup,
            ProxyDnsRequestFailure::Network,
            error,
        )));
    }
    failed
}

pub(super) fn next_proxy_dns_udp_deadline(
    deadlines: &mut BinaryHeap<Reverse<PendingProxyDnsDeadline>>,
    pending: &HashMap<u16, PendingProxyDnsUdpRequest>,
) -> Option<time::Instant> {
    compact_proxy_dns_udp_deadlines(deadlines, pending);
    loop {
        let Reverse(deadline) = *deadlines.peek()?;
        let Some(request) = pending.get(&deadline.id) else {
            deadlines.pop();
            continue;
        };
        if request.generation != deadline.generation
            || request.context.deadline() != deadline.deadline
        {
            deadlines.pop();
            continue;
        }
        return Some(deadline.deadline);
    }
}

fn compact_proxy_dns_udp_deadlines(
    deadlines: &mut BinaryHeap<Reverse<PendingProxyDnsDeadline>>,
    pending: &HashMap<u16, PendingProxyDnsUdpRequest>,
) {
    let compact_threshold = pending.len().saturating_mul(2).saturating_add(64);
    if deadlines.len() <= compact_threshold {
        return;
    }
    *deadlines = pending
        .values()
        .map(|request| {
            Reverse(PendingProxyDnsDeadline {
                deadline: request.context.deadline(),
                generation: request.generation,
                id: request.upstream_id,
            })
        })
        .collect();
}

pub(super) async fn wait_proxy_dns_udp_deadline(deadline: Option<time::Instant>) {
    match deadline {
        Some(deadline) => time::sleep_until(deadline).await,
        None => std::future::pending::<()>().await,
    }
}
