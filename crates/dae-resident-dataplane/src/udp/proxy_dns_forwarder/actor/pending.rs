use futures_util::{StreamExt, stream::FuturesUnordered};

use super::*;
use crate::dns::{ProxyDnsRequestError, ProxyDnsRequestFailure, ProxyDnsRequestStage};
use crate::udp::proxy_dns_forwarder::actor::transaction::ProxyDnsRequestRelease;

#[cfg(test)]
mod tests;

pub(super) fn insert_proxy_dns_udp_deadline(
    deadlines: &mut VecDeque<PendingProxyDnsDeadline>,
    deadline: PendingProxyDnsDeadline,
) {
    let index = deadlines
        .iter()
        .position(|queued| deadline.deadline < queued.deadline)
        .unwrap_or(deadlines.len());
    deadlines.insert(index, deadline);
}

pub(super) fn remove_proxy_dns_udp_deadline(
    deadlines: &mut VecDeque<PendingProxyDnsDeadline>,
    id: u16,
    generation: u64,
) -> bool {
    let Some(index) = deadlines
        .iter()
        .position(|deadline| deadline.id == id && deadline.generation == generation)
    else {
        return false;
    };
    deadlines.remove(index);
    true
}

pub(super) fn expire_proxy_dns_udp_requests(
    pending: &mut HashMap<u16, PendingProxyDnsUdpRequest>,
    deadlines: &mut VecDeque<PendingProxyDnsDeadline>,
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
        remove_proxy_dns_udp_deadline(deadlines, id, request.generation);
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

    let now = time::Instant::now();
    while let Some(deadline) = deadlines.front().copied() {
        let Some(request) = pending.get(&deadline.id) else {
            deadlines.pop_front();
            continue;
        };
        if request.generation != deadline.generation
            || request.context.deadline() != deadline.deadline
        {
            deadlines.pop_front();
            continue;
        }
        if deadline.deadline > now {
            break;
        }
        deadlines.pop_front();
        if let Some(request) = pending.remove(&deadline.id) {
            id_allocator.release(deadline.id);
            request.deliver(
                Err(ProxyDnsRequestError::deadline(ProxyDnsRequestStage::Read)),
                ProxyDnsRequestRelease::Expired,
            );
        }
    }
}

pub(super) fn fail_proxy_dns_udp_requests(
    pending: &mut HashMap<u16, PendingProxyDnsUdpRequest>,
    deadlines: &mut VecDeque<PendingProxyDnsDeadline>,
    id_allocator: &mut DnsRequestIdAllocator,
    error: ProxyDnsRequestError,
) -> usize {
    let pending = std::mem::take(pending);
    let failed = pending.len();
    for (id, request) in pending {
        remove_proxy_dns_udp_deadline(deadlines, id, request.generation);
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
    deadlines: &mut VecDeque<PendingProxyDnsDeadline>,
    pending: &HashMap<u16, PendingProxyDnsUdpRequest>,
) -> Option<time::Instant> {
    loop {
        let deadline = *deadlines.front()?;
        let Some(request) = pending.get(&deadline.id) else {
            deadlines.pop_front();
            continue;
        };
        if request.generation != deadline.generation
            || request.context.deadline() != deadline.deadline
        {
            deadlines.pop_front();
            continue;
        }
        return Some(deadline.deadline);
    }
}

pub(super) async fn wait_proxy_dns_udp_cancellation(
    pending: &mut HashMap<u16, PendingProxyDnsUdpRequest>,
) {
    let cancellations = pending
        .values_mut()
        .map(|request| request.response.closed())
        .collect::<FuturesUnordered<_>>();
    if cancellations.is_empty() {
        std::future::pending::<()>().await;
    } else {
        let _ = cancellations.into_future().await;
    }
}

pub(super) async fn wait_proxy_dns_udp_deadline(deadline: Option<time::Instant>) {
    match deadline {
        Some(deadline) => time::sleep_until(deadline).await,
        None => std::future::pending::<()>().await,
    }
}
