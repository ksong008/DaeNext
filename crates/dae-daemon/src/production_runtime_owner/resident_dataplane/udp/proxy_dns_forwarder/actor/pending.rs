use super::*;

pub(super) fn expire_proxy_dns_udp_requests(
    pending: &mut HashMap<u16, PendingProxyDnsUdpRequest>,
    deadlines: &mut VecDeque<PendingProxyDnsDeadline>,
    id_allocator: &mut UdpRequestIdAllocator,
    metrics: &ResidentDataplaneMetrics,
) {
    let now = time::Instant::now();
    while let Some(deadline) = deadlines.front().copied() {
        let Some(request) = pending.get(&deadline.id) else {
            deadlines.pop_front();
            continue;
        };
        if request.generation != deadline.generation || request.deadline != deadline.deadline {
            deadlines.pop_front();
            continue;
        }
        if request.deadline > now && !request.response.is_closed() {
            break;
        }
        deadlines.pop_front();
        if let Some(request) = pending.remove(&deadline.id) {
            id_allocator.release(deadline.id);
            metrics.dns_udp_pending_removed(1);
            let _ = request
                .response
                .send(Err("proxied DNS UDP pending request timed out".to_owned()));
        }
    }
}

pub(super) fn fail_proxy_dns_udp_requests(
    pending: &mut HashMap<u16, PendingProxyDnsUdpRequest>,
    id_allocator: &mut UdpRequestIdAllocator,
    error: String,
    metrics: &ResidentDataplaneMetrics,
) -> usize {
    let pending = std::mem::take(pending);
    let failed = pending.len();
    metrics.dns_udp_pending_removed(failed);
    for (id, request) in pending {
        id_allocator.release(id);
        let _ = request.response.send(Err(error.clone()));
    }
    failed
}

pub(super) fn fail_queued_proxy_dns_udp_requests(
    receiver: &mut tokio::sync::mpsc::Receiver<ResidentProxyDnsUdpRequest>,
    error: &str,
) -> usize {
    let mut failed = 0_usize;
    while let Ok(request) = receiver.try_recv() {
        failed = failed.saturating_add(1);
        let _ = request.response.send(Err(error.to_owned()));
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
        if request.generation != deadline.generation || request.deadline != deadline.deadline {
            deadlines.pop_front();
            continue;
        }
        return Some(deadline.deadline);
    }
}

pub(super) async fn wait_proxy_dns_udp_deadline(deadline: Option<time::Instant>) {
    match deadline {
        Some(deadline) => time::sleep_until(deadline).await,
        None => std::future::pending::<()>().await,
    }
}
