use super::*;

pub(super) async fn run_udp_multiplex_actor(
    target: SocketAddr,
    socket: tokio::net::UdpSocket,
    mut receiver: tokio::sync::mpsc::Receiver<UdpMultiplexRequest>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
    cancellation_notify: Arc<tokio::sync::Notify>,
    config: UdpMultiplexActorConfig,
) -> bool {
    let mut pending = HashMap::<u16, PendingUdpRequest>::new();
    let mut id_allocator = DnsRequestIdAllocator::new(config.attempt_timeout);
    let mut deadlines = VecDeque::<PendingUdpDeadline>::new();
    let mut next_generation = 1_u64;
    let mut buf = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
    let mut fatal = false;
    let mut idle_deadline = config
        .idle_timeout
        .map(|timeout| time::Instant::now() + timeout);
    loop {
        expire_pending_udp_requests(
            &mut pending,
            &mut deadlines,
            &mut id_allocator,
            &config.metrics,
        );
        if receiver.is_closed() && pending.is_empty() {
            break;
        }
        let cleanup_deadline = next_udp_multiplex_deadline(&mut deadlines, &pending);
        tokio::select! {
            biased;

            _ = &mut stop => {
                receiver.close();
                let pending_failed = fail_pending_udp_requests(
                    &mut pending,
                    &mut id_allocator,
                    "DNS UDP multiplex actor is shutting down".to_owned(),
                    &config.metrics,
                );
                let queued_failed = fail_queued_udp_requests(
                    &mut receiver,
                    "DNS UDP multiplex actor is shutting down",
                );
                config
                    .metrics
                    .dns_udp_shutdown_failed_requests(pending_failed.saturating_add(queued_failed));
                break;
            }

            received = socket.recv(&mut buf) => {
                config.metrics.dns_udp_recv_syscall();
                idle_deadline = config
                    .idle_timeout
                    .map(|timeout| time::Instant::now() + timeout);
                match received {
                    Ok(read) => {
                        config.metrics.dns_udp_datagram_received();
                        handle_udp_multiplex_response(
                            &mut pending,
                            &mut id_allocator,
                            &buf[..read],
                            &config.metrics,
                        )
                    }
                    Err(err) => {
                        receiver.close();
                        fail_pending_udp_requests(
                            &mut pending,
                            &mut id_allocator,
                            format!("receive DNS UDP multiplex response from {target}: {err}"),
                            &config.metrics,
                        );
                        fail_queued_udp_requests(
                            &mut receiver,
                            "DNS UDP multiplex actor stopped after socket failure",
                        );
                        fatal = true;
                        break;
                    }
                }
            }

            maybe_request = receiver.recv(), if pending.len() < config.inflight_window => {
                let Some(request) = maybe_request else {
                    if pending.is_empty() {
                        break;
                    }
                    continue;
                };
                handle_udp_multiplex_requests(
                    target,
                    &socket,
                    &mut receiver,
                    &mut pending,
                    &mut id_allocator,
                    &mut deadlines,
                    &mut next_generation,
                    request,
                    &config,
                ).await;
                idle_deadline = config
                    .idle_timeout
                    .map(|timeout| time::Instant::now() + timeout);
            }

            _ = cancellation_notify.notified() => {
                cancel_abandoned_udp_requests(
                    &mut pending,
                    &mut id_allocator,
                    &config.metrics,
                );
                idle_deadline = config
                    .idle_timeout
                    .map(|timeout| time::Instant::now() + timeout);
            }

            _ = wait_for_udp_multiplex_deadline(cleanup_deadline) => {
                expire_pending_udp_requests(
                    &mut pending,
                    &mut deadlines,
                    &mut id_allocator,
                    &config.metrics,
                );
            }

            _ = wait_for_udp_multiplex_deadline(idle_deadline),
                if idle_deadline.is_some() && pending.is_empty() && receiver.is_empty() =>
            {
                break;
            }
        }
    }
    fatal
}

fn fail_queued_udp_requests(
    receiver: &mut tokio::sync::mpsc::Receiver<UdpMultiplexRequest>,
    error: &str,
) -> usize {
    let mut failed = 0_usize;
    while let Ok(request) = receiver.try_recv() {
        failed = failed.saturating_add(1);
        let _ = request.response.send(Err(error.to_owned()));
    }
    failed
}

#[allow(clippy::too_many_arguments)]
async fn handle_udp_multiplex_requests(
    target: SocketAddr,
    socket: &tokio::net::UdpSocket,
    receiver: &mut tokio::sync::mpsc::Receiver<UdpMultiplexRequest>,
    pending: &mut HashMap<u16, PendingUdpRequest>,
    id_allocator: &mut DnsRequestIdAllocator,
    deadlines: &mut VecDeque<PendingUdpDeadline>,
    next_generation: &mut u64,
    request: UdpMultiplexRequest,
    config: &UdpMultiplexActorConfig,
) {
    let ready_limit = config
        .send_batch_limit
        .min(config.inflight_window.saturating_sub(pending.len()).max(1));
    let mut requests = Vec::with_capacity(ready_limit);
    requests.push(request);
    if !cfg!(feature = "test-scalar-udp-send") {
        while requests.len() < ready_limit {
            match receiver.try_recv() {
                Ok(request) => requests.push(request),
                Err(
                    tokio::sync::mpsc::error::TryRecvError::Empty
                    | tokio::sync::mpsc::error::TryRecvError::Disconnected,
                ) => break,
            }
        }
    }
    let mut prepared = Vec::with_capacity(requests.len());
    for request in requests {
        if let Some(request) = prepare_udp_multiplex_request(
            pending,
            id_allocator,
            deadlines,
            next_generation,
            request,
            config,
        ) {
            prepared.push(request);
        }
    }
    if prepared.len() <= 1 || cfg!(feature = "test-scalar-udp-send") {
        for request in prepared {
            send_prepared_udp_request(target, socket, pending, id_allocator, request, config).await;
        }
        return;
    }

    let writable = socket.writable().await;
    let sent = match writable {
        Ok(()) => {
            let datagrams = prepared
                .iter()
                .map(|request| UdpSendMessage {
                    payload: &request.payload,
                    peer: None,
                })
                .collect::<Vec<_>>();
            config.metrics.dns_udp_send_syscall(datagrams.len());
            try_sendmmsg(socket.as_raw_fd(), &datagrams).unwrap_or(0)
        }
        Err(_) => 0,
    };
    config.metrics.dns_udp_datagrams_sent(sent);
    for request in prepared.into_iter().skip(sent) {
        send_prepared_udp_request(target, socket, pending, id_allocator, request, config).await;
    }
}

struct PreparedUdpMultiplexRequest {
    upstream_id: u16,
    payload: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
fn prepare_udp_multiplex_request(
    pending: &mut HashMap<u16, PendingUdpRequest>,
    id_allocator: &mut DnsRequestIdAllocator,
    deadlines: &mut VecDeque<PendingUdpDeadline>,
    next_generation: &mut u64,
    mut request: UdpMultiplexRequest,
    config: &UdpMultiplexActorConfig,
) -> Option<PreparedUdpMultiplexRequest> {
    if pending.len() >= config.pending_capacity {
        config.metrics.dns_udp_pending_rejected();
        let _ = request
            .response
            .send(Err("DNS UDP multiplex pending queue is full".to_owned()));
        return None;
    }
    if request.deadline <= time::Instant::now() {
        let _ = request.response.send(Err(
            "DNS UDP multiplex request deadline expired before admission".to_owned(),
        ));
        return None;
    }
    let request_view = match DnsPacketView::parse(&request.payload) {
        Ok(view) => view,
        Err(err) => {
            let _ = request
                .response
                .send(Err(format!("parse DNS UDP multiplex request: {err}")));
            return None;
        }
    };
    let original_id = request_view.id();
    let questions = pending_dns_questions(&request_view);
    let upstream_id = match id_allocator.allocate(config.pending_capacity) {
        Ok(id) => id,
        Err(err) => {
            config.metrics.dns_udp_id_exhausted();
            let _ = request.response.send(Err(err));
            return None;
        }
    };
    rewrite_dns_packet_id_in_place(&mut request.payload, upstream_id);
    let deadline = request
        .deadline
        .min(time::Instant::now() + config.attempt_timeout);
    let generation = *next_generation;
    *next_generation = (*next_generation).wrapping_add(1).max(1);
    pending.insert(
        upstream_id,
        PendingUdpRequest {
            upstream_id,
            original_id,
            generation,
            deadline,
            questions,
            response: request.response,
        },
    );
    config.metrics.dns_udp_pending_added();
    deadlines.push_back(PendingUdpDeadline {
        id: upstream_id,
        generation,
        deadline,
    });
    Some(PreparedUdpMultiplexRequest {
        upstream_id,
        payload: request.payload,
    })
}

async fn send_prepared_udp_request(
    target: SocketAddr,
    socket: &tokio::net::UdpSocket,
    pending: &mut HashMap<u16, PendingUdpRequest>,
    id_allocator: &mut DnsRequestIdAllocator,
    request: PreparedUdpMultiplexRequest,
    config: &UdpMultiplexActorConfig,
) {
    config.metrics.dns_udp_send_syscall(1);
    match socket.send(&request.payload).await {
        Ok(_) => config.metrics.dns_udp_datagrams_sent(1),
        Err(err) => {
            if let Some(pending) = pending.remove(&request.upstream_id) {
                id_allocator.release(request.upstream_id);
                config.metrics.dns_udp_pending_removed(1);
                let _ = pending.response.send(Err(format!(
                    "send DNS UDP multiplex packet to {target}: {err}"
                )));
            }
        }
    }
}

pub(super) fn handle_udp_multiplex_response(
    pending: &mut HashMap<u16, PendingUdpRequest>,
    id_allocator: &mut DnsRequestIdAllocator,
    response: &[u8],
    metrics: &ResidentDataplaneMetrics,
) {
    let Ok(response_id) = dns_packet_id(response) else {
        return;
    };
    let Some(pending_request) = pending.get(&response_id) else {
        return;
    };
    let Ok(restored_response) =
        validate_and_restore_udp_multiplex_response(pending_request, response)
    else {
        return;
    };
    let Some(pending_request) = pending.remove(&response_id) else {
        return;
    };
    id_allocator.release(response_id);
    metrics.dns_udp_pending_removed(1);
    let _ = pending_request.response.send(Ok(restored_response));
}

pub(super) fn validate_and_restore_udp_multiplex_response(
    pending: &PendingUdpRequest,
    response: &[u8],
) -> Result<Vec<u8>, String> {
    let response_view = DnsPacketView::parse(response)
        .map_err(|err| format!("parse DNS UDP multiplex response: {err}"))?;
    validate_dns_udp_multiplex_response_for_request(pending, &response_view)?;
    restore_packed_response_request_id(response, pending.original_id)
        .ok_or_else(|| "DNS UDP multiplex response is too short to restore request id".to_owned())
}

fn validate_dns_udp_multiplex_response_for_request(
    pending: &PendingUdpRequest,
    response: &DnsPacketView<'_>,
) -> Result<(), String> {
    if !response.response() {
        return Err("validate DNS UDP multiplex response: DNS request received".to_owned());
    }
    if response.id() != pending.upstream_id {
        return Err(format!(
            "validate DNS UDP multiplex response: id mismatch got {} want {}",
            response.id(),
            pending.upstream_id
        ));
    }
    if pending.questions.is_empty() {
        return Ok(());
    }
    if response.question_count() == 0 {
        return Err("validate DNS UDP multiplex response: missing question".to_owned());
    }
    if response.question_count() != pending.questions.len() {
        return Err(format!(
            "validate DNS UDP multiplex response: question count mismatch got {} want {}",
            response.question_count(),
            pending.questions.len()
        ));
    }
    for (index, (want, got)) in pending
        .questions
        .iter()
        .zip(response.questions())
        .enumerate()
    {
        if want.matches(got.qname_wire(), got.qtype(), got.qclass()) {
            continue;
        }
        return Err(format!(
            "validate DNS UDP multiplex response: question mismatch at index {index}"
        ));
    }
    Ok(())
}

pub(super) fn expire_pending_udp_requests(
    pending: &mut HashMap<u16, PendingUdpRequest>,
    deadlines: &mut VecDeque<PendingUdpDeadline>,
    id_allocator: &mut DnsRequestIdAllocator,
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
                .send(Err("DNS UDP multiplex pending request timed out".to_owned()));
        }
    }
}

fn cancel_abandoned_udp_requests(
    pending: &mut HashMap<u16, PendingUdpRequest>,
    id_allocator: &mut DnsRequestIdAllocator,
    metrics: &ResidentDataplaneMetrics,
) {
    let cancelled = pending
        .iter()
        .filter_map(|(id, request)| request.response.is_closed().then_some(*id))
        .collect::<Vec<_>>();
    for id in &cancelled {
        pending.remove(id);
        id_allocator.release(*id);
    }
    metrics.dns_udp_pending_removed(cancelled.len());
}

fn fail_pending_udp_requests(
    pending: &mut HashMap<u16, PendingUdpRequest>,
    id_allocator: &mut DnsRequestIdAllocator,
    error: String,
    metrics: &ResidentDataplaneMetrics,
) -> usize {
    let pending_requests = std::mem::take(pending);
    let failed = pending_requests.len();
    metrics.dns_udp_pending_removed(failed);
    for (id, request) in pending_requests {
        id_allocator.release(id);
        let _ = request.response.send(Err(error.clone()));
    }
    failed
}

pub(super) fn next_udp_multiplex_deadline(
    deadlines: &mut VecDeque<PendingUdpDeadline>,
    pending: &HashMap<u16, PendingUdpRequest>,
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

async fn wait_for_udp_multiplex_deadline(deadline: Option<time::Instant>) {
    match deadline {
        Some(deadline) => time::sleep_until(deadline).await,
        None => std::future::pending::<()>().await,
    }
}
