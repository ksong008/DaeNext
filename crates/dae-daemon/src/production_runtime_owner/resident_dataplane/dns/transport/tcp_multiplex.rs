use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use super::super::*;

#[derive(Clone)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsTcpMultiplexHandle
{
    commands: tokio::sync::mpsc::Sender<ResidentDnsTcpMultiplexCommand>,
    lifecycle: Arc<ResidentDnsTcpMultiplexLifecycle>,
    next_token: Arc<AtomicU64>,
    active: Arc<AtomicUsize>,
    capacity: usize,
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsTcpMultiplexRegistration
{
    commands: tokio::sync::mpsc::Receiver<ResidentDnsTcpMultiplexCommand>,
    lifecycle: Arc<ResidentDnsTcpMultiplexLifecycle>,
    active: Arc<AtomicUsize>,
    capacity: usize,
}

struct ResidentDnsTcpMultiplexLifecycle {
    closing: AtomicBool,
    notify: tokio::sync::Notify,
    capacity_notify: tokio::sync::Notify,
}

enum ResidentDnsTcpMultiplexCommand {
    Request(ResidentDnsTcpMultiplexRequest),
    Cancel(u64),
}

struct ResidentDnsTcpMultiplexRequest {
    token: u64,
    payload: Vec<u8>,
    deadline: time::Instant,
    response: tokio::sync::oneshot::Sender<Result<Vec<u8>, ProxyDnsRequestError>>,
}

struct ResidentDnsTcpPendingRequest {
    token: u64,
    original_id: u16,
    generation: u64,
    request: Vec<u8>,
    deadline: time::Instant,
    response: tokio::sync::oneshot::Sender<Result<Vec<u8>, ProxyDnsRequestError>>,
}

struct ResidentDnsTcpWrite {
    payload: Vec<u8>,
}

struct ResidentDnsTcpCancellationGuard {
    token: u64,
    commands: tokio::sync::mpsc::Sender<ResidentDnsTcpMultiplexCommand>,
    armed: bool,
}

impl Drop for ResidentDnsTcpCancellationGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self
                .commands
                .try_send(ResidentDnsTcpMultiplexCommand::Cancel(self.token));
        }
    }
}

impl ResidentDnsTcpMultiplexHandle {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn new(
        capacity: usize,
    ) -> (Self, ResidentDnsTcpMultiplexRegistration) {
        let capacity = capacity.clamp(1, (u16::MAX as usize) + 1);
        let (commands, command_receiver) = tokio::sync::mpsc::channel(capacity);
        let lifecycle = Arc::new(ResidentDnsTcpMultiplexLifecycle {
            closing: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
            capacity_notify: tokio::sync::Notify::new(),
        });
        let active = Arc::new(AtomicUsize::new(0));
        (
            Self {
                commands,
                lifecycle: Arc::clone(&lifecycle),
                next_token: Arc::new(AtomicU64::new(1)),
                active: Arc::clone(&active),
                capacity,
            },
            ResidentDnsTcpMultiplexRegistration {
                commands: command_receiver,
                lifecycle,
                active,
                capacity,
            },
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) async fn exchange(
        &self,
        payload: &[u8],
        context: ProxyDnsRequestContext,
    ) -> Result<Vec<u8>, ProxyDnsRequestError> {
        context.ensure(ProxyDnsRequestStage::Enqueue)?;
        if self.is_closed() {
            return Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Enqueue,
                ProxyDnsRequestFailure::Network,
                "DNS TCP multiplex connection is closed",
            ));
        }
        if payload.len() > u16::MAX as usize {
            return Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Enqueue,
                ProxyDnsRequestFailure::Capacity,
                format!("DNS TCP request exceeds frame limit: {}", payload.len()),
            ));
        }
        self.reserve_slot()?;
        let token = self.next_token.fetch_add(1, Ordering::Relaxed);
        let (response, response_receiver) = tokio::sync::oneshot::channel();
        let mut cancellation = ResidentDnsTcpCancellationGuard {
            token,
            commands: self.commands.clone(),
            armed: false,
        };
        if let Err(error) = context
            .run(
                ProxyDnsRequestStage::Queued,
                ProxyDnsRequestFailure::Capacity,
                self.commands.send(ResidentDnsTcpMultiplexCommand::Request(
                    ResidentDnsTcpMultiplexRequest {
                        token,
                        payload: payload.to_vec(),
                        deadline: context.deadline(),
                        response,
                    },
                )),
            )
            .await
        {
            release_resident_dns_tcp_slot(&self.lifecycle, &self.active);
            return Err(error);
        }
        cancellation.armed = true;
        let result = context
            .run(
                ProxyDnsRequestStage::Read,
                ProxyDnsRequestFailure::Cancelled,
                response_receiver,
            )
            .await?
            .map_err(|error| error.with_context("DNS TCP multiplex exchange"));
        cancellation.armed = false;
        result
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn pending(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn has_capacity(
        &self,
    ) -> bool {
        !self.is_closed() && self.pending() < self.capacity
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn is_closed(&self) -> bool {
        self.lifecycle.closing.load(Ordering::Acquire) || self.commands.is_closed()
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn close(&self) {
        if !self.lifecycle.closing.swap(true, Ordering::AcqRel) {
            self.lifecycle.notify.notify_waiters();
            self.lifecycle.capacity_notify.notify_waiters();
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) async fn wait_for_capacity(
        &self,
        context: ProxyDnsRequestContext,
    ) -> Result<(), ProxyDnsRequestError> {
        loop {
            context.ensure(ProxyDnsRequestStage::Queued)?;
            if self.is_closed() {
                return Err(ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::Queued,
                    ProxyDnsRequestFailure::Network,
                    "DNS TCP multiplex connection closed while waiting for capacity",
                ));
            }
            if self.has_capacity() {
                return Ok(());
            }
            let notified = self.lifecycle.capacity_notify.notified();
            if self.has_capacity() {
                return Ok(());
            }
            context
                .run(
                    ProxyDnsRequestStage::Queued,
                    ProxyDnsRequestFailure::Capacity,
                    async {
                        notified.await;
                        Ok::<(), std::convert::Infallible>(())
                    },
                )
                .await?;
        }
    }

    fn reserve_slot(&self) -> Result<(), ProxyDnsRequestError> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.capacity).then_some(active + 1)
            })
            .map(|_| ())
            .map_err(|_| {
                ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::Enqueue,
                    ProxyDnsRequestFailure::Capacity,
                    "DNS TCP multiplex connection request limit is reached",
                )
            })
    }
}

impl ResidentDnsTcpMultiplexRegistration {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) async fn run(
        self,
        stream: TokioTcpStream,
    ) -> Result<(), String> {
        let (reader, writer) = stream.into_split();
        run_resident_dns_tcp_multiplex_actor(reader, writer, self).await
    }
}

async fn run_resident_dns_tcp_multiplex_actor(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    writer: tokio::net::tcp::OwnedWriteHalf,
    mut registration: ResidentDnsTcpMultiplexRegistration,
) -> Result<(), String> {
    let (writes, write_receiver) = tokio::sync::mpsc::channel(registration.capacity);
    let mut writer_task = tokio::spawn(run_resident_dns_tcp_writer(writer, write_receiver));
    let mut pending = HashMap::<u16, ResidentDnsTcpPendingRequest>::new();
    let mut tokens = HashMap::<u64, u16>::new();
    let mut deadlines = BinaryHeap::<Reverse<(time::Instant, u16, u64)>>::new();
    let mut allocator =
        super::udp_multiplex::DnsRequestIdAllocator::new(RESIDENT_UDP_RESPONSE_TIMEOUT);
    let mut generation = 0_u64;
    let mut writer_finished = false;
    let result = loop {
        if registration.lifecycle.closing.load(Ordering::Acquire) {
            break Ok(());
        }
        let next_deadline = deadlines.peek().map(|entry| entry.0.0);
        tokio::select! {
            _ = registration.lifecycle.notify.notified() => {}
            writer_result = &mut writer_task => {
                writer_finished = true;
                break match writer_result {
                    Ok(Ok(())) => Err("DNS TCP multiplex writer stopped".to_owned()),
                    Ok(Err(error)) => Err(error),
                    Err(error) => Err(format!("join DNS TCP multiplex writer: {error}")),
                };
            }
            command = registration.commands.recv(),
                if pending.len() < registration.capacity && writes.capacity() > 0 =>
            {
                let Some(command) = command else {
                    break Ok(());
                };
                match command {
                    ResidentDnsTcpMultiplexCommand::Request(request) => {
                        generation = generation.wrapping_add(1);
                        admit_resident_dns_tcp_request(
                            request,
                            generation,
                            registration.capacity,
                            &writes,
                            &mut pending,
                            &mut tokens,
                            &mut deadlines,
                            &mut allocator,
                            &registration.lifecycle,
                            &registration.active,
                        );
                    }
                    ResidentDnsTcpMultiplexCommand::Cancel(token) => {
                        cancel_resident_dns_tcp_request(
                            token,
                            &mut pending,
                            &mut tokens,
                            &mut allocator,
                            &registration.lifecycle,
                            &registration.active,
                        );
                    }
                }
            }
            response = read_dns_tcp_payload_async(&mut reader) => {
                match response {
                    Ok(Some(response)) => dispatch_resident_dns_tcp_response(
                        response,
                        &mut pending,
                        &mut tokens,
                        &mut allocator,
                        &registration.lifecycle,
                        &registration.active,
                    ),
                    Ok(None) => break Err("DNS TCP multiplex upstream closed the stream".to_owned()),
                    Err(error) => break Err(format!("read DNS TCP multiplex response: {error}")),
                }
            }
            _ = time::sleep_until(next_deadline.unwrap_or_else(time::Instant::now)),
                if next_deadline.is_some() =>
            {
                expire_resident_dns_tcp_requests(
                    time::Instant::now(),
                    &mut deadlines,
                    &mut pending,
                    &mut tokens,
                    &mut allocator,
                    &registration.lifecycle,
                    &registration.active,
                );
            }
        }
    };

    registration
        .lifecycle
        .closing
        .store(true, Ordering::Release);
    registration.lifecycle.notify.notify_waiters();
    drop(writes);
    if !writer_finished && !writer_task.is_finished() {
        writer_task.abort();
    }
    if !writer_finished {
        let _ = writer_task.await;
    }
    fail_all_resident_dns_tcp_requests(
        &mut pending,
        &mut tokens,
        &mut allocator,
        &registration.lifecycle,
        &registration.active,
        result
            .as_ref()
            .err()
            .map_or("DNS TCP multiplex connection stopped", String::as_str),
    );
    fail_queued_resident_dns_tcp_requests(
        &mut registration.commands,
        &registration.lifecycle,
        &registration.active,
    );
    result
}

#[allow(clippy::too_many_arguments)]
fn admit_resident_dns_tcp_request(
    request: ResidentDnsTcpMultiplexRequest,
    generation: u64,
    capacity: usize,
    writes: &tokio::sync::mpsc::Sender<ResidentDnsTcpWrite>,
    pending: &mut HashMap<u16, ResidentDnsTcpPendingRequest>,
    tokens: &mut HashMap<u64, u16>,
    deadlines: &mut BinaryHeap<Reverse<(time::Instant, u16, u64)>>,
    allocator: &mut super::udp_multiplex::DnsRequestIdAllocator,
    lifecycle: &ResidentDnsTcpMultiplexLifecycle,
    active_count: &AtomicUsize,
) {
    if request.deadline <= time::Instant::now() {
        let _ = request.response.send(Err(ProxyDnsRequestError::deadline(
            ProxyDnsRequestStage::Pending,
        )));
        release_resident_dns_tcp_slot(lifecycle, active_count);
        return;
    }
    let mut payload = request.payload;
    let original_id = match dns_packet_id(&payload) {
        Ok(id) => id,
        Err(error) => {
            let _ = request.response.send(Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Parse,
                ProxyDnsRequestFailure::Protocol,
                error,
            )));
            release_resident_dns_tcp_slot(lifecycle, active_count);
            return;
        }
    };
    let id = match allocator.allocate(capacity) {
        Ok(id) => id,
        Err(error) => {
            let _ = request.response.send(Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Identifier,
                ProxyDnsRequestFailure::Capacity,
                error,
            )));
            release_resident_dns_tcp_slot(lifecycle, active_count);
            return;
        }
    };
    payload[0..2].copy_from_slice(&id.to_be_bytes());
    if let Err(error) = DnsPacketView::parse(&payload) {
        allocator.release(id);
        let _ = request.response.send(Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Parse,
            ProxyDnsRequestFailure::Protocol,
            format!("parse DNS TCP multiplex request: {error}"),
        )));
        release_resident_dns_tcp_slot(lifecycle, active_count);
        return;
    }
    if let Err(error) = writes.try_send(ResidentDnsTcpWrite {
        payload: payload.clone(),
    }) {
        let failure = match error {
            tokio::sync::mpsc::error::TrySendError::Full(_) => ProxyDnsRequestFailure::Capacity,
            tokio::sync::mpsc::error::TrySendError::Closed(_) => ProxyDnsRequestFailure::Network,
        };
        allocator.release(id);
        let _ = request.response.send(Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Send,
            failure,
            "DNS TCP multiplex writer queue is unavailable",
        )));
        release_resident_dns_tcp_slot(lifecycle, active_count);
        return;
    }
    deadlines.push(Reverse((request.deadline, id, generation)));
    tokens.insert(request.token, id);
    pending.insert(
        id,
        ResidentDnsTcpPendingRequest {
            token: request.token,
            original_id,
            generation,
            request: payload,
            deadline: request.deadline,
            response: request.response,
        },
    );
}

async fn run_resident_dns_tcp_writer(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut writes: tokio::sync::mpsc::Receiver<ResidentDnsTcpWrite>,
) -> Result<(), String> {
    while let Some(write) = writes.recv().await {
        write_dns_tcp_payload_async(&mut writer, &write.payload)
            .await
            .map_err(|error| format!("write DNS TCP multiplex request: {error}"))?;
    }
    Ok(())
}

fn dispatch_resident_dns_tcp_response(
    mut response: Vec<u8>,
    pending: &mut HashMap<u16, ResidentDnsTcpPendingRequest>,
    tokens: &mut HashMap<u64, u16>,
    allocator: &mut super::udp_multiplex::DnsRequestIdAllocator,
    lifecycle: &ResidentDnsTcpMultiplexLifecycle,
    active_count: &AtomicUsize,
) {
    let Ok(id) = dns_packet_id(&response) else {
        return;
    };
    let Some(request) = pending.remove(&id) else {
        return;
    };
    tokens.remove(&request.token);
    allocator.release(id);
    release_resident_dns_tcp_slot(lifecycle, active_count);
    let result = validate_resident_dns_tcp_response(&request, &response).map(|()| {
        response[0..2].copy_from_slice(&request.original_id.to_be_bytes());
        response
    });
    let _ = request.response.send(result);
}

fn validate_resident_dns_tcp_response(
    request: &ResidentDnsTcpPendingRequest,
    response: &[u8],
) -> Result<(), ProxyDnsRequestError> {
    let request_view = DnsPacketView::parse(&request.request).map_err(|error| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Parse,
            ProxyDnsRequestFailure::Protocol,
            format!("parse pending DNS TCP request: {error}"),
        )
    })?;
    let response_view = DnsPacketView::parse(response).map_err(|error| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Protocol,
            format!("parse DNS TCP multiplex response: {error}"),
        )
    })?;
    validate_dns_packet_response_for_request_fast(&request_view, Some(&response_view), true)
        .map_err(|error| {
            ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Read,
                ProxyDnsRequestFailure::Protocol,
                format!("validate DNS TCP multiplex response: {error:?}"),
            )
        })
}

fn cancel_resident_dns_tcp_request(
    token: u64,
    pending: &mut HashMap<u16, ResidentDnsTcpPendingRequest>,
    tokens: &mut HashMap<u64, u16>,
    allocator: &mut super::udp_multiplex::DnsRequestIdAllocator,
    lifecycle: &ResidentDnsTcpMultiplexLifecycle,
    active_count: &AtomicUsize,
) {
    let Some(id) = tokens.remove(&token) else {
        return;
    };
    if pending.remove(&id).is_some() {
        allocator.release(id);
        release_resident_dns_tcp_slot(lifecycle, active_count);
    }
}

fn expire_resident_dns_tcp_requests(
    now: time::Instant,
    deadlines: &mut BinaryHeap<Reverse<(time::Instant, u16, u64)>>,
    pending: &mut HashMap<u16, ResidentDnsTcpPendingRequest>,
    tokens: &mut HashMap<u64, u16>,
    allocator: &mut super::udp_multiplex::DnsRequestIdAllocator,
    lifecycle: &ResidentDnsTcpMultiplexLifecycle,
    active_count: &AtomicUsize,
) {
    while deadlines.peek().is_some_and(|deadline| deadline.0.0 <= now) {
        let Some(Reverse((_, id, generation))) = deadlines.pop() else {
            break;
        };
        if !pending
            .get(&id)
            .is_some_and(|request| request.generation == generation && request.deadline <= now)
        {
            continue;
        }
        let Some(request) = pending.remove(&id) else {
            continue;
        };
        tokens.remove(&request.token);
        allocator.release(id);
        release_resident_dns_tcp_slot(lifecycle, active_count);
        let _ = request.response.send(Err(ProxyDnsRequestError::deadline(
            ProxyDnsRequestStage::Read,
        )));
    }
}

fn fail_all_resident_dns_tcp_requests(
    pending: &mut HashMap<u16, ResidentDnsTcpPendingRequest>,
    tokens: &mut HashMap<u64, u16>,
    allocator: &mut super::udp_multiplex::DnsRequestIdAllocator,
    lifecycle: &ResidentDnsTcpMultiplexLifecycle,
    active_count: &AtomicUsize,
    detail: &str,
) {
    for (id, request) in pending.drain() {
        tokens.remove(&request.token);
        allocator.release(id);
        release_resident_dns_tcp_slot(lifecycle, active_count);
        let _ = request.response.send(Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Cleanup,
            ProxyDnsRequestFailure::Network,
            detail.to_owned(),
        )));
    }
}

fn fail_queued_resident_dns_tcp_requests(
    commands: &mut tokio::sync::mpsc::Receiver<ResidentDnsTcpMultiplexCommand>,
    lifecycle: &ResidentDnsTcpMultiplexLifecycle,
    active_count: &AtomicUsize,
) {
    while let Ok(command) = commands.try_recv() {
        let ResidentDnsTcpMultiplexCommand::Request(request) = command else {
            continue;
        };
        let _ = request.response.send(Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Cleanup,
            ProxyDnsRequestFailure::Network,
            "DNS TCP multiplex connection stopped before request admission",
        )));
        release_resident_dns_tcp_slot(lifecycle, active_count);
    }
}

fn release_resident_dns_tcp_slot(
    lifecycle: &ResidentDnsTcpMultiplexLifecycle,
    active_count: &AtomicUsize,
) {
    let _ = active_count.fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
        Some(active.saturating_sub(1))
    });
    lifecycle.capacity_notify.notify_waiters();
}

fn dns_packet_id(payload: &[u8]) -> Result<u16, String> {
    let id = payload
        .get(0..2)
        .ok_or_else(|| "DNS packet is too short to read request id".to_owned())?;
    Ok(u16::from_be_bytes([id[0], id[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn tcp_multiplex_dispatches_out_of_order_responses_to_original_ids() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let first = read_frame(&mut stream).await;
            let second = read_frame(&mut stream).await;
            write_response(&mut stream, &second, [192, 0, 2, 2]).await;
            write_response(&mut stream, &first, [192, 0, 2, 1]).await;
        });
        let stream = TokioTcpStream::connect(target).await.unwrap();
        let (handle, registration) = ResidentDnsTcpMultiplexHandle::new(16);
        let actor = tokio::spawn(registration.run(stream));
        let first = build_dns_query_packet(0x1111, "first.example", DNS_QTYPE_A).unwrap();
        let second = build_dns_query_packet(0x2222, "second.example", DNS_QTYPE_A).unwrap();
        let context = ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(1));
        let (first, second) = tokio::join!(
            handle.exchange(&first, context),
            handle.exchange(&second, context),
        );
        assert_eq!(&first.unwrap()[0..2], &0x1111_u16.to_be_bytes());
        assert_eq!(&second.unwrap()[0..2], &0x2222_u16.to_be_bytes());
        handle.close();
        let _ = actor.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_multiplex_quarantines_a_late_response_after_request_timeout() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let first = read_frame(&mut stream).await;
            time::sleep(std::time::Duration::from_millis(50)).await;
            write_response(&mut stream, &first, [192, 0, 2, 10]).await;
            let second = read_frame(&mut stream).await;
            write_response(&mut stream, &second, [192, 0, 2, 11]).await;
        });
        let stream = TokioTcpStream::connect(target).await.unwrap();
        let (handle, registration) = ResidentDnsTcpMultiplexHandle::new(1);
        let actor = tokio::spawn(registration.run(stream));
        let first = build_dns_query_packet(0x3111, "late.example", DNS_QTYPE_A).unwrap();
        let first_error = handle
            .exchange(
                &first,
                ProxyDnsRequestContext::from_timeout(std::time::Duration::from_millis(20)),
            )
            .await
            .unwrap_err();
        assert_eq!(first_error.failure(), ProxyDnsRequestFailure::Deadline);
        time::timeout(std::time::Duration::from_millis(200), async {
            while handle.pending() != 0 {
                time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("timed out DNS TCP request retained its multiplex slot");
        let second = build_dns_query_packet(0x3222, "current.example", DNS_QTYPE_A).unwrap();
        let response = handle
            .exchange(
                &second,
                ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(1)),
            )
            .await
            .unwrap();
        assert_eq!(&response[0..2], &0x3222_u16.to_be_bytes());
        assert_eq!(handle.pending(), 0);
        handle.close();
        let _ = actor.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_multiplex_saturation_is_local_and_shutdown_releases_the_slot() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = listener.local_addr().unwrap();
        let request_received = Arc::new(tokio::sync::Notify::new());
        let server_notify = Arc::clone(&request_received);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = read_frame(&mut stream).await;
            server_notify.notify_one();
            std::future::pending::<()>().await;
        });
        let stream = TokioTcpStream::connect(target).await.unwrap();
        let (handle, registration) = ResidentDnsTcpMultiplexHandle::new(1);
        let actor = tokio::spawn(registration.run(stream));
        let first_query = build_dns_query_packet(0x4111, "held.example", DNS_QTYPE_A).unwrap();
        let first_handle = handle.clone();
        let first = tokio::spawn(async move {
            first_handle
                .exchange(
                    &first_query,
                    ProxyDnsRequestContext::from_timeout(Duration::from_secs(2)),
                )
                .await
        });
        time::timeout(Duration::from_millis(200), request_received.notified())
            .await
            .expect("DNS TCP fixture did not receive the first request");
        assert_eq!(handle.pending(), 1);

        let second_query =
            build_dns_query_packet(0x4222, "saturated.example", DNS_QTYPE_A).unwrap();
        let second_error = handle
            .exchange(
                &second_query,
                ProxyDnsRequestContext::from_timeout(Duration::from_millis(100)),
            )
            .await
            .unwrap_err();
        assert_eq!(second_error.failure(), ProxyDnsRequestFailure::Capacity);
        assert_eq!(handle.pending(), 1);

        handle.close();
        assert!(first.await.unwrap().is_err());
        assert_eq!(handle.pending(), 0);
        assert!(actor.await.unwrap().is_ok());
        server.abort();
    }

    #[tokio::test]
    async fn tcp_multiplex_connection_failure_releases_all_pending_requests() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = read_frame(&mut stream).await;
            let _ = read_frame(&mut stream).await;
        });
        let stream = TokioTcpStream::connect(target).await.unwrap();
        let (handle, registration) = ResidentDnsTcpMultiplexHandle::new(4);
        let actor = tokio::spawn(registration.run(stream));
        let first = build_dns_query_packet(0x5111, "closed-first.example", DNS_QTYPE_A).unwrap();
        let second = build_dns_query_packet(0x5222, "closed-second.example", DNS_QTYPE_A).unwrap();
        let context = ProxyDnsRequestContext::from_timeout(Duration::from_secs(1));
        let (first_result, second_result) = tokio::join!(
            handle.exchange(&first, context),
            handle.exchange(&second, context),
        );

        assert!(first_result.is_err());
        assert!(second_result.is_err());
        assert_eq!(handle.pending(), 0);
        assert!(handle.is_closed());
        assert!(actor.await.unwrap().is_err());
        server.await.unwrap();
    }

    async fn read_frame(stream: &mut TokioTcpStream) -> Vec<u8> {
        let len = stream.read_u16().await.unwrap() as usize;
        let mut payload = vec![0_u8; len];
        stream.read_exact(&mut payload).await.unwrap();
        payload
    }

    async fn write_response(stream: &mut TokioTcpStream, request: &[u8], ip: [u8; 4]) {
        let view = DnsPacketView::parse(request).unwrap();
        let mut response = Vec::new();
        response.extend_from_slice(&request[0..2]);
        response.extend_from_slice(&0x8180_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&request[12..view.answer_offset()]);
        response.extend_from_slice(&0xc00c_u16.to_be_bytes());
        response.extend_from_slice(&DNS_QTYPE_A.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&ip);
        stream.write_u16(response.len() as u16).await.unwrap();
        stream.write_all(&response).await.unwrap();
    }
}
