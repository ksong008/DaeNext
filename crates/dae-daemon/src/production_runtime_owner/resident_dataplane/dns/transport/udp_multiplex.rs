use std::collections::{HashMap, VecDeque};

use super::super::*;
use super::plain::{DNS_UDP_FORWARD_ATTEMPTS, dns_udp_forward_attempt_timeout};

const DNS_UDP_MULTIPLEX_QUEUE_CAPACITY: usize = 4096;
const DNS_UDP_MULTIPLEX_PENDING_CAPACITY: usize = 4096;
const DNS_UDP_FORWARDER_MAX_SHARDS: usize = 4;
const DNS_UDP_MULTIPLEX_WORKER_THREAD_NAME: &str = "daed-dns-udp";
const DNS_UDP_MULTIPLEX_WORKER_STACK_BYTES: usize = 512 * 1024;
const DNS_UDP_REQUEST_ID_SPACE: usize = (u16::MAX as usize) + 1;
const DNS_UDP_REQUEST_ID_BITMAP_WORD_BITS: usize = u64::BITS as usize;
const DNS_UDP_REQUEST_ID_BITMAP_WORDS: usize =
    DNS_UDP_REQUEST_ID_SPACE / DNS_UDP_REQUEST_ID_BITMAP_WORD_BITS;

#[derive(Clone)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsUdpMultiplexHandle
{
    sender: tokio::sync::mpsc::Sender<UdpMultiplexRequest>,
}

struct UdpMultiplexRequest {
    payload: Vec<u8>,
    response: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
}

struct PendingUdpRequest {
    upstream_id: u16,
    original_id: u16,
    generation: u64,
    deadline: time::Instant,
    questions: Vec<PendingDnsQuestion>,
    response: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingDnsQuestion {
    qname_wire: Vec<u8>,
    qtype: u16,
    qclass: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingUdpDeadline {
    id: u16,
    generation: u64,
    deadline: time::Instant,
}

struct UdpRequestIdAllocator {
    occupied: [u64; DNS_UDP_REQUEST_ID_BITMAP_WORDS],
    next_id: u16,
    in_use: usize,
}

impl Default for UdpRequestIdAllocator {
    fn default() -> Self {
        Self {
            occupied: [0_u64; DNS_UDP_REQUEST_ID_BITMAP_WORDS],
            next_id: 0,
            in_use: 0,
        }
    }
}

impl UdpRequestIdAllocator {
    fn allocate(&mut self, capacity: usize) -> Result<u16, String> {
        let capacity = capacity.min(DNS_UDP_REQUEST_ID_SPACE);
        if self.in_use >= capacity {
            return Err("DNS UDP multiplex pending queue is full".to_owned());
        }
        for _ in 0..DNS_UDP_REQUEST_ID_SPACE {
            let candidate = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            if self.is_occupied(candidate) {
                continue;
            }
            self.set_occupied(candidate, true);
            self.in_use += 1;
            return Ok(candidate);
        }
        Err("DNS UDP multiplex request id space is exhausted".to_owned())
    }

    fn release(&mut self, id: u16) {
        if !self.is_occupied(id) {
            return;
        }
        self.set_occupied(id, false);
        self.in_use = self.in_use.saturating_sub(1);
    }

    fn is_occupied(&self, id: u16) -> bool {
        let (word, bit) = dns_udp_request_id_bitmap_slot(id);
        self.occupied[word] & (1_u64 << bit) != 0
    }

    fn set_occupied(&mut self, id: u16, occupied: bool) {
        let (word, bit) = dns_udp_request_id_bitmap_slot(id);
        let mask = 1_u64 << bit;
        if occupied {
            self.occupied[word] |= mask;
        } else {
            self.occupied[word] &= !mask;
        }
    }
}

impl PendingDnsQuestion {
    fn matches(&self, qname_wire: &[u8], qtype: u16, qclass: u16) -> bool {
        self.qtype == qtype
            && self.qclass == qclass
            && self.qname_wire.eq_ignore_ascii_case(qname_wire)
    }
}

fn dns_udp_request_id_bitmap_slot(id: u16) -> (usize, usize) {
    let index = id as usize;
    (
        index / DNS_UDP_REQUEST_ID_BITMAP_WORD_BITS,
        index % DNS_UDP_REQUEST_ID_BITMAP_WORD_BITS,
    )
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) async fn open_udp_multiplex_handle(
    target: SocketAddr,
    mark: u32,
) -> Result<ResidentDnsUdpMultiplexHandle, String> {
    let socket = open_connected_dns_udp_socket(target, mark).await?;
    let (sender, receiver) = tokio::sync::mpsc::channel(DNS_UDP_MULTIPLEX_QUEUE_CAPACITY);
    tokio::spawn(run_udp_multiplex_actor(target, socket, receiver));
    Ok(ResidentDnsUdpMultiplexHandle { sender })
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) async fn open_threaded_udp_multiplex_handle(
    target: SocketAddr,
    mark: u32,
) -> Result<ResidentDnsUdpMultiplexHandle, String> {
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name(DNS_UDP_MULTIPLEX_WORKER_THREAD_NAME.to_owned())
        .stack_size(DNS_UDP_MULTIPLEX_WORKER_STACK_BYTES)
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    let _ = ready_tx.send(Err(format!(
                        "build DNS UDP multiplex worker runtime: {err}"
                    )));
                    return;
                }
            };
            let opened = runtime.block_on(async {
                let socket = open_connected_dns_udp_socket(target, mark).await?;
                let (sender, receiver) =
                    tokio::sync::mpsc::channel(DNS_UDP_MULTIPLEX_QUEUE_CAPACITY);
                Ok::<_, String>((ResidentDnsUdpMultiplexHandle { sender }, socket, receiver))
            });
            match opened {
                Ok((handle, socket, receiver)) => {
                    let _ = ready_tx.send(Ok(handle));
                    runtime.block_on(run_udp_multiplex_actor(target, socket, receiver));
                }
                Err(err) => {
                    let _ = ready_tx.send(Err(err));
                }
            }
        })
        .map_err(|err| format!("spawn DNS UDP multiplex worker thread: {err}"))?;
    ready_rx
        .await
        .map_err(|_| "DNS UDP multiplex worker exited before initialization".to_owned())?
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) fn dns_udp_forwarder_shard_count()
-> usize {
    let parallelism = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    dns_udp_forwarder_shard_count_for_parallelism(parallelism)
}

fn dns_udp_forwarder_shard_count_for_parallelism(parallelism: usize) -> usize {
    if parallelism <= 1 {
        1
    } else {
        parallelism.min(DNS_UDP_FORWARDER_MAX_SHARDS)
    }
}

impl ResidentDnsUdpMultiplexHandle {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) async fn exchange(
        &self,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mut failures = Vec::new();
        for _ in 0..DNS_UDP_FORWARD_ATTEMPTS {
            match self.exchange_once(payload).await {
                Ok(response) => return Ok(response),
                Err(err) => failures.push(err),
            }
        }
        Err(format!(
            "receive DNS UDP response timeout after {DNS_UDP_FORWARD_ATTEMPTS} attempts: {}",
            failures.join("; ")
        ))
    }

    async fn exchange_once(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        time::timeout(
            dns_udp_forward_attempt_timeout(),
            self.sender.send(UdpMultiplexRequest {
                payload: payload.to_vec(),
                response: response_tx,
            }),
        )
        .await
        .map_err(|_| "DNS UDP multiplex request queue wait timeout".to_owned())?
        .map_err(|_| "DNS UDP multiplex actor is closed".to_owned())?;
        time::timeout(dns_udp_forward_attempt_timeout(), response_rx)
            .await
            .map_err(|_| "DNS UDP multiplex exchange timeout".to_owned())?
            .map_err(|_| "DNS UDP multiplex actor dropped response".to_owned())?
    }
}

async fn run_udp_multiplex_actor(
    target: SocketAddr,
    socket: tokio::net::UdpSocket,
    mut receiver: tokio::sync::mpsc::Receiver<UdpMultiplexRequest>,
) {
    let mut pending = HashMap::<u16, PendingUdpRequest>::new();
    let mut id_allocator = UdpRequestIdAllocator::default();
    let mut deadlines = VecDeque::<PendingUdpDeadline>::new();
    let mut next_generation = 1_u64;
    let mut buf = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
    loop {
        expire_pending_udp_requests(&mut pending, &mut deadlines, &mut id_allocator);
        if receiver.is_closed() && pending.is_empty() {
            break;
        }
        let cleanup_deadline = next_udp_multiplex_deadline(&mut deadlines, &pending);
        tokio::select! {
            biased;

            received = socket.recv(&mut buf) => {
                match received {
                    Ok(read) => {
                        handle_udp_multiplex_response(&mut pending, &mut id_allocator, &buf[..read]);
                    }
                    Err(err) => {
                        fail_pending_udp_requests(
                            &mut pending,
                            &mut id_allocator,
                            format!("receive DNS UDP multiplex response from {target}: {err}"),
                        );
                        break;
                    }
                }
            }

            maybe_request = receiver.recv(), if pending.len() < DNS_UDP_MULTIPLEX_PENDING_CAPACITY => {
                let Some(request) = maybe_request else {
                    if pending.is_empty() {
                        break;
                    }
                    continue;
                };
                handle_udp_multiplex_request(
                    target,
                    &socket,
                    &mut pending,
                    &mut id_allocator,
                    &mut deadlines,
                    &mut next_generation,
                    request,
                ).await;
            }

            _ = wait_for_udp_multiplex_deadline(cleanup_deadline) => {
                expire_pending_udp_requests(&mut pending, &mut deadlines, &mut id_allocator);
            }
        }
    }
}

async fn handle_udp_multiplex_request(
    target: SocketAddr,
    socket: &tokio::net::UdpSocket,
    pending: &mut HashMap<u16, PendingUdpRequest>,
    id_allocator: &mut UdpRequestIdAllocator,
    deadlines: &mut VecDeque<PendingUdpDeadline>,
    next_generation: &mut u64,
    mut request: UdpMultiplexRequest,
) {
    if pending.len() >= DNS_UDP_MULTIPLEX_PENDING_CAPACITY {
        let _ = request
            .response
            .send(Err("DNS UDP multiplex pending queue is full".to_owned()));
        return;
    }
    let request_view = match DnsPacketView::parse(&request.payload) {
        Ok(view) => view,
        Err(err) => {
            let _ = request
                .response
                .send(Err(format!("parse DNS UDP multiplex request: {err}")));
            return;
        }
    };
    let original_id = request_view.id();
    let questions = pending_dns_questions(&request_view);
    let upstream_id = match id_allocator.allocate(DNS_UDP_MULTIPLEX_PENDING_CAPACITY) {
        Ok(id) => id,
        Err(err) => {
            let _ = request.response.send(Err(err));
            return;
        }
    };
    rewrite_dns_packet_id_in_place(&mut request.payload, upstream_id);
    let deadline = time::Instant::now() + dns_udp_forward_attempt_timeout();
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
    deadlines.push_back(PendingUdpDeadline {
        id: upstream_id,
        generation,
        deadline,
    });
    if let Err(err) = socket.send(&request.payload).await {
        if let Some(pending) = pending.remove(&upstream_id) {
            id_allocator.release(upstream_id);
            let _ = pending.response.send(Err(format!(
                "send DNS UDP multiplex packet to {target}: {err}"
            )));
        }
    }
}

fn handle_udp_multiplex_response(
    pending: &mut HashMap<u16, PendingUdpRequest>,
    id_allocator: &mut UdpRequestIdAllocator,
    response: &[u8],
) {
    let Ok(response_id) = dns_packet_id(response) else {
        return;
    };
    let Some(pending_request) = pending.remove(&response_id) else {
        return;
    };
    id_allocator.release(response_id);
    let result = validate_and_restore_udp_multiplex_response(&pending_request, response);
    let _ = pending_request.response.send(result);
}

fn validate_and_restore_udp_multiplex_response(
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

fn expire_pending_udp_requests(
    pending: &mut HashMap<u16, PendingUdpRequest>,
    deadlines: &mut VecDeque<PendingUdpDeadline>,
    id_allocator: &mut UdpRequestIdAllocator,
) {
    let now = time::Instant::now();
    loop {
        let Some(deadline) = deadlines.front().copied() else {
            break;
        };
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
            let _ = request
                .response
                .send(Err("DNS UDP multiplex pending request timed out".to_owned()));
        }
    }
}

fn fail_pending_udp_requests(
    pending: &mut HashMap<u16, PendingUdpRequest>,
    id_allocator: &mut UdpRequestIdAllocator,
    error: String,
) {
    let pending_requests = std::mem::take(pending);
    for (id, request) in pending_requests {
        id_allocator.release(id);
        let _ = request.response.send(Err(error.clone()));
    }
}

fn next_udp_multiplex_deadline(
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

fn dns_packet_id(payload: &[u8]) -> Result<u16, String> {
    let Some(id) = payload.get(0..2) else {
        return Err("DNS packet is too short to read request id".to_owned());
    };
    Ok(u16::from_be_bytes([id[0], id[1]]))
}

fn pending_dns_questions(request: &DnsPacketView<'_>) -> Vec<PendingDnsQuestion> {
    request
        .questions()
        .map(|question| PendingDnsQuestion {
            qname_wire: question.qname_wire().to_vec(),
            qtype: question.qtype(),
            qclass: question.qclass(),
        })
        .collect()
}

fn rewrite_dns_packet_id_in_place(payload: &mut [u8], id: u16) {
    if payload.len() >= 2 {
        payload[0..2].copy_from_slice(&id.to_be_bytes());
    }
}

async fn open_connected_dns_udp_socket(
    target: SocketAddr,
    mark: u32,
) -> Result<tokio::net::UdpSocket, String> {
    let bind = match target {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket =
        std::net::UdpSocket::bind(bind).map_err(|err| format!("bind DNS UDP socket: {err}"))?;
    apply_resident_udp_socket_buffer_tuning(&socket);
    if mark != 0 {
        set_socket_mark(socket.as_raw_fd(), mark)
            .map_err(|err| format!("set DNS UDP SO_MARK {mark}: {err}"))?;
    }
    socket
        .set_nonblocking(true)
        .map_err(|err| format!("set DNS UDP nonblocking: {err}"))?;
    let socket = tokio::net::UdpSocket::from_std(socket)
        .map_err(|err| format!("adopt async DNS UDP socket: {err}"))?;
    socket
        .connect(target)
        .await
        .map_err(|err| format!("connect DNS UDP socket to {target}: {err}"))?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_request_id_allocator_enforces_capacity_and_releases_ids() {
        let mut allocator = UdpRequestIdAllocator::default();
        let first = allocator.allocate(1).unwrap();
        assert!(allocator.allocate(1).is_err());
        assert!(allocator.is_occupied(first));

        allocator.release(first);
        assert!(!allocator.is_occupied(first));
        allocator.next_id = first;
        assert_eq!(allocator.allocate(1).unwrap(), first);
    }

    #[test]
    fn udp_deadline_cleanup_ignores_stale_generation_for_reused_id() {
        let mut allocator = UdpRequestIdAllocator::default();
        let id = allocator
            .allocate(DNS_UDP_MULTIPLEX_PENDING_CAPACITY)
            .unwrap();
        let mut pending = HashMap::new();
        let mut deadlines = VecDeque::new();
        let now = time::Instant::now();
        let live_deadline = now + dns_udp_forward_attempt_timeout();
        let (response, _receiver) = tokio::sync::oneshot::channel();

        pending.insert(
            id,
            PendingUdpRequest {
                upstream_id: id,
                original_id: id,
                generation: 2,
                deadline: live_deadline,
                questions: Vec::new(),
                response,
            },
        );
        deadlines.push_back(PendingUdpDeadline {
            id,
            generation: 1,
            deadline: now,
        });
        deadlines.push_back(PendingUdpDeadline {
            id,
            generation: 2,
            deadline: live_deadline,
        });

        expire_pending_udp_requests(&mut pending, &mut deadlines, &mut allocator);

        assert!(pending.contains_key(&id));
        assert!(allocator.is_occupied(id));
        assert_eq!(
            next_udp_multiplex_deadline(&mut deadlines, &pending),
            Some(live_deadline)
        );
    }

    #[test]
    fn udp_forwarder_shard_count_follows_cpu_parallelism() {
        assert_eq!(dns_udp_forwarder_shard_count_for_parallelism(0), 1);
        assert_eq!(dns_udp_forwarder_shard_count_for_parallelism(1), 1);
        assert_eq!(dns_udp_forwarder_shard_count_for_parallelism(2), 2);
        assert_eq!(
            dns_udp_forwarder_shard_count_for_parallelism(DNS_UDP_FORWARDER_MAX_SHARDS + 1),
            DNS_UDP_FORWARDER_MAX_SHARDS
        );
    }

    #[test]
    fn udp_multiplex_validation_rejects_question_mismatch() {
        const UPSTREAM_ID: u16 = 0x5151;
        const ORIGINAL_ID: u16 = 0x1515;
        const EXPECTED_QNAME: &str = "expected.example";
        const DIFFERENT_QNAME: &str = "different.example";

        let expected_query =
            build_dns_query_packet(ORIGINAL_ID, EXPECTED_QNAME, DNS_QTYPE_A).unwrap();
        let expected_view = DnsPacketView::parse(&expected_query).unwrap();
        let (response, _receiver) = tokio::sync::oneshot::channel();
        let pending = PendingUdpRequest {
            upstream_id: UPSTREAM_ID,
            original_id: ORIGINAL_ID,
            generation: 1,
            deadline: time::Instant::now() + dns_udp_forward_attempt_timeout(),
            questions: pending_dns_questions(&expected_view),
            response,
        };
        let different_query =
            build_dns_query_packet(UPSTREAM_ID, DIFFERENT_QNAME, DNS_QTYPE_A).unwrap();
        let different_response = dns_a_response_for_query(&different_query, [192, 0, 2, 1]);

        assert!(
            validate_and_restore_udp_multiplex_response(&pending, &different_response).is_err()
        );
    }

    #[tokio::test]
    async fn udp_multiplex_handles_out_of_order_responses() {
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = upstream.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut first = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
            let mut second = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
            let (first_len, peer) = upstream.recv_from(&mut first).await.unwrap();
            let (second_len, _) = upstream.recv_from(&mut second).await.unwrap();
            let first_response = dns_a_response_for_query(&first[..first_len], [192, 0, 2, 1]);
            let second_response = dns_a_response_for_query(&second[..second_len], [192, 0, 2, 2]);
            upstream.send_to(&second_response, peer).await.unwrap();
            upstream.send_to(&first_response, peer).await.unwrap();
        });
        let handle = open_udp_multiplex_handle(target, 0).await.unwrap();
        let first = build_dns_query_packet(0x1111, "first.example", DNS_QTYPE_A).unwrap();
        let second = build_dns_query_packet(0x2222, "second.example", DNS_QTYPE_A).unwrap();
        let (first_response, second_response) =
            tokio::join!(handle.exchange(&first), handle.exchange(&second));

        assert_eq!(&first_response.unwrap()[0..2], &0x1111_u16.to_be_bytes());
        assert_eq!(&second_response.unwrap()[0..2], &0x2222_u16.to_be_bytes());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn udp_multiplex_discards_stale_response() {
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = upstream.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut request = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
            let (read, peer) = upstream.recv_from(&mut request).await.unwrap();
            let mut stale = dns_a_response_for_query(&request[..read], [192, 0, 2, 1]);
            stale[0..2].copy_from_slice(&0xffff_u16.to_be_bytes());
            let response = dns_a_response_for_query(&request[..read], [192, 0, 2, 2]);
            upstream.send_to(&stale, peer).await.unwrap();
            upstream.send_to(&response, peer).await.unwrap();
        });
        let handle = open_udp_multiplex_handle(target, 0).await.unwrap();
        let query = build_dns_query_packet(0x3333, "stale.example", DNS_QTYPE_A).unwrap();
        let response = handle.exchange(&query).await.unwrap();

        assert_eq!(&response[0..2], &0x3333_u16.to_be_bytes());
        server.await.unwrap();
    }

    fn dns_a_response_for_query(query: &[u8], address: [u8; 4]) -> Vec<u8> {
        let view = DnsPacketView::parse(query).unwrap();
        let mut response = Vec::new();
        response.extend_from_slice(&query[0..2]);
        response.extend_from_slice(&0x8180_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&query[12..view.answer_offset()]);
        response.extend_from_slice(&0xc00c_u16.to_be_bytes());
        response.extend_from_slice(&DNS_QTYPE_A.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&address);
        response
    }
}
