use std::collections::BTreeMap;

use super::super::*;
use super::plain::{DNS_UDP_FORWARD_ATTEMPTS, dns_udp_forward_attempt_timeout};

const DNS_UDP_MULTIPLEX_QUEUE_CAPACITY: usize = 4096;
const DNS_UDP_MULTIPLEX_PENDING_CAPACITY: usize = 4096;

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
    upstream_payload: Vec<u8>,
    original_id: u16,
    deadline: time::Instant,
    response: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
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
    let mut pending = BTreeMap::<u16, PendingUdpRequest>::new();
    let mut next_id = 0_u16;
    let mut buf = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
    let mut cleanup = time::interval(dns_udp_forward_attempt_timeout());
    loop {
        tokio::select! {
            biased;

            maybe_request = receiver.recv(), if pending.len() < DNS_UDP_MULTIPLEX_PENDING_CAPACITY => {
                let Some(request) = maybe_request else {
                    if pending.is_empty() {
                        break;
                    }
                    continue;
                };
                handle_udp_multiplex_request(target, &socket, &mut pending, &mut next_id, request).await;
            }

            received = socket.recv(&mut buf) => {
                match received {
                    Ok(read) => {
                        handle_udp_multiplex_response(&mut pending, &buf[..read]);
                    }
                    Err(err) => {
                        fail_pending_udp_requests(
                            &mut pending,
                            format!("receive DNS UDP multiplex response from {target}: {err}"),
                        );
                        break;
                    }
                }
            }

            _ = cleanup.tick() => {
                expire_pending_udp_requests(&mut pending);
                if receiver.is_closed() && pending.is_empty() {
                    break;
                }
            }
        }
    }
}

async fn handle_udp_multiplex_request(
    target: SocketAddr,
    socket: &tokio::net::UdpSocket,
    pending: &mut BTreeMap<u16, PendingUdpRequest>,
    next_id: &mut u16,
    request: UdpMultiplexRequest,
) {
    if pending.len() >= DNS_UDP_MULTIPLEX_PENDING_CAPACITY {
        let _ = request
            .response
            .send(Err("DNS UDP multiplex pending queue is full".to_owned()));
        return;
    }
    let original_id = match dns_packet_id(&request.payload) {
        Ok(id) => id,
        Err(err) => {
            let _ = request.response.send(Err(err));
            return;
        }
    };
    let upstream_id = match allocate_dns_udp_request_id(pending, next_id) {
        Ok(id) => id,
        Err(err) => {
            let _ = request.response.send(Err(err));
            return;
        }
    };
    let upstream_payload = rewrite_dns_packet_id(&request.payload, upstream_id);
    let deadline = time::Instant::now() + dns_udp_forward_attempt_timeout();
    pending.insert(
        upstream_id,
        PendingUdpRequest {
            upstream_payload: upstream_payload.clone(),
            original_id,
            deadline,
            response: request.response,
        },
    );
    if let Err(err) = socket.send(&upstream_payload).await {
        if let Some(pending) = pending.remove(&upstream_id) {
            let _ = pending.response.send(Err(format!(
                "send DNS UDP multiplex packet to {target}: {err}"
            )));
        }
    }
}

fn handle_udp_multiplex_response(pending: &mut BTreeMap<u16, PendingUdpRequest>, response: &[u8]) {
    let Ok(response_id) = dns_packet_id(response) else {
        return;
    };
    let Some(pending_request) = pending.remove(&response_id) else {
        return;
    };
    let result = validate_and_restore_udp_multiplex_response(&pending_request, response);
    let _ = pending_request.response.send(result);
}

fn validate_and_restore_udp_multiplex_response(
    pending: &PendingUdpRequest,
    response: &[u8],
) -> Result<Vec<u8>, String> {
    let request = DnsPacketView::parse(&pending.upstream_payload)
        .map_err(|err| format!("parse DNS UDP multiplex request: {err}"))?;
    let response_view = DnsPacketView::parse(response)
        .map_err(|err| format!("parse DNS UDP multiplex response: {err}"))?;
    validate_dns_packet_response_for_request_fast(&request, Some(&response_view), true)
        .map_err(|err| format!("validate DNS UDP multiplex response: {err:?}"))?;
    restore_packed_response_request_id(response, pending.original_id)
        .ok_or_else(|| "DNS UDP multiplex response is too short to restore request id".to_owned())
}

fn expire_pending_udp_requests(pending: &mut BTreeMap<u16, PendingUdpRequest>) {
    let now = time::Instant::now();
    let expired = pending
        .iter()
        .filter_map(|(id, request)| {
            (request.deadline <= now || request.response.is_closed()).then_some(*id)
        })
        .collect::<Vec<_>>();
    for id in expired {
        if let Some(request) = pending.remove(&id) {
            let _ = request
                .response
                .send(Err("DNS UDP multiplex pending request timed out".to_owned()));
        }
    }
}

fn fail_pending_udp_requests(pending: &mut BTreeMap<u16, PendingUdpRequest>, error: String) {
    let pending_requests = std::mem::take(pending);
    for (_, request) in pending_requests {
        let _ = request.response.send(Err(error.clone()));
    }
}

fn allocate_dns_udp_request_id(
    pending: &BTreeMap<u16, PendingUdpRequest>,
    next_id: &mut u16,
) -> Result<u16, String> {
    for _ in 0..=u16::MAX {
        let candidate = *next_id;
        *next_id = next_id.wrapping_add(1);
        if !pending.contains_key(&candidate) {
            return Ok(candidate);
        }
    }
    Err("DNS UDP multiplex request id space is exhausted".to_owned())
}

fn dns_packet_id(payload: &[u8]) -> Result<u16, String> {
    let Some(id) = payload.get(0..2) else {
        return Err("DNS packet is too short to read request id".to_owned());
    };
    Ok(u16::from_be_bytes([id[0], id[1]]))
}

fn rewrite_dns_packet_id(payload: &[u8], id: u16) -> Vec<u8> {
    let mut out = payload.to_vec();
    if out.len() >= 2 {
        out[0..2].copy_from_slice(&id.to_be_bytes());
    }
    out
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
