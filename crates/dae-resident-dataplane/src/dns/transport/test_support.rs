use super::*;

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use ::h3::server;
use bytes::Bytes;
use dae_outbound::shared_transport::boring_quic::{
    BoringQuicClientPolicy, build_boring_quic_client_config,
};
use dae_outbound::shared_transport::test_support::{
    boring_quic_server_config, self_signed_tls_identity,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::plan::build_resident_proxy_plan_for_node;

const DNS_TRANSPORT_TEST_SERVER_NAME: &str = "dns-transport.fixture.invalid";

pub(in crate::dns) struct Socks5UdpRelay {
    address: SocketAddr,
    control_connections: Arc<AtomicUsize>,
    datagrams_forwarded: Arc<AtomicUsize>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Socks5UdpRelay {
    pub(in crate::dns) async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let relay = Arc::new(
            tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap(),
        );
        let relay_address = relay.local_addr().unwrap();
        let control_connections = Arc::new(AtomicUsize::new(0));
        let datagrams_forwarded = Arc::new(AtomicUsize::new(0));

        let control_counter = Arc::clone(&control_connections);
        let control_task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            break;
                        };
                        control_counter.fetch_add(1, Ordering::AcqRel);
                        connections.spawn(serve_socks5_udp_control(stream, relay_address));
                    }
                    completed = connections.join_next(), if !connections.is_empty() => {
                        if completed.is_none() {
                            break;
                        }
                    }
                }
            }
        });

        let datagram_counter = Arc::clone(&datagrams_forwarded);
        let datagram_task = tokio::spawn(async move {
            let mut client = None::<SocketAddr>;
            let mut packet = vec![0_u8; u16::MAX as usize + 1];
            loop {
                let Ok((read, peer)) = relay.recv_from(&mut packet).await else {
                    break;
                };
                if let Ok(request) = dae_outbound::socks5::udp_packet::unwrap(&packet[..read])
                    && request.reserved == [0, 0]
                    && request.fragment == 0
                    && let Ok(target) = request.target.authority().parse::<SocketAddr>()
                {
                    client = Some(peer);
                    if relay.send_to(&request.payload, target).await.is_ok() {
                        datagram_counter.fetch_add(1, Ordering::AcqRel);
                    }
                    continue;
                }
                let Some(client) = client else {
                    continue;
                };
                let Ok(response) = dae_outbound::socks5::udp_packet::wrap_target(
                    &peer.to_string(),
                    &packet[..read],
                ) else {
                    continue;
                };
                let _ = relay.send_to(&response, client).await;
            }
        });

        Self {
            address,
            control_connections,
            datagrams_forwarded,
            tasks: vec![control_task, datagram_task],
        }
    }

    pub(in crate::dns) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(in crate::dns) fn control_connections(&self) -> usize {
        self.control_connections.load(Ordering::Acquire)
    }

    pub(in crate::dns) fn datagrams_forwarded(&self) -> usize {
        self.datagrams_forwarded.load(Ordering::Acquire)
    }
}

impl Drop for Socks5UdpRelay {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

pub(in crate::dns) struct Socks5TcpRelay {
    address: SocketAddr,
    connections: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Socks5TcpRelay {
    pub(in crate::dns) async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let connection_counter = Arc::clone(&connections);
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            break;
                        };
                        connection_counter.fetch_add(1, Ordering::AcqRel);
                        connections.spawn(serve_socks5_tcp_connection(stream));
                    }
                    completed = connections.join_next(), if !connections.is_empty() => {
                        if completed.is_none() {
                            break;
                        }
                    }
                }
            }
        });
        Self {
            address,
            connections,
            task,
        }
    }

    pub(in crate::dns) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(in crate::dns) fn connections(&self) -> usize {
        self.connections.load(Ordering::Acquire)
    }
}

impl Drop for Socks5TcpRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_socks5_tcp_connection(mut client: tokio::net::TcpStream) {
    let mut greeting = [0_u8; 2];
    if client.read_exact(&mut greeting).await.is_err() || greeting[0] != 5 {
        return;
    }
    let mut methods = vec![0_u8; greeting[1] as usize];
    if client.read_exact(&mut methods).await.is_err() || client.write_all(&[5, 0]).await.is_err() {
        return;
    }
    let mut header = [0_u8; 3];
    if client.read_exact(&mut header).await.is_err() || header != [5, 1, 0] {
        return;
    }
    let mut encoded_target = Vec::new();
    let mut address_type = [0_u8; 1];
    if client.read_exact(&mut address_type).await.is_err() {
        return;
    }
    encoded_target.push(address_type[0]);
    let tail_length = match address_type[0] {
        1 => 6,
        4 => 18,
        3 => {
            let mut length = [0_u8; 1];
            if client.read_exact(&mut length).await.is_err() {
                return;
            }
            encoded_target.push(length[0]);
            length[0] as usize + 2
        }
        _ => return,
    };
    let mut tail = vec![0_u8; tail_length];
    if client.read_exact(&mut tail).await.is_err() {
        return;
    }
    encoded_target.extend_from_slice(&tail);
    let Ok((target, _)) = dae_outbound::socks5::Socks5Address::decode(&encoded_target) else {
        return;
    };
    let Ok(mut upstream) = tokio::net::TcpStream::connect(target.authority()).await else {
        let _ = client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        return;
    };
    if client
        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
        .await
        .is_err()
    {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

async fn serve_socks5_udp_control(mut stream: tokio::net::TcpStream, relay_address: SocketAddr) {
    let mut greeting = [0_u8; 2];
    if stream.read_exact(&mut greeting).await.is_err() || greeting[0] != 5 {
        return;
    }
    let mut methods = vec![0_u8; greeting[1] as usize];
    if stream.read_exact(&mut methods).await.is_err() || stream.write_all(&[5, 0]).await.is_err() {
        return;
    }
    let mut request = [0_u8; 4];
    if stream.read_exact(&mut request).await.is_err() || request[0] != 5 || request[1] != 3 {
        return;
    }
    if read_socks5_address_tail(&mut stream, request[3])
        .await
        .is_err()
    {
        return;
    }
    let Ok(bind) = dae_outbound::socks5::Socks5Address::parse(&relay_address.to_string()) else {
        return;
    };
    let Ok(encoded_bind) = bind.encode() else {
        return;
    };
    let mut response = vec![5, 0, 0];
    response.extend_from_slice(&encoded_bind);
    if stream.write_all(&response).await.is_err() {
        return;
    }
    let mut hold = [0_u8; 1];
    let _ = stream.read(&mut hold).await;
}

async fn read_socks5_address_tail(
    stream: &mut tokio::net::TcpStream,
    address_type: u8,
) -> std::io::Result<()> {
    let bytes = match address_type {
        1 => 6,
        4 => 18,
        3 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            length[0] as usize + 2
        }
        _ => return Err(std::io::ErrorKind::InvalidData.into()),
    };
    let mut tail = vec![0_u8; bytes];
    stream.read_exact(&mut tail).await.map(|_| ())
}

pub(in crate::dns) fn socks5_dns_proxy(address: SocketAddr) -> Arc<ResidentProxyPlan> {
    let sections = dae_config::parser::parse_config(
        r#"
        global {
            allow_insecure: false
            so_mark_from_dae: 0
            mptcp: false
        }
        routing {
            fallback: direct
        }
        "#,
    )
    .unwrap();
    let config = dae_config::schema::build_config(&sections).unwrap();
    let mut proxy = build_resident_proxy_plan_for_node(
        &config,
        "dns-transport-test".to_owned(),
        "dns-transport-test-node".to_owned(),
        format!("socks5://{address}#dns-transport-test"),
    )
    .unwrap();
    proxy.materialize_execution();
    Arc::new(proxy)
}

pub(in crate::dns) fn dns_proxy_binding(
    proxy: Arc<ResidentProxyPlan>,
    generation: u64,
) -> ResidentProxyBinding {
    if generation == 0 {
        ResidentProxyBinding::control_plane(proxy).expect("materialized DNS test proxy")
    } else {
        ResidentProxyBinding::resident(proxy, dae_runtime_control::OwnerGeneration::new(generation))
            .expect("materialized DNS test proxy")
    }
}

#[derive(Clone, Copy)]
pub(in crate::dns) enum DnsQuicTestProtocol {
    Doq,
    Doh3,
}

pub(in crate::dns) struct DnsQuicTestServer {
    address: SocketAddr,
    certificate: Vec<u8>,
    protocol: DnsQuicTestProtocol,
    connections: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    current_connection: Arc<Mutex<Option<quinn::Connection>>>,
    task: tokio::task::JoinHandle<()>,
}

impl DnsQuicTestServer {
    pub(in crate::dns) async fn start_with_response_delay(
        protocol: DnsQuicTestProtocol,
        responses: Vec<Vec<u8>>,
        response_delay: std::time::Duration,
    ) -> Self {
        assert!(!responses.is_empty());
        let identity = self_signed_tls_identity(&[DNS_TRANSPORT_TEST_SERVER_NAME]).unwrap();
        let certificate = identity.certificate_der().unwrap();
        let server_config = boring_quic_server_config(
            &identity,
            &[protocol.alpn().as_bytes().to_vec()],
            Arc::new(quinn::TransportConfig::default()),
        )
        .unwrap();
        let endpoint = dae_outbound::shared_transport::test_support::boring_quic_server_endpoint(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let current_connection = Arc::new(Mutex::new(None));
        let task_connections = Arc::clone(&connections);
        let task_requests = Arc::clone(&requests);
        let task_current_connection = Arc::clone(&current_connection);
        let responses = Arc::new(responses);
        let task = tokio::spawn(async move {
            let mut connection_tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = endpoint.accept() => {
                        let Some(connecting) = accepted else {
                            break;
                        };
                        let connections = Arc::clone(&task_connections);
                        let requests = Arc::clone(&task_requests);
                        let responses = Arc::clone(&responses);
                        let current_connection = Arc::clone(&task_current_connection);
                        connection_tasks.spawn(async move {
                            let Ok(connection) = connecting.await else {
                                return;
                            };
                            connections.fetch_add(1, Ordering::AcqRel);
                            *current_connection.lock().unwrap() = Some(connection.clone());
                            match protocol {
                                DnsQuicTestProtocol::Doq => {
                                    serve_doq_connection(
                                        connection,
                                        requests,
                                        responses,
                                        response_delay,
                                    )
                                    .await;
                                }
                                DnsQuicTestProtocol::Doh3 => {
                                    serve_doh3_connection(
                                        connection,
                                        requests,
                                        responses,
                                        response_delay,
                                    )
                                    .await;
                                }
                            }
                        });
                    }
                    completed = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                        if completed.is_none() {
                            break;
                        }
                    }
                }
            }
        });
        Self {
            address,
            certificate,
            protocol,
            connections,
            requests,
            current_connection,
            task,
        }
    }

    pub(in crate::dns) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(in crate::dns) fn server_name(&self) -> &'static str {
        DNS_TRANSPORT_TEST_SERVER_NAME
    }

    pub(in crate::dns) fn client_config(&self) -> quinn::ClientConfig {
        let digest: [u8; 32] = Sha256::digest(&self.certificate).into();
        let policy = BoringQuicClientPolicy::new([self.protocol.alpn().as_bytes()])
            .unwrap()
            .pinned_leaf_sha256(digest, false);
        build_boring_quic_client_config(&policy, Arc::new(quinn::TransportConfig::default()))
            .unwrap()
    }

    pub(in crate::dns) fn connections(&self) -> usize {
        self.connections.load(Ordering::Acquire)
    }

    pub(in crate::dns) fn requests(&self) -> usize {
        self.requests.load(Ordering::Acquire)
    }

    pub(in crate::dns) fn close_current(&self) {
        if let Some(connection) = self.current_connection.lock().unwrap().as_ref() {
            connection.close(0_u32.into(), b"DNS transport test rebuild");
        }
    }
}

impl Drop for DnsQuicTestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl DnsQuicTestProtocol {
    fn alpn(self) -> &'static str {
        match self {
            Self::Doq => DNS_DOQ_ALPN,
            Self::Doh3 => DNS_DOH3_ALPN,
        }
    }
}

async fn serve_doq_connection(
    connection: quinn::Connection,
    requests: Arc<AtomicUsize>,
    responses: Arc<Vec<Vec<u8>>>,
    response_delay: std::time::Duration,
) {
    loop {
        let Ok((mut send, mut receive)) = connection.accept_bi().await else {
            return;
        };
        let requests = Arc::clone(&requests);
        let responses = Arc::clone(&responses);
        tokio::spawn(async move {
            let Ok(_) = super::wire::read_dns_tcp_message_async(&mut receive).await else {
                return;
            };
            let index = requests.fetch_add(1, Ordering::AcqRel);
            time::sleep(response_delay).await;
            let response = responses
                .get(index)
                .or_else(|| responses.last())
                .expect("DoQ test response exists");
            if super::wire::write_dns_tcp_message_async(&mut send, response)
                .await
                .is_ok()
            {
                let _ = send.finish();
            }
        });
    }
}

async fn serve_doh3_connection(
    connection: quinn::Connection,
    requests: Arc<AtomicUsize>,
    responses: Arc<Vec<Vec<u8>>>,
    response_delay: std::time::Duration,
) {
    let h3_connection = h3_quinn::Connection::new(connection);
    let Ok(mut incoming): Result<server::Connection<h3_quinn::Connection, Bytes>, _> =
        server::Connection::new(h3_connection).await
    else {
        return;
    };
    loop {
        let request = match incoming.accept().await {
            Ok(Some(request)) => request,
            _ => return,
        };
        let Ok((_request, mut stream)) = request.resolve_request().await else {
            return;
        };
        while let Ok(Some(_)) = stream.recv_data().await {}
        let index = requests.fetch_add(1, Ordering::AcqRel);
        time::sleep(response_delay).await;
        let response_body = responses
            .get(index)
            .or_else(|| responses.last())
            .expect("DoH3 test response exists");
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CONTENT_TYPE, DOH_MEDIA_TYPE)
            .body(())
            .unwrap();
        if stream.send_response(response).await.is_err()
            || stream
                .send_data(Bytes::copy_from_slice(response_body))
                .await
                .is_err()
        {
            return;
        }
        if stream.finish().await.is_err() {
            return;
        }
    }
}

pub(in crate::dns) fn dns_test_response(bytes: usize, marker: u8) -> Vec<u8> {
    let mut response = vec![marker; bytes.max(12)];
    response[0..2].copy_from_slice(&0_u16.to_be_bytes());
    response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    response[4..12].fill(0);
    response
}

pub(in crate::dns) fn dns_a_test_response(query: &[u8], address: [u8; 4]) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&DNS_QTYPE_A.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u32.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&address);
    response
}
