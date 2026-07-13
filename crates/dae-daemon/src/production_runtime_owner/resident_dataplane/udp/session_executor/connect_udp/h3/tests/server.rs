use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::task::{JoinHandle, JoinSet};

use dae_outbound::shared_transport::encode_quic_varint;

use super::super::*;

const TEST_SERVER_NAME: &str = "connect-udp-h3.fixture.invalid";
const TEST_DATAGRAM_BUFFER_BYTES: usize = 64 * 1024;

type ConnectUdpH3ServerStream = ::h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

#[derive(Clone, Copy)]
enum TestResponseBehavior {
    Echo,
    DnsAnswer,
    UnknownQuarterThenEcho,
    MalformedContext,
    GoAwayAfterFirstStream,
    ResetAfterHeaders,
    CloseConnectionAfterHeaders,
}

#[derive(Clone)]
pub(super) struct ConnectUdpH3TestServerConfig {
    enable_extended_connect: bool,
    enable_h3_datagram: bool,
    enable_quic_datagram: bool,
    negotiate_capsule_protocol: bool,
    expected_authorization: Option<String>,
    response_status: StatusCode,
    behavior: TestResponseBehavior,
}

impl ConnectUdpH3TestServerConfig {
    pub(super) fn echo() -> Self {
        Self {
            enable_extended_connect: true,
            enable_h3_datagram: true,
            enable_quic_datagram: true,
            negotiate_capsule_protocol: true,
            expected_authorization: None,
            response_status: StatusCode::OK,
            behavior: TestResponseBehavior::Echo,
        }
    }

    pub(super) fn dns_answer() -> Self {
        Self {
            behavior: TestResponseBehavior::DnsAnswer,
            ..Self::echo()
        }
    }

    pub(super) fn with_basic_auth(mut self, username: &str, password: &str) -> Self {
        self.expected_authorization = Some(format!(
            "Basic {}",
            STANDARD.encode(format!("{username}:{password}"))
        ));
        self
    }

    pub(super) fn without_extended_connect(mut self) -> Self {
        self.enable_extended_connect = false;
        self
    }

    pub(super) fn without_h3_datagram(mut self) -> Self {
        self.enable_h3_datagram = false;
        self
    }

    pub(super) fn without_quic_datagram(mut self) -> Self {
        self.enable_quic_datagram = false;
        self
    }

    pub(super) fn without_capsule_protocol(mut self) -> Self {
        self.negotiate_capsule_protocol = false;
        self
    }

    pub(super) fn with_response_status(mut self, status: StatusCode) -> Self {
        self.response_status = status;
        self
    }

    pub(super) fn unknown_quarter_then_echo() -> Self {
        Self {
            behavior: TestResponseBehavior::UnknownQuarterThenEcho,
            ..Self::echo()
        }
    }

    pub(super) fn malformed_context() -> Self {
        Self {
            behavior: TestResponseBehavior::MalformedContext,
            ..Self::echo()
        }
    }

    pub(super) fn reset_after_headers() -> Self {
        Self {
            behavior: TestResponseBehavior::ResetAfterHeaders,
            ..Self::echo()
        }
    }

    pub(super) fn goaway_after_first_stream() -> Self {
        Self {
            behavior: TestResponseBehavior::GoAwayAfterFirstStream,
            ..Self::echo()
        }
    }

    pub(super) fn close_connection_after_headers() -> Self {
        Self {
            behavior: TestResponseBehavior::CloseConnectionAfterHeaders,
            ..Self::echo()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ConnectUdpH3TestObservation {
    pub(super) method: String,
    pub(super) uri: String,
    pub(super) protocol: Option<String>,
    pub(super) authorization: Option<String>,
    pub(super) capsule_protocol: Option<String>,
    pub(super) quarter_stream_id: u64,
}

struct ConnectUdpH3TestServerState {
    connections: AtomicUsize,
    streams: AtomicUsize,
    datagrams: AtomicUsize,
    goaway_sent: AtomicBool,
    observations: Mutex<Vec<ConnectUdpH3TestObservation>>,
}

pub(super) struct ConnectUdpH3TestServer {
    address: std::net::SocketAddr,
    state: Arc<ConnectUdpH3TestServerState>,
    task: JoinHandle<()>,
}

impl ConnectUdpH3TestServer {
    pub(super) async fn start(config: ConnectUdpH3TestServerConfig) -> Self {
        let endpoint = quinn::Endpoint::server(
            build_server_config(config.enable_quic_datagram),
            (std::net::Ipv4Addr::LOCALHOST, 0).into(),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let state = Arc::new(ConnectUdpH3TestServerState {
            connections: AtomicUsize::new(0),
            streams: AtomicUsize::new(0),
            datagrams: AtomicUsize::new(0),
            goaway_sent: AtomicBool::new(false),
            observations: Mutex::new(Vec::new()),
        });
        let task_state = Arc::clone(&state);
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            while let Some(connecting) = endpoint.accept().await {
                let state = Arc::clone(&task_state);
                let config = config.clone();
                connections.spawn(async move {
                    let Ok(connection) = connecting.await else {
                        return;
                    };
                    state.connections.fetch_add(1, Ordering::Relaxed);
                    run_connection(connection, config, state).await;
                });
            }
        });
        Self {
            address,
            state,
            task,
        }
    }

    pub(super) fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    pub(super) fn server_name(&self) -> &'static str {
        TEST_SERVER_NAME
    }

    pub(super) fn connection_count(&self) -> usize {
        self.state.connections.load(Ordering::Relaxed)
    }

    pub(super) fn stream_count(&self) -> usize {
        self.state.streams.load(Ordering::Relaxed)
    }

    pub(super) fn datagram_count(&self) -> usize {
        self.state.datagrams.load(Ordering::Relaxed)
    }

    pub(super) fn observations(&self) -> Vec<ConnectUdpH3TestObservation> {
        self.state.observations.lock().unwrap().clone()
    }
}

impl Drop for ConnectUdpH3TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn build_server_config(enable_quic_datagram: bool) -> quinn::ServerConfig {
    let certified = generate_simple_self_signed(vec![TEST_SERVER_NAME.to_owned()]).unwrap();
    let cert_der = certified.cert.der().clone();
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let mut crypto =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut server =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto).unwrap()));
    let mut transport = quinn::TransportConfig::default();
    if enable_quic_datagram {
        transport.datagram_receive_buffer_size(Some(TEST_DATAGRAM_BUFFER_BYTES));
        transport.datagram_send_buffer_size(TEST_DATAGRAM_BUFFER_BYTES);
    } else {
        transport.datagram_receive_buffer_size(None);
        transport.datagram_send_buffer_size(0);
    }
    server.transport_config(Arc::new(transport));
    server
}

async fn run_connection(
    connection: quinn::Connection,
    config: ConnectUdpH3TestServerConfig,
    state: Arc<ConnectUdpH3TestServerState>,
) {
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let mut builder = ::h3::server::builder();
    builder
        .enable_extended_connect(config.enable_extended_connect)
        .enable_datagram(config.enable_h3_datagram);
    let Ok(mut incoming) = builder.build::<_, Bytes>(h3_connection).await else {
        return;
    };
    let mut sessions = HashMap::<MasqueQuarterStreamId, ConnectUdpH3ServerStream>::new();

    loop {
        tokio::select! {
            request = incoming.accept() => {
                let Ok(Some(resolver)) = request else {
                    break;
                };
                let Ok((request, stream)) = resolver.resolve_request().await else {
                    break;
                };
                if matches!(config.behavior, TestResponseBehavior::GoAwayAfterFirstStream)
                    && !state.goaway_sent.swap(true, Ordering::AcqRel)
                    && incoming.shutdown(0).await.is_err()
                {
                    break;
                }
                if handle_request(&connection, request, stream, &config, &state, &mut sessions)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            datagram = connection.read_datagram(), if config.enable_quic_datagram => {
                let Ok(datagram) = datagram else {
                    break;
                };
                if handle_datagram(&connection, datagram, &config, &state, &sessions).is_err() {
                    break;
                }
            }
        }
    }
}

async fn handle_request(
    connection: &quinn::Connection,
    request: Request<()>,
    mut stream: ConnectUdpH3ServerStream,
    config: &ConnectUdpH3TestServerConfig,
    state: &ConnectUdpH3TestServerState,
    sessions: &mut HashMap<MasqueQuarterStreamId, ConnectUdpH3ServerStream>,
) -> Result<(), ()> {
    let quarter_stream_id =
        MasqueQuarterStreamId::from_quarter_stream_id(stream.id().index()).map_err(|_| ())?;
    let protocol = request
        .extensions()
        .get::<::h3::ext::Protocol>()
        .map(|value| value.as_str().to_owned());
    let authorization = header_value(&request, http::header::PROXY_AUTHORIZATION.as_str());
    let capsule_protocol = header_value(&request, CAPSULE_PROTOCOL_HEADER);
    state.streams.fetch_add(1, Ordering::Relaxed);
    state
        .observations
        .lock()
        .map_err(|_| ())?
        .push(ConnectUdpH3TestObservation {
            method: request.method().to_string(),
            uri: request.uri().to_string(),
            protocol,
            authorization: authorization.clone(),
            capsule_protocol,
            quarter_stream_id: quarter_stream_id.value(),
        });

    let authenticated = config
        .expected_authorization
        .as_ref()
        .is_none_or(|expected| authorization.as_ref() == Some(expected));
    let status = if authenticated {
        config.response_status
    } else {
        StatusCode::PROXY_AUTHENTICATION_REQUIRED
    };
    let mut response = Response::builder().status(status);
    if config.negotiate_capsule_protocol {
        response = response.header(CAPSULE_PROTOCOL_HEADER, CAPSULE_PROTOCOL_TRUE);
    }
    stream
        .send_response(response.body(()).map_err(|_| ())?)
        .await
        .map_err(|_| ())?;

    if !status.is_success() || !config.negotiate_capsule_protocol {
        let _ = stream.finish().await;
        return Ok(());
    }
    match config.behavior {
        TestResponseBehavior::ResetAfterHeaders => {
            stream.stop_stream(::h3::error::Code::H3_REQUEST_CANCELLED);
            stream.stop_sending(::h3::error::Code::H3_REQUEST_CANCELLED);
        }
        TestResponseBehavior::CloseConnectionAfterHeaders => {
            connection.close(0_u32.into(), b"fixture connection close");
        }
        _ => {
            sessions.insert(quarter_stream_id, stream);
        }
    }
    Ok(())
}

fn handle_datagram(
    connection: &quinn::Connection,
    datagram: Bytes,
    config: &ConnectUdpH3TestServerConfig,
    state: &ConnectUdpH3TestServerState,
    sessions: &HashMap<MasqueQuarterStreamId, ConnectUdpH3ServerStream>,
) -> Result<(), ()> {
    let limits = ResidentConnectUdpRuntimePlan::standalone().capsule_limits;
    let decoded =
        decode_http_datagram(datagram, limits.max_datagram_payload_bytes).map_err(|_| ())?;
    if !sessions.contains_key(&decoded.quarter_stream_id) {
        return Ok(());
    }
    state.datagrams.fetch_add(1, Ordering::Relaxed);
    match config.behavior {
        TestResponseBehavior::MalformedContext => {
            let mut malformed = Vec::new();
            encode_quic_varint(decoded.quarter_stream_id.value(), &mut malformed)
                .map_err(|_| ())?;
            encode_quic_varint(1, &mut malformed).map_err(|_| ())?;
            malformed.extend_from_slice(&decoded.payload);
            connection
                .send_datagram(Bytes::from(malformed))
                .map_err(|_| ())?;
        }
        TestResponseBehavior::UnknownQuarterThenEcho => {
            let unknown = MasqueQuarterStreamId::from_quarter_stream_id(
                decoded.quarter_stream_id.value().saturating_add(1),
            )
            .map_err(|_| ())?;
            let unrelated =
                encode_http_datagram(unknown, b"unrelated", limits.max_datagram_payload_bytes)
                    .map_err(|_| ())?;
            connection
                .send_datagram(Bytes::from(unrelated))
                .map_err(|_| ())?;
            send_echo(
                connection,
                decoded.quarter_stream_id,
                decoded.payload,
                limits,
            )?;
        }
        TestResponseBehavior::DnsAnswer => {
            send_echo(
                connection,
                decoded.quarter_stream_id,
                Bytes::from(dns_answer(&decoded.payload)),
                limits,
            )?;
        }
        TestResponseBehavior::Echo | TestResponseBehavior::GoAwayAfterFirstStream => {
            send_echo(
                connection,
                decoded.quarter_stream_id,
                decoded.payload,
                limits,
            )?;
        }
        TestResponseBehavior::ResetAfterHeaders
        | TestResponseBehavior::CloseConnectionAfterHeaders => {}
    }
    Ok(())
}

fn send_echo(
    connection: &quinn::Connection,
    quarter_stream_id: MasqueQuarterStreamId,
    payload: Bytes,
    limits: dae_outbound::shared_transport::MasqueCapsuleLimits,
) -> Result<(), ()> {
    let response = encode_http_datagram(
        quarter_stream_id,
        &payload,
        limits.max_datagram_payload_bytes,
    )
    .map_err(|_| ())?;
    connection
        .send_datagram(Bytes::from(response))
        .map_err(|_| ())
}

fn header_value(request: &Request<()>, name: &str) -> Option<String> {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn dns_answer(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return query.to_vec();
    }
    let mut response = query.to_vec();
    response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&[
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 0, 2, 1,
    ]);
    response
}
