use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures_util::future::poll_fn;
use http::{Request, Response, StatusCode};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

use super::super::*;

const TEST_SERVER_NAME: &str = "connect-udp-h2.fixture.invalid";
const CAPSULE_PROTOCOL_HEADER: &str = "capsule-protocol";
const CAPSULE_PROTOCOL_TRUE: &str = "?1";

#[derive(Clone, Copy)]
enum TestResponseBehavior {
    Echo,
    DnsAnswer,
    GoAwayAfterFirstStream,
    ResetAfterHeaders,
    MalformedCapsule,
}

#[derive(Clone)]
pub(super) struct ConnectUdpH2TestServerConfig {
    enable_extended_connect: bool,
    negotiate_capsule_protocol: bool,
    expected_authorization: Option<String>,
    behavior: TestResponseBehavior,
}

impl ConnectUdpH2TestServerConfig {
    pub(super) fn echo() -> Self {
        Self {
            enable_extended_connect: true,
            negotiate_capsule_protocol: true,
            expected_authorization: None,
            behavior: TestResponseBehavior::Echo,
        }
    }

    pub(super) fn with_basic_auth(mut self, username: &str, password: &str) -> Self {
        self.expected_authorization = Some(format!(
            "Basic {}",
            STANDARD.encode(format!("{username}:{password}"))
        ));
        self
    }

    pub(super) fn dns_answer() -> Self {
        Self {
            behavior: TestResponseBehavior::DnsAnswer,
            ..Self::echo()
        }
    }

    pub(super) fn without_extended_connect(mut self) -> Self {
        self.enable_extended_connect = false;
        self
    }

    pub(super) fn without_capsule_protocol(mut self) -> Self {
        self.negotiate_capsule_protocol = false;
        self
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

    pub(super) fn malformed_capsule() -> Self {
        Self {
            behavior: TestResponseBehavior::MalformedCapsule,
            ..Self::echo()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ConnectUdpH2TestObservation {
    pub(super) method: String,
    pub(super) uri: String,
    pub(super) protocol: Option<String>,
    pub(super) authorization: Option<String>,
}

struct ConnectUdpH2TestServerState {
    connections: AtomicUsize,
    streams: AtomicUsize,
    goaway_sent: AtomicBool,
    observations: Mutex<Vec<ConnectUdpH2TestObservation>>,
}

pub(super) struct ConnectUdpH2TestServer {
    address: std::net::SocketAddr,
    state: Arc<ConnectUdpH2TestServerState>,
    task: JoinHandle<()>,
}

impl ConnectUdpH2TestServer {
    pub(super) async fn start(config: ConnectUdpH2TestServerConfig) -> Self {
        let certified = generate_simple_self_signed(vec![TEST_SERVER_NAME.to_owned()]).unwrap();
        let cert_der = certified.cert.der().clone();
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        tls_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(ConnectUdpH2TestServerState {
            connections: AtomicUsize::new(0),
            streams: AtomicUsize::new(0),
            goaway_sent: AtomicBool::new(false),
            observations: Mutex::new(Vec::new()),
        });
        let task_state = Arc::clone(&state);
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let config = config.clone();
                let state = Arc::clone(&task_state);
                connections.spawn(async move {
                    let Ok(tls) = acceptor.accept(socket).await else {
                        return;
                    };
                    state.connections.fetch_add(1, Ordering::Relaxed);
                    let mut builder = ::h2::server::Builder::new();
                    if config.enable_extended_connect {
                        builder.enable_connect_protocol();
                    }
                    let Ok(mut connection) = builder.handshake(tls).await else {
                        return;
                    };
                    let mut streams = JoinSet::new();
                    while let Some(result) = connection.accept().await {
                        let Ok((request, respond)) = result else {
                            break;
                        };
                        state.streams.fetch_add(1, Ordering::Relaxed);
                        if matches!(
                            config.behavior,
                            TestResponseBehavior::GoAwayAfterFirstStream
                        ) && !state.goaway_sent.swap(true, Ordering::AcqRel)
                        {
                            connection.graceful_shutdown();
                        }
                        let config = config.clone();
                        let state = Arc::clone(&state);
                        streams.spawn(async move {
                            handle_request(request, respond, config, state).await;
                        });
                    }
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

    pub(super) fn observations(&self) -> Vec<ConnectUdpH2TestObservation> {
        self.state.observations.lock().unwrap().clone()
    }
}

impl Drop for ConnectUdpH2TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle_request(
    mut request: Request<::h2::RecvStream>,
    mut respond: ::h2::server::SendResponse<Bytes>,
    config: ConnectUdpH2TestServerConfig,
    state: Arc<ConnectUdpH2TestServerState>,
) {
    let protocol = request
        .extensions()
        .get::<::h2::ext::Protocol>()
        .map(|value| value.as_str().to_owned());
    let authorization = request
        .headers()
        .get(http::header::PROXY_AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    state
        .observations
        .lock()
        .unwrap()
        .push(ConnectUdpH2TestObservation {
            method: request.method().to_string(),
            uri: request.uri().to_string(),
            protocol,
            authorization: authorization.clone(),
        });

    let authenticated = config
        .expected_authorization
        .as_ref()
        .is_none_or(|expected| authorization.as_ref() == Some(expected));
    let mut response = Response::builder().status(if authenticated {
        StatusCode::OK
    } else {
        StatusCode::PROXY_AUTHENTICATION_REQUIRED
    });
    if config.negotiate_capsule_protocol {
        response = response.header(CAPSULE_PROTOCOL_HEADER, CAPSULE_PROTOCOL_TRUE);
    }
    let Ok(response) = response.body(()) else {
        return;
    };
    let Ok(mut send) = respond.send_response(response, false) else {
        return;
    };
    if !authenticated || !config.negotiate_capsule_protocol {
        let _ = send.send_data(Bytes::new(), true);
        return;
    }
    match config.behavior {
        TestResponseBehavior::ResetAfterHeaders => {
            send.send_reset(::h2::Reason::CANCEL);
        }
        TestResponseBehavior::MalformedCapsule => {
            if let Some(Ok(data)) = request.body_mut().data().await {
                let _ = request
                    .body_mut()
                    .flow_control()
                    .release_capacity(data.len());
            }
            // DATAGRAM Capsule with Context ID 1, which the client contract rejects.
            let _ = send.send_data(Bytes::from_static(&[0x00, 0x01, 0x01]), false);
            while let Some(data) = request.body_mut().data().await {
                let Ok(data) = data else {
                    break;
                };
                let _ = request
                    .body_mut()
                    .flow_control()
                    .release_capacity(data.len());
            }
        }
        TestResponseBehavior::Echo
        | TestResponseBehavior::DnsAnswer
        | TestResponseBehavior::GoAwayAfterFirstStream => {
            let limits = ResidentConnectUdpRuntimePlan::standalone().capsule_limits;
            let mut decoder = MasqueCapsuleDecoder::new(limits);
            while let Some(data) = request.body_mut().data().await {
                let Ok(data) = data else {
                    return;
                };
                let _ = request
                    .body_mut()
                    .flow_control()
                    .release_capacity(data.len());
                let Ok(capsules) = decoder.push(&data) else {
                    send.send_reset(::h2::Reason::PROTOCOL_ERROR);
                    return;
                };
                for capsule in capsules {
                    let MasqueCapsule::Datagram(payload) = capsule else {
                        continue;
                    };
                    let payload = match config.behavior {
                        TestResponseBehavior::DnsAnswer => dns_answer(&payload),
                        _ => payload.to_vec(),
                    };
                    let Ok(encoded) = encode_connect_udp_capsule(&payload, limits) else {
                        send.send_reset(::h2::Reason::PROTOCOL_ERROR);
                        return;
                    };
                    if send_h2_data(&mut send, Bytes::from(encoded)).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

fn dns_answer(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return query.to_vec();
    }
    let mut response = query.to_vec();
    response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&[
        0xc0, 0x0c, // compressed question name
        0x00, 0x01, // A
        0x00, 0x01, // IN
        0x00, 0x00, 0x00, 0x3c, // TTL
        0x00, 0x04, // RDLENGTH
        192, 0, 2, 1,
    ]);
    response
}

async fn send_h2_data(
    send: &mut ::h2::SendStream<Bytes>,
    mut data: Bytes,
) -> Result<(), ::h2::Error> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let capacity = loop {
            if send.capacity() > 0 {
                break send.capacity();
            }
            let Some(capacity) = poll_fn(|cx| send.poll_capacity(cx)).await else {
                return Err(::h2::Reason::CANCEL.into());
            };
            capacity?;
        };
        let chunk = data.split_to(capacity.min(data.len()));
        send.send_data(chunk, false)?;
    }
    Ok(())
}
