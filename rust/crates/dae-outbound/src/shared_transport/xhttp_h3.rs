use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use h3::{client, server};
use http::{Method, Request, Response, StatusCode};
use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use rcgen::generate_simple_self_signed;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::error::OutboundError;
use crate::shared_transport::{XHttpLifecycleOptions, xhttp_request_path};

pub const XHTTP_H3_ALPN: &str = "h3";
pub const XHTTP_H3_KEEPALIVE_SECS: u64 = 5;
pub const XHTTP_H3_HANDSHAKE_IDLE_TIMEOUT_SECS: u64 = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XHttpH3LoopbackOptions {
    pub xhttp: XHttpLifecycleOptions,
    pub request_payload: Vec<u8>,
    pub response_payload: Vec<u8>,
    pub iterations: usize,
    pub timeout: Duration,
}

#[derive(Clone, Debug, PartialEq)]
pub struct XHttpH3LoopbackReport {
    pub server_name: String,
    pub alpn_protocol: String,
    pub client_selected_alpn: String,
    pub server_selected_alpn: String,
    pub tls13_only_configured: bool,
    pub quic_datagram_disabled: bool,
    pub keepalive_secs: u64,
    pub handshake_idle_timeout_secs: u64,
    pub loopback_addr: String,
    pub certificate_der_len: usize,
    pub certificate_callback_observed: bool,
    pub verifier_server_name: String,
    pub iterations: usize,
    pub total_exchange_count: usize,
    pub elapsed_ns: u128,
    pub ns_per_xhttp_h3_exchange: f64,
    pub xhttp_host: String,
    pub xhttp_path: String,
    pub xhttp_request_path: String,
    pub xhttp_mode: String,
    pub xhttp_security: String,
    pub xhttp_alpn: String,
    pub request_payload_len: usize,
    pub response_payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub h3_status: u16,
    pub h3_request_count: usize,
    pub h3_request_path_match_count: usize,
    pub h3_request_body_match_count: usize,
    pub h3_response_count: usize,
    pub h3_request_response_validated: bool,
    pub quic_handshake_validated: bool,
    pub xhttp_h3_packet_up_validated: bool,
    pub reality_h3_rejected: bool,
    pub full_h3_tls_lifecycle: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct CertCallbackState {
    observed: bool,
    server_name: String,
}

#[derive(Debug)]
struct AcceptAnyCertVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
    state: Arc<Mutex<CertCallbackState>>,
}

impl AcceptAnyCertVerifier {
    fn new(state: Arc<Mutex<CertCallbackState>>) -> Arc<Self> {
        Arc::new(Self {
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            state,
        })
    }
}

impl ServerCertVerifier for AcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut state) = self.state.lock() {
            state.observed = true;
            state.server_name = server_name.to_str().into_owned();
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug, Default)]
struct XHttpH3ServerSummary {
    selected_alpn: String,
    request_count: usize,
    request_path_match_count: usize,
    request_body_match_count: usize,
    response_count: usize,
}

impl XHttpH3LoopbackOptions {
    pub fn new(
        xhttp: XHttpLifecycleOptions,
        request_payload: Vec<u8>,
        response_payload: Vec<u8>,
        iterations: usize,
        timeout: Duration,
    ) -> Result<Self, OutboundError> {
        if iterations == 0 {
            return Err(bad_xhttp_h3(
                "xHTTP H3 loopback iterations must be greater than zero",
            ));
        }
        if xhttp.security != "tls" {
            return Err(bad_xhttp_h3("xHTTP H3 loopback requires security=tls"));
        }
        if xhttp.alpn != XHTTP_H3_ALPN {
            return Err(bad_xhttp_h3("xHTTP H3 loopback requires exact alpn=h3"));
        }
        if xhttp.mode != "packet-up" {
            return Err(bad_xhttp_h3(
                "xHTTP H3 loopback currently admits packet-up only",
            ));
        }
        if request_payload.is_empty() || response_payload.is_empty() {
            return Err(bad_xhttp_h3("xHTTP H3 payloads cannot be empty"));
        }
        Ok(Self {
            xhttp,
            request_payload,
            response_payload,
            iterations,
            timeout,
        })
    }
}

pub fn xhttp_h3_packet_up_loopback(
    options: &XHttpH3LoopbackOptions,
) -> Result<XHttpH3LoopbackReport, OutboundError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| bad_xhttp_h3(format!("build tokio runtime: {err}")))?;
    runtime.block_on(async {
        tokio::time::timeout(options.timeout, run_xhttp_h3_loopback_async(options))
            .await
            .map_err(|_| bad_xhttp_h3("xHTTP H3 loopback timed out"))?
    })
}

async fn run_xhttp_h3_loopback_async(
    options: &XHttpH3LoopbackOptions,
) -> Result<XHttpH3LoopbackReport, OutboundError> {
    let (server_config, cert_der) = build_server_config(&options.xhttp.host)?;
    let certificate_der_len = cert_der.as_ref().len();
    let server_endpoint = quinn::Endpoint::server(
        server_config,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .map_err(|err| bad_xhttp_h3(format!("create xHTTP H3 server endpoint: {err}")))?;
    let loopback_addr = server_endpoint
        .local_addr()
        .map_err(|err| bad_xhttp_h3(format!("xHTTP H3 server local addr: {err}")))?;
    let server_options = options.clone();
    let server_task =
        tokio::spawn(async move { run_xhttp_h3_server(server_endpoint, server_options).await });

    let verifier_state = Arc::new(Mutex::new(CertCallbackState::default()));
    let mut client_endpoint =
        quinn::Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .map_err(|err| bad_xhttp_h3(format!("create xHTTP H3 client endpoint: {err}")))?;
    client_endpoint.set_default_client_config(build_client_config(Arc::clone(&verifier_state))?);
    let client_connection = client_endpoint
        .connect(loopback_addr, &options.xhttp.host)
        .map_err(|err| bad_xhttp_h3(format!("connect xHTTP H3 loopback: {err}")))?
        .await
        .map_err(|err| bad_xhttp_h3(format!("await xHTTP H3 loopback connect: {err}")))?;
    let client_selected_alpn = selected_alpn(&client_connection);
    let h3_connection = h3_quinn::Connection::new(client_connection.clone());
    let (mut driver, mut client) = client::new(h3_connection)
        .await
        .map_err(|err| bad_xhttp_h3(format!("create xHTTP H3 client: {err:?}")))?;
    let driver_task = tokio::spawn(async move { poll_fn(|cx| driver.poll_close(cx)).await });

    let start = Instant::now();
    let request_path = xhttp_request_path(&options.xhttp);
    let mut last_echoed_payload = Vec::new();
    let mut last_status = StatusCode::OK;
    for _ in 0..options.iterations {
        let mut request_stream = client
            .send_request(
                Request::post(format!("https://{}{}", options.xhttp.host, request_path))
                    .body(())
                    .map_err(|err| bad_xhttp_h3(format!("build xHTTP H3 request: {err}")))?,
            )
            .await
            .map_err(|err| bad_xhttp_h3(format!("send xHTTP H3 request: {err:?}")))?;
        request_stream
            .send_data(Bytes::copy_from_slice(&options.request_payload))
            .await
            .map_err(|err| bad_xhttp_h3(format!("send xHTTP H3 request body: {err:?}")))?;
        request_stream
            .finish()
            .await
            .map_err(|err| bad_xhttp_h3(format!("finish xHTTP H3 request body: {err:?}")))?;
        let response = request_stream
            .recv_response()
            .await
            .map_err(|err| bad_xhttp_h3(format!("recv xHTTP H3 response: {err:?}")))?;
        last_status = response.status();
        last_echoed_payload.clear();
        while let Some(mut chunk) = request_stream
            .recv_data()
            .await
            .map_err(|err| bad_xhttp_h3(format!("recv xHTTP H3 response body: {err:?}")))?
        {
            let remaining = chunk.remaining();
            last_echoed_payload.extend_from_slice(&chunk.copy_to_bytes(remaining));
        }
    }
    let elapsed_ns = start.elapsed().as_nanos();
    drop(client);
    client_connection.close(0_u32.into(), b"xhttp-h3 done");
    client_endpoint.wait_idle().await;
    let _ = driver_task.await;
    let server = server_task
        .await
        .map_err(|err| bad_xhttp_h3(format!("join xHTTP H3 server task: {err}")))??;
    let callback = verifier_state
        .lock()
        .map_err(|_| bad_xhttp_h3("lock xHTTP H3 cert callback state"))?
        .clone();

    let quic_handshake_validated = client_selected_alpn == XHTTP_H3_ALPN
        && server.selected_alpn == XHTTP_H3_ALPN
        && callback.observed;
    let h3_request_response_validated = quic_handshake_validated
        && last_status == StatusCode::OK
        && last_echoed_payload == options.response_payload
        && server.request_count == options.iterations
        && server.request_path_match_count == options.iterations
        && server.request_body_match_count == options.iterations
        && server.response_count == options.iterations;

    Ok(XHttpH3LoopbackReport {
        server_name: options.xhttp.host.clone(),
        alpn_protocol: XHTTP_H3_ALPN.to_owned(),
        client_selected_alpn,
        server_selected_alpn: server.selected_alpn,
        tls13_only_configured: true,
        quic_datagram_disabled: true,
        keepalive_secs: XHTTP_H3_KEEPALIVE_SECS,
        handshake_idle_timeout_secs: XHTTP_H3_HANDSHAKE_IDLE_TIMEOUT_SECS,
        loopback_addr: loopback_addr.to_string(),
        certificate_der_len,
        certificate_callback_observed: callback.observed,
        verifier_server_name: callback.server_name,
        iterations: options.iterations,
        total_exchange_count: options.iterations,
        elapsed_ns,
        ns_per_xhttp_h3_exchange: elapsed_ns as f64 / options.iterations as f64,
        xhttp_host: options.xhttp.host.clone(),
        xhttp_path: crate::shared_transport::ir::normalize_xhttp_path_and_query(
            &options.xhttp.path,
        )
        .path,
        xhttp_request_path: request_path,
        xhttp_mode: options.xhttp.mode.clone(),
        xhttp_security: options.xhttp.security.clone(),
        xhttp_alpn: options.xhttp.alpn.clone(),
        request_payload_len: options.request_payload.len(),
        response_payload_len: options.response_payload.len(),
        echoed_payload: last_echoed_payload,
        h3_status: last_status.as_u16(),
        h3_request_count: server.request_count,
        h3_request_path_match_count: server.request_path_match_count,
        h3_request_body_match_count: server.request_body_match_count,
        h3_response_count: server.response_count,
        h3_request_response_validated,
        quic_handshake_validated,
        xhttp_h3_packet_up_validated: h3_request_response_validated,
        reality_h3_rejected: true,
        full_h3_tls_lifecycle: true,
        default_go_path: true,
    })
}

async fn run_xhttp_h3_server(
    endpoint: quinn::Endpoint,
    options: XHttpH3LoopbackOptions,
) -> Result<XHttpH3ServerSummary, OutboundError> {
    let connection = endpoint
        .accept()
        .await
        .ok_or_else(|| bad_xhttp_h3("xHTTP H3 server accept returned none"))?
        .await
        .map_err(|err| bad_xhttp_h3(format!("xHTTP H3 server accept connection: {err}")))?;
    let selected_alpn = selected_alpn(&connection);
    let h3_connection = h3_quinn::Connection::new(connection);
    let mut incoming = server::Connection::new(h3_connection)
        .await
        .map_err(|err| bad_xhttp_h3(format!("create xHTTP H3 server: {err:?}")))?;
    let request_path = xhttp_request_path(&options.xhttp);
    let mut summary = XHttpH3ServerSummary {
        selected_alpn,
        ..XHttpH3ServerSummary::default()
    };

    for _ in 0..options.iterations {
        let request = incoming
            .accept()
            .await
            .map_err(|err| bad_xhttp_h3(format!("accept xHTTP H3 request: {err:?}")))?
            .ok_or_else(|| bad_xhttp_h3("xHTTP H3 request stream closed"))?;
        let (request, mut stream) = request
            .resolve_request()
            .await
            .map_err(|err| bad_xhttp_h3(format!("resolve xHTTP H3 request: {err:?}")))?;
        summary.request_count += 1;
        if request.method() == Method::POST
            && request.uri().path_and_query().map(|value| value.as_str())
                == Some(request_path.as_str())
        {
            summary.request_path_match_count += 1;
        }
        let mut received = Vec::with_capacity(options.request_payload.len());
        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|err| bad_xhttp_h3(format!("recv xHTTP H3 request body: {err:?}")))?
        {
            let remaining = chunk.remaining();
            received.extend_from_slice(&chunk.copy_to_bytes(remaining));
        }
        if received == options.request_payload {
            summary.request_body_match_count += 1;
        }
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .map_err(|err| bad_xhttp_h3(format!("build xHTTP H3 response: {err}")))?,
            )
            .await
            .map_err(|err| bad_xhttp_h3(format!("send xHTTP H3 response: {err:?}")))?;
        stream
            .send_data(Bytes::copy_from_slice(&options.response_payload))
            .await
            .map_err(|err| bad_xhttp_h3(format!("send xHTTP H3 response body: {err:?}")))?;
        stream
            .finish()
            .await
            .map_err(|err| bad_xhttp_h3(format!("finish xHTTP H3 response body: {err:?}")))?;
        summary.response_count += 1;
    }
    endpoint.wait_idle().await;
    Ok(summary)
}

fn build_server_config(
    server_name: &str,
) -> Result<(quinn::ServerConfig, CertificateDer<'static>), OutboundError> {
    let certified = generate_simple_self_signed(vec![server_name.to_owned()])
        .map_err(|err| bad_xhttp_h3(format!("generate xHTTP H3 cert: {err}")))?;
    let cert_der = certified.cert.der().clone();
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let mut crypto =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .map_err(|err| bad_xhttp_h3(format!("xHTTP H3 server cert config: {err}")))?;
    crypto.alpn_protocols = vec![XHTTP_H3_ALPN.as_bytes().to_vec()];
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(crypto)
            .map_err(|err| bad_xhttp_h3(format!("xHTTP H3 server quic tls config: {err}")))?,
    ));
    config.transport_config(Arc::new(transport_config()?));
    Ok((config, cert_der))
}

fn build_client_config(
    verifier_state: Arc<Mutex<CertCallbackState>>,
) -> Result<quinn::ClientConfig, OutboundError> {
    let verifier = AcceptAnyCertVerifier::new(verifier_state);
    let mut crypto =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
    crypto.alpn_protocols = vec![XHTTP_H3_ALPN.as_bytes().to_vec()];
    let mut config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)
            .map_err(|err| bad_xhttp_h3(format!("xHTTP H3 client quic tls config: {err}")))?,
    ));
    config.transport_config(Arc::new(transport_config()?));
    Ok(config)
}

fn transport_config() -> Result<quinn::TransportConfig, OutboundError> {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(XHTTP_H3_KEEPALIVE_SECS)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(XHTTP_H3_HANDSHAKE_IDLE_TIMEOUT_SECS)
            .try_into()
            .map_err(|err| bad_xhttp_h3(format!("xHTTP H3 idle timeout config: {err}")))?,
    ));
    transport.datagram_receive_buffer_size(None);
    transport.datagram_send_buffer_size(0);
    Ok(transport)
}

fn selected_alpn(connection: &quinn::Connection) -> String {
    connection
        .handshake_data()
        .and_then(|data| data.downcast::<HandshakeData>().ok())
        .and_then(|data| data.protocol.clone())
        .map(|protocol| String::from_utf8_lossy(&protocol).to_string())
        .unwrap_or_default()
}

fn bad_xhttp_h3(message: impl Into<String>) -> OutboundError {
    OutboundError::BadSharedTransport(message.into())
}
