use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose};
use bytes::{Buf, Bytes};
use h3::{client, server};
use http::{Request, Response, StatusCode};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rcgen::generate_simple_self_signed;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::error::OutboundError;

use super::{generate_cert_chain_hash, verify_pinned_certchain};

pub const DEFAULT_H3_SERVER_NAME: &str = "localhost";
pub const DEFAULT_H3_ALPN: &str = "h3";
pub const DEFAULT_H3_KEEPALIVE_SECS: u64 = 5;
pub const DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS: u64 = 8;
pub const DEFAULT_H3_LOOPBACK_PAYLOAD: &[u8] = b"juicity-h3-loopback-ping";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityH3LoopbackOptions {
    pub server_name: String,
    pub payload: Vec<u8>,
    pub iterations: usize,
    pub timeout: Duration,
    pub verify_pinned_certchain: bool,
}

impl Default for JuicityH3LoopbackOptions {
    fn default() -> Self {
        Self {
            server_name: DEFAULT_H3_SERVER_NAME.to_owned(),
            payload: DEFAULT_H3_LOOPBACK_PAYLOAD.to_vec(),
            iterations: 1,
            timeout: Duration::from_secs(5),
            verify_pinned_certchain: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct JuicityH3LoopbackReport {
    pub server_name: String,
    pub alpn_protocol: String,
    pub client_selected_alpn: String,
    pub server_selected_alpn: String,
    pub tls13_only_configured: bool,
    pub quic_datagram_disabled: bool,
    pub keepalive_secs: u64,
    pub handshake_idle_timeout_secs: u64,
    pub loopback_addr: String,
    pub iterations: usize,
    pub elapsed_ns: u128,
    pub ns_per_juicity_h3_loopback_exchange: f64,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub h3_status: u16,
    pub h3_request_response_validated: bool,
    pub quic_handshake_validated: bool,
    pub certificate_chain_callback_observed: bool,
    pub certificate_chain_der_count: usize,
    pub certificate_chain_hash_hex: String,
    pub verifier_server_name: String,
    pub live_certchain_pin_format: Option<String>,
    pub live_certchain_pin_len: usize,
    pub live_certchain_pin_matched: bool,
    pub live_certchain_pin_error: Option<String>,
    pub ns_per_juicity_live_certchain_h3_exchange: Option<f64>,
    pub juicity_h3_handshake_admitted: bool,
    pub juicity_tls_verify_peer_certificate_hook_admitted: bool,
    pub juicity_tls_certchain_verification_admitted: bool,
    pub juicity_dialauth_over_h3_admitted: bool,
    pub juicity_transport_packet_conn_dataplane_admitted: bool,
    pub juicity_stream_packet_conn_dataplane_admitted: bool,
    pub juicity_true_quic_h3_dataplane_admitted: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct CertCallbackState {
    observed: bool,
    cert_count: usize,
    chain_hash_hex: String,
    server_name: String,
    pin_format: Option<String>,
    pin_matched: bool,
    pin_error: Option<String>,
}

#[derive(Debug)]
struct RecordingServerCertVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
    state: Arc<Mutex<CertCallbackState>>,
    pinned_certchain_sha256: Option<String>,
}

impl RecordingServerCertVerifier {
    fn new(
        state: Arc<Mutex<CertCallbackState>>,
        pinned_certchain_sha256: Option<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            state,
            pinned_certchain_sha256,
        })
    }
}

impl ServerCertVerifier for RecordingServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut raw_certs: Vec<&[u8]> = Vec::with_capacity(intermediates.len() + 1);
        raw_certs.push(end_entity.as_ref());
        raw_certs.extend(intermediates.iter().map(|cert| cert.as_ref()));
        let chain_hash = generate_cert_chain_hash(&raw_certs);
        let pin_check = self
            .pinned_certchain_sha256
            .as_deref()
            .map(|pin| verify_pinned_certchain(&raw_certs, pin));
        if let Ok(mut state) = self.state.lock() {
            state.observed = true;
            state.cert_count = raw_certs.len();
            state.chain_hash_hex = hex_encode(&chain_hash);
            state.server_name = server_name.to_str().into_owned();
            if let Some(check) = &pin_check {
                match check {
                    Ok(check) => {
                        state.pin_format = Some(check.pin_format.clone());
                        state.pin_matched = check.matched;
                        state.pin_error = None;
                    }
                    Err(err) => {
                        state.pin_format = None;
                        state.pin_matched = false;
                        state.pin_error = Some(err.to_string());
                    }
                }
            }
        }
        if let Some(Err(err)) = pin_check {
            return Err(rustls::Error::General(format!(
                "juicity pinned certchain verification failed: {err}"
            )));
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

pub fn run_h3_loopback_smoke(
    options: &JuicityH3LoopbackOptions,
) -> Result<JuicityH3LoopbackReport, OutboundError> {
    if options.iterations == 0 {
        return Err(OutboundError::BadJuicity(
            "Juicity h3 loopback iterations must be greater than zero".to_owned(),
        ));
    }
    if options.payload.is_empty() {
        return Err(OutboundError::BadJuicity(
            "Juicity h3 loopback payload cannot be empty".to_owned(),
        ));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| bad_loopback(format!("build tokio runtime: {err}")))?;
    runtime.block_on(async {
        tokio::time::timeout(options.timeout, run_h3_loopback_smoke_async(options))
            .await
            .map_err(|_| bad_loopback("Juicity h3 loopback timed out"))?
    })
}

async fn run_h3_loopback_smoke_async(
    options: &JuicityH3LoopbackOptions,
) -> Result<JuicityH3LoopbackReport, OutboundError> {
    let (server_config, cert_der) = build_server_config(&options.server_name)?;
    let pinned_certchain_sha256 = options
        .verify_pinned_certchain
        .then(|| encode_live_certchain_pin_url_base64(&cert_der));
    let server_endpoint = quinn::Endpoint::server(
        server_config,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .map_err(|err| bad_loopback(format!("create server endpoint: {err}")))?;
    let loopback_addr = server_endpoint
        .local_addr()
        .map_err(|err| bad_loopback(format!("server local addr: {err}")))?;
    let server_payload_len = options.payload.len();
    let server_iterations = options.iterations;
    let server_task = tokio::spawn(async move {
        run_h3_loopback_server(server_endpoint, server_iterations, server_payload_len).await
    });

    let verifier_state = Arc::new(Mutex::new(CertCallbackState::default()));
    let client_config =
        build_client_config(Arc::clone(&verifier_state), pinned_certchain_sha256.clone())?;
    let mut client_endpoint =
        quinn::Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .map_err(|err| bad_loopback(format!("create client endpoint: {err}")))?;
    client_endpoint.set_default_client_config(client_config);
    let client_connection = client_endpoint
        .connect(loopback_addr, &options.server_name)
        .map_err(|err| bad_loopback(format!("connect h3 loopback: {err}")))?
        .await
        .map_err(|err| bad_loopback(format!("await h3 loopback connect: {err}")))?;
    let client_selected_alpn = selected_alpn(&client_connection);
    let h3_connection = h3_quinn::Connection::new(client_connection.clone());
    let (mut driver, mut client) = client::new(h3_connection)
        .await
        .map_err(|err| bad_loopback(format!("create h3 client: {err:?}")))?;
    let driver_task = tokio::spawn(async move { poll_fn(|cx| driver.poll_close(cx)).await });

    let start = Instant::now();
    let mut last_echoed_payload = Vec::new();
    let mut last_status = StatusCode::OK;
    for _ in 0..options.iterations {
        let mut request_stream = client
            .send_request(
                Request::post(format!(
                    "https://{}/juicity-h3-loopback",
                    options.server_name
                ))
                .body(())
                .map_err(|err| bad_loopback(format!("build h3 request: {err}")))?,
            )
            .await
            .map_err(|err| bad_loopback(format!("send h3 request: {err:?}")))?;
        request_stream
            .send_data(Bytes::copy_from_slice(&options.payload))
            .await
            .map_err(|err| bad_loopback(format!("send h3 request body: {err:?}")))?;
        request_stream
            .finish()
            .await
            .map_err(|err| bad_loopback(format!("finish h3 request body: {err:?}")))?;
        let response = request_stream
            .recv_response()
            .await
            .map_err(|err| bad_loopback(format!("recv h3 response: {err:?}")))?;
        last_status = response.status();
        last_echoed_payload.clear();
        while let Some(mut chunk) = request_stream
            .recv_data()
            .await
            .map_err(|err| bad_loopback(format!("recv h3 response body: {err:?}")))?
        {
            let remaining = chunk.remaining();
            last_echoed_payload.extend_from_slice(&chunk.copy_to_bytes(remaining));
        }
    }
    let elapsed_ns = start.elapsed().as_nanos();
    drop(client);
    client_connection.close(0_u32.into(), b"juicity-h3-loopback done");
    client_endpoint.wait_idle().await;
    let _ = driver_task.await;
    let (server_selected_alpn, server_h3_request_count, server_h3_echo_count) = server_task
        .await
        .map_err(|err| bad_loopback(format!("join h3 server task: {err}")))??;

    let callback = verifier_state
        .lock()
        .map_err(|_| bad_loopback("lock cert callback state"))?
        .clone();
    let h3_request_response_validated = last_status == StatusCode::OK
        && last_echoed_payload == options.payload
        && server_h3_request_count == options.iterations
        && server_h3_echo_count == options.iterations;
    let quic_handshake_validated =
        client_selected_alpn == DEFAULT_H3_ALPN && server_selected_alpn == DEFAULT_H3_ALPN;
    let certificate_chain_der_count = if callback.cert_count == 0 {
        usize::from(!cert_der.as_ref().is_empty())
    } else {
        callback.cert_count
    };
    let live_certchain_requested = pinned_certchain_sha256.is_some();
    let live_certchain_admitted =
        live_certchain_requested && callback.observed && callback.pin_matched;

    Ok(JuicityH3LoopbackReport {
        server_name: options.server_name.clone(),
        alpn_protocol: DEFAULT_H3_ALPN.to_owned(),
        client_selected_alpn,
        server_selected_alpn,
        tls13_only_configured: true,
        quic_datagram_disabled: true,
        keepalive_secs: DEFAULT_H3_KEEPALIVE_SECS,
        handshake_idle_timeout_secs: DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS,
        loopback_addr: loopback_addr.to_string(),
        iterations: options.iterations,
        elapsed_ns,
        ns_per_juicity_h3_loopback_exchange: elapsed_ns as f64 / options.iterations as f64,
        payload_len: options.payload.len(),
        echoed_payload: last_echoed_payload,
        h3_status: last_status.as_u16(),
        h3_request_response_validated,
        quic_handshake_validated,
        certificate_chain_callback_observed: callback.observed,
        certificate_chain_der_count,
        certificate_chain_hash_hex: callback.chain_hash_hex,
        verifier_server_name: callback.server_name,
        live_certchain_pin_format: callback.pin_format,
        live_certchain_pin_len: pinned_certchain_sha256.as_deref().map_or(0, str::len),
        live_certchain_pin_matched: callback.pin_matched,
        live_certchain_pin_error: callback.pin_error,
        ns_per_juicity_live_certchain_h3_exchange: live_certchain_requested
            .then_some(elapsed_ns as f64 / options.iterations as f64),
        juicity_h3_handshake_admitted: h3_request_response_validated && quic_handshake_validated,
        juicity_tls_verify_peer_certificate_hook_admitted: callback.observed,
        juicity_tls_certchain_verification_admitted: live_certchain_admitted,
        juicity_dialauth_over_h3_admitted: false,
        juicity_transport_packet_conn_dataplane_admitted: false,
        juicity_stream_packet_conn_dataplane_admitted: false,
        juicity_true_quic_h3_dataplane_admitted: false,
    })
}

async fn run_h3_loopback_server(
    endpoint: quinn::Endpoint,
    iterations: usize,
    expected_payload_len: usize,
) -> Result<(String, usize, usize), OutboundError> {
    let connection = endpoint
        .accept()
        .await
        .ok_or_else(|| bad_loopback("server accept returned none"))?
        .await
        .map_err(|err| bad_loopback(format!("server accept h3 connection: {err}")))?;
    let selected_alpn = selected_alpn(&connection);
    let h3_connection = h3_quinn::Connection::new(connection);
    let mut incoming = server::Connection::new(h3_connection)
        .await
        .map_err(|err| bad_loopback(format!("create h3 server: {err:?}")))?;
    let mut accepted = 0_usize;
    let mut echoed = 0_usize;
    for _ in 0..iterations {
        let request = incoming
            .accept()
            .await
            .map_err(|err| bad_loopback(format!("accept h3 request: {err:?}")))?
            .ok_or_else(|| bad_loopback("h3 request stream closed"))?;
        let (_request, mut stream) = request
            .resolve_request()
            .await
            .map_err(|err| bad_loopback(format!("resolve h3 request: {err:?}")))?;
        accepted += 1;
        let mut received = Vec::with_capacity(expected_payload_len);
        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|err| bad_loopback(format!("recv h3 request body: {err:?}")))?
        {
            let remaining = chunk.remaining();
            received.extend_from_slice(&chunk.copy_to_bytes(remaining));
            if received.len() >= expected_payload_len {
                break;
            }
        }
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .map_err(|err| bad_loopback(format!("build h3 response: {err}")))?,
            )
            .await
            .map_err(|err| bad_loopback(format!("send h3 response: {err:?}")))?;
        stream
            .send_data(Bytes::copy_from_slice(&received))
            .await
            .map_err(|err| bad_loopback(format!("send h3 response body: {err:?}")))?;
        stream
            .finish()
            .await
            .map_err(|err| bad_loopback(format!("finish h3 response body: {err:?}")))?;
        echoed += 1;
    }
    endpoint.wait_idle().await;
    Ok((selected_alpn, accepted, echoed))
}

fn build_server_config(
    server_name: &str,
) -> Result<(quinn::ServerConfig, CertificateDer<'static>), OutboundError> {
    let certified = generate_simple_self_signed(vec![server_name.to_owned()])
        .map_err(|err| bad_loopback(format!("generate h3 cert: {err}")))?;
    let cert_der = certified.cert.der().clone();
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let mut crypto =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .map_err(|err| bad_loopback(format!("server cert config: {err}")))?;
    crypto.alpn_protocols = vec![DEFAULT_H3_ALPN.as_bytes().to_vec()];
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(crypto)
            .map_err(|err| bad_loopback(format!("server quic tls config: {err}")))?,
    ));
    config.transport_config(Arc::new(transport_config()?));
    Ok((config, cert_der))
}

fn build_client_config(
    verifier_state: Arc<Mutex<CertCallbackState>>,
    pinned_certchain_sha256: Option<String>,
) -> Result<quinn::ClientConfig, OutboundError> {
    let verifier = RecordingServerCertVerifier::new(verifier_state, pinned_certchain_sha256);
    let mut crypto =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
    crypto.alpn_protocols = vec![DEFAULT_H3_ALPN.as_bytes().to_vec()];
    let mut config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)
            .map_err(|err| bad_loopback(format!("client quic tls config: {err}")))?,
    ));
    config.transport_config(Arc::new(transport_config()?));
    Ok(config)
}

fn encode_live_certchain_pin_url_base64(cert_der: &CertificateDer<'_>) -> String {
    let raw_certs = [cert_der.as_ref()];
    let chain_hash = generate_cert_chain_hash(&raw_certs);
    general_purpose::URL_SAFE.encode(chain_hash)
}

fn transport_config() -> Result<quinn::TransportConfig, OutboundError> {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(DEFAULT_H3_KEEPALIVE_SECS)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS)
            .try_into()
            .map_err(|err| bad_loopback(format!("h3 idle timeout config: {err}")))?,
    ));
    transport.datagram_receive_buffer_size(None);
    transport.datagram_send_buffer_size(0);
    Ok(transport)
}

pub(super) fn selected_alpn(connection: &quinn::Connection) -> String {
    crate::shared_transport::boring_quic::selected_connection_alpn(connection)
        .map(|protocol| String::from_utf8_lossy(&protocol).into_owned())
        .unwrap_or_default()
}

fn bad_loopback(message: impl Into<String>) -> OutboundError {
    OutboundError::BadJuicity(message.into())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
