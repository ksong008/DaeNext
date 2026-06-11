use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use rcgen::generate_simple_self_signed;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::error::OutboundError;

use super::auth_stream::{build_auth_stream_transcript, build_deterministic_authenticate_header};
use super::h3_loopback::{
    DEFAULT_H3_ALPN, DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS, DEFAULT_H3_KEEPALIVE_SECS,
    DEFAULT_H3_SERVER_NAME,
};
use super::packet::build_dialauth_record_for_port_zero;

pub const DEFAULT_LIVE_AUTH_STREAM_TARGET: &str = "juicity-auth-stream.fixture.invalid:0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityLiveAuthStreamOptions {
    pub server_name: String,
    pub target: String,
    pub iterations: usize,
    pub timeout: Duration,
}

impl Default for JuicityLiveAuthStreamOptions {
    fn default() -> Self {
        Self {
            server_name: DEFAULT_H3_SERVER_NAME.to_owned(),
            target: DEFAULT_LIVE_AUTH_STREAM_TARGET.to_owned(),
            iterations: 1,
            timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct JuicityLiveAuthStreamReport {
    pub server_name: String,
    pub target: String,
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
    pub ns_per_juicity_live_auth_stream_exchange: f64,
    pub authenticate_header_len: usize,
    pub dialauth_record_len: usize,
    pub transcript_len: usize,
    pub auth_header_offset: usize,
    pub dialauth_record_offset: usize,
    pub open_uni_stream_count: usize,
    pub uni_stream_finish_count: usize,
    pub uni_stream_acked_count: usize,
    pub server_received_count: usize,
    pub server_received_len: usize,
    pub server_transcript_match_count: usize,
    pub auth_header_written_first: bool,
    pub dialauth_record_matches_auth_stream_contract: bool,
    pub live_auth_uni_stream_write_order_validated: bool,
    pub quic_handshake_validated: bool,
    pub juicity_authenticate_header_layout_admitted: bool,
    pub juicity_auth_uni_stream_write_order_admitted: bool,
    pub juicity_dialauth_record_over_auth_stream_admitted: bool,
    pub juicity_live_auth_uni_stream_harness_admitted: bool,
    pub juicity_live_auth_uni_stream_write_order_admitted: bool,
    pub juicity_auth_token_live_ekm_admitted: bool,
    pub juicity_dialauth_over_h3_admitted: bool,
    pub juicity_transport_packet_conn_dataplane_admitted: bool,
    pub juicity_stream_packet_conn_dataplane_admitted: bool,
    pub juicity_true_quic_h3_dataplane_admitted: bool,
}

#[derive(Debug)]
struct AcceptAnyServerCertVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl AcceptAnyServerCertVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        })
    }
}

impl ServerCertVerifier for AcceptAnyServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
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

pub fn run_live_auth_stream_smoke(
    options: &JuicityLiveAuthStreamOptions,
) -> Result<JuicityLiveAuthStreamReport, OutboundError> {
    if options.iterations == 0 {
        return Err(OutboundError::BadJuicity(
            "Juicity live auth stream iterations must be greater than zero".to_owned(),
        ));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| bad_live_auth_stream(format!("build tokio runtime: {err}")))?;
    runtime.block_on(async {
        tokio::time::timeout(options.timeout, run_live_auth_stream_smoke_async(options))
            .await
            .map_err(|_| bad_live_auth_stream("Juicity live auth stream timed out"))?
    })
}

async fn run_live_auth_stream_smoke_async(
    options: &JuicityLiveAuthStreamOptions,
) -> Result<JuicityLiveAuthStreamReport, OutboundError> {
    let header = build_deterministic_authenticate_header();
    let dialauth = build_dialauth_record_for_port_zero(&options.target)?;
    let transcript = build_auth_stream_transcript(&header, &dialauth);
    let expected_transcript = transcript.transcript.clone();

    let server_config = build_live_server_config(&options.server_name)?;
    let server_endpoint = quinn::Endpoint::server(
        server_config,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .map_err(|err| bad_live_auth_stream(format!("create server endpoint: {err}")))?;
    let loopback_addr = server_endpoint
        .local_addr()
        .map_err(|err| bad_live_auth_stream(format!("server local addr: {err}")))?;
    let server_iterations = options.iterations;
    let server_task = tokio::spawn(async move {
        run_live_auth_stream_server(server_endpoint, expected_transcript, server_iterations).await
    });

    let mut client_endpoint =
        quinn::Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .map_err(|err| bad_live_auth_stream(format!("create client endpoint: {err}")))?;
    client_endpoint.set_default_client_config(build_live_client_config()?);
    let client_connection = client_endpoint
        .connect(loopback_addr, &options.server_name)
        .map_err(|err| bad_live_auth_stream(format!("connect auth stream loopback: {err}")))?
        .await
        .map_err(|err| {
            bad_live_auth_stream(format!("await auth stream loopback connect: {err}"))
        })?;
    let client_selected_alpn = selected_alpn(&client_connection);

    let start = Instant::now();
    let mut open_uni_stream_count = 0_usize;
    let mut uni_stream_finish_count = 0_usize;
    let mut uni_stream_acked_count = 0_usize;
    for _ in 0..options.iterations {
        let mut stream = client_connection
            .open_uni()
            .await
            .map_err(|err| bad_live_auth_stream(format!("open auth uni stream: {err}")))?;
        open_uni_stream_count += 1;
        stream
            .write_all(&transcript.transcript)
            .await
            .map_err(|err| bad_live_auth_stream(format!("write auth uni stream: {err}")))?;
        stream
            .finish()
            .map_err(|err| bad_live_auth_stream(format!("finish auth uni stream: {err}")))?;
        uni_stream_finish_count += 1;
        if stream
            .stopped()
            .await
            .map_err(|err| bad_live_auth_stream(format!("wait auth uni stream ack: {err}")))?
            .is_none()
        {
            uni_stream_acked_count += 1;
        }
    }
    let elapsed_ns = start.elapsed().as_nanos();
    client_connection.close(0_u32.into(), b"juicity-auth-stream done");
    client_endpoint.wait_idle().await;

    let server = server_task.await.map_err(|err| {
        bad_live_auth_stream(format!("join live auth stream server task: {err}"))
    })??;
    let quic_handshake_validated =
        client_selected_alpn == DEFAULT_H3_ALPN && server.selected_alpn == DEFAULT_H3_ALPN;
    let live_harness_admitted = quic_handshake_validated
        && open_uni_stream_count == options.iterations
        && uni_stream_finish_count == options.iterations
        && server.received_count == options.iterations
        && server.transcript_match_count == options.iterations;
    let live_write_order_admitted = live_harness_admitted
        && transcript.auth_header_written_first
        && transcript.dialauth_record_matches_packet_state_contract
        && transcript.dialauth_record_order_valid;

    Ok(JuicityLiveAuthStreamReport {
        server_name: options.server_name.clone(),
        target: dialauth.target,
        alpn_protocol: DEFAULT_H3_ALPN.to_owned(),
        client_selected_alpn,
        server_selected_alpn: server.selected_alpn,
        tls13_only_configured: true,
        quic_datagram_disabled: true,
        keepalive_secs: DEFAULT_H3_KEEPALIVE_SECS,
        handshake_idle_timeout_secs: DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS,
        loopback_addr: loopback_addr.to_string(),
        iterations: options.iterations,
        elapsed_ns,
        ns_per_juicity_live_auth_stream_exchange: elapsed_ns as f64 / options.iterations as f64,
        authenticate_header_len: header.encoded.len(),
        dialauth_record_len: dialauth.packed.len(),
        transcript_len: transcript.transcript_len,
        auth_header_offset: transcript.auth_header_offset,
        dialauth_record_offset: transcript.dialauth_record_offset,
        open_uni_stream_count,
        uni_stream_finish_count,
        uni_stream_acked_count,
        server_received_count: server.received_count,
        server_received_len: server.last_received_len,
        server_transcript_match_count: server.transcript_match_count,
        auth_header_written_first: transcript.auth_header_written_first,
        dialauth_record_matches_auth_stream_contract: transcript
            .dialauth_record_matches_packet_state_contract,
        live_auth_uni_stream_write_order_validated: live_write_order_admitted,
        quic_handshake_validated,
        juicity_authenticate_header_layout_admitted: header.layout_valid(),
        juicity_auth_uni_stream_write_order_admitted: transcript.auth_header_written_first
            && transcript.dialauth_record_order_valid,
        juicity_dialauth_record_over_auth_stream_admitted: transcript
            .dialauth_record_matches_packet_state_contract,
        juicity_live_auth_uni_stream_harness_admitted: live_harness_admitted,
        juicity_live_auth_uni_stream_write_order_admitted: live_write_order_admitted,
        juicity_auth_token_live_ekm_admitted: false,
        juicity_dialauth_over_h3_admitted: false,
        juicity_transport_packet_conn_dataplane_admitted: false,
        juicity_stream_packet_conn_dataplane_admitted: false,
        juicity_true_quic_h3_dataplane_admitted: false,
    })
}

#[derive(Debug)]
struct LiveAuthStreamServerReport {
    selected_alpn: String,
    received_count: usize,
    last_received_len: usize,
    transcript_match_count: usize,
}

async fn run_live_auth_stream_server(
    endpoint: quinn::Endpoint,
    expected_transcript: Vec<u8>,
    iterations: usize,
) -> Result<LiveAuthStreamServerReport, OutboundError> {
    let connection = endpoint
        .accept()
        .await
        .ok_or_else(|| bad_live_auth_stream("server accept returned none"))?
        .await
        .map_err(|err| {
            bad_live_auth_stream(format!("server accept auth stream connection: {err}"))
        })?;
    let selected_alpn = selected_alpn(&connection);
    let mut received_count = 0_usize;
    let mut last_received_len = 0_usize;
    let mut transcript_match_count = 0_usize;
    for _ in 0..iterations {
        let mut stream = connection
            .accept_uni()
            .await
            .map_err(|err| bad_live_auth_stream(format!("accept auth uni stream: {err}")))?;
        let received = stream
            .read_to_end(expected_transcript.len())
            .await
            .map_err(|err| bad_live_auth_stream(format!("read auth uni stream: {err}")))?;
        received_count += 1;
        last_received_len = received.len();
        if received == expected_transcript {
            transcript_match_count += 1;
        }
    }
    endpoint.wait_idle().await;
    Ok(LiveAuthStreamServerReport {
        selected_alpn,
        received_count,
        last_received_len,
        transcript_match_count,
    })
}

pub(super) fn build_live_server_config(
    server_name: &str,
) -> Result<quinn::ServerConfig, OutboundError> {
    let certified = generate_simple_self_signed(vec![server_name.to_owned()])
        .map_err(|err| bad_live_auth_stream(format!("generate h3 cert: {err}")))?;
    let cert_der = certified.cert.der().clone();
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let mut crypto =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|err| bad_live_auth_stream(format!("server cert config: {err}")))?;
    crypto.alpn_protocols = vec![DEFAULT_H3_ALPN.as_bytes().to_vec()];
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(crypto)
            .map_err(|err| bad_live_auth_stream(format!("server quic tls config: {err}")))?,
    ));
    config.transport_config(Arc::new(transport_config()?));
    Ok(config)
}

pub(super) fn build_live_client_config() -> Result<quinn::ClientConfig, OutboundError> {
    let mut crypto =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(AcceptAnyServerCertVerifier::new())
            .with_no_client_auth();
    crypto.alpn_protocols = vec![DEFAULT_H3_ALPN.as_bytes().to_vec()];
    let mut config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)
            .map_err(|err| bad_live_auth_stream(format!("client quic tls config: {err}")))?,
    ));
    config.transport_config(Arc::new(transport_config()?));
    Ok(config)
}

fn transport_config() -> Result<quinn::TransportConfig, OutboundError> {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(DEFAULT_H3_KEEPALIVE_SECS)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS)
            .try_into()
            .map_err(|err| bad_live_auth_stream(format!("h3 idle timeout config: {err}")))?,
    ));
    transport.datagram_receive_buffer_size(None);
    transport.datagram_send_buffer_size(0);
    Ok(transport)
}

pub(super) fn selected_alpn(connection: &quinn::Connection) -> String {
    connection
        .handshake_data()
        .and_then(|data| data.downcast::<HandshakeData>().ok())
        .and_then(|data| data.protocol.clone())
        .map(|protocol| String::from_utf8_lossy(&protocol).to_string())
        .unwrap_or_default()
}

pub(super) fn bad_live_auth_stream(message: impl Into<String>) -> OutboundError {
    OutboundError::BadJuicity(message.into())
}
