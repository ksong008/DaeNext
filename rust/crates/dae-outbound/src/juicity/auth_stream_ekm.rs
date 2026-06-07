use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use crate::error::OutboundError;

use super::auth_stream::{
    JUICITY_AUTHENTICATE_TOKEN_LEN, build_auth_stream_transcript, build_authenticate_header,
    build_deterministic_authenticate_header,
};
use super::auth_stream_live::{build_live_client_config, build_live_server_config, selected_alpn};
use super::h3_loopback::{
    DEFAULT_H3_ALPN, DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS, DEFAULT_H3_KEEPALIVE_SECS,
    DEFAULT_H3_SERVER_NAME,
};
use super::packet::build_dialauth_record_for_port_zero;

pub const DEFAULT_LIVE_EKM_AUTH_TARGET: &str = "juicity-ekm-auth.example:0";
pub const DEFAULT_LIVE_EKM_AUTH_PASSWORD: &str = "juicity-live-ekm-password";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityLiveEkmAuthOptions {
    pub server_name: String,
    pub target: String,
    pub password: Vec<u8>,
    pub iterations: usize,
    pub timeout: Duration,
}

impl Default for JuicityLiveEkmAuthOptions {
    fn default() -> Self {
        Self {
            server_name: DEFAULT_H3_SERVER_NAME.to_owned(),
            target: DEFAULT_LIVE_EKM_AUTH_TARGET.to_owned(),
            password: DEFAULT_LIVE_EKM_AUTH_PASSWORD.as_bytes().to_vec(),
            iterations: 1,
            timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct JuicityLiveEkmAuthReport {
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
    pub ns_per_juicity_live_ekm_auth_stream_exchange: f64,
    pub ekm_label_len: usize,
    pub ekm_context_len: usize,
    pub ekm_token_len: usize,
    pub client_ekm_token_nonzero: bool,
    pub server_ekm_token_exported: bool,
    pub authenticate_header_len: usize,
    pub dialauth_record_len: usize,
    pub transcript_len: usize,
    pub open_uni_stream_count: usize,
    pub uni_stream_finish_count: usize,
    pub uni_stream_acked_count: usize,
    pub server_received_count: usize,
    pub server_received_len: usize,
    pub server_transcript_match_count: usize,
    pub quic_handshake_validated: bool,
    pub live_ekm_auth_stream_validated: bool,
    pub juicity_auth_token_live_ekm_admitted: bool,
    pub juicity_live_ekm_auth_header_admitted: bool,
    pub juicity_live_ekm_auth_stream_transcript_admitted: bool,
    pub juicity_dialauth_over_h3_admitted: bool,
    pub juicity_transport_packet_conn_dataplane_admitted: bool,
    pub juicity_stream_packet_conn_dataplane_admitted: bool,
    pub juicity_true_quic_h3_dataplane_admitted: bool,
}

pub fn run_live_ekm_auth_smoke(
    options: &JuicityLiveEkmAuthOptions,
) -> Result<JuicityLiveEkmAuthReport, OutboundError> {
    if options.iterations == 0 {
        return Err(OutboundError::BadJuicity(
            "Juicity live ekm auth iterations must be greater than zero".to_owned(),
        ));
    }
    if options.password.is_empty() {
        return Err(OutboundError::BadJuicity(
            "Juicity live ekm auth password cannot be empty".to_owned(),
        ));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| bad_live_ekm_auth(format!("build tokio runtime: {err}")))?;
    runtime.block_on(async {
        tokio::time::timeout(options.timeout, run_live_ekm_auth_smoke_async(options))
            .await
            .map_err(|_| bad_live_ekm_auth("Juicity live ekm auth timed out"))?
    })
}

async fn run_live_ekm_auth_smoke_async(
    options: &JuicityLiveEkmAuthOptions,
) -> Result<JuicityLiveEkmAuthReport, OutboundError> {
    let seed_header = build_deterministic_authenticate_header();
    let uuid = seed_header.uuid;
    let dialauth = build_dialauth_record_for_port_zero(&options.target)?;

    let server_endpoint = quinn::Endpoint::server(
        build_live_server_config(&options.server_name)?,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .map_err(|err| bad_live_ekm_auth(format!("create server endpoint: {err}")))?;
    let loopback_addr = server_endpoint
        .local_addr()
        .map_err(|err| bad_live_ekm_auth(format!("server local addr: {err}")))?;
    let server_iterations = options.iterations;
    let server_target = options.target.clone();
    let server_password = options.password.clone();
    let server_task = tokio::spawn(async move {
        run_live_ekm_auth_server(
            server_endpoint,
            uuid,
            server_password,
            server_target,
            server_iterations,
        )
        .await
    });

    let mut client_endpoint =
        quinn::Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .map_err(|err| bad_live_ekm_auth(format!("create client endpoint: {err}")))?;
    client_endpoint.set_default_client_config(build_live_client_config()?);
    let client_connection = client_endpoint
        .connect(loopback_addr, &options.server_name)
        .map_err(|err| bad_live_ekm_auth(format!("connect live ekm auth loopback: {err}")))?
        .await
        .map_err(|err| bad_live_ekm_auth(format!("await live ekm auth loopback connect: {err}")))?;
    let client_selected_alpn = selected_alpn(&client_connection);
    let client_token = export_juicity_auth_token(&client_connection, &uuid, &options.password)?;
    let client_ekm_token_nonzero = client_token.iter().any(|byte| *byte != 0);
    let header = build_authenticate_header(uuid, client_token, "quic-tls-export-keying-material");
    let transcript = build_auth_stream_transcript(&header, &dialauth);

    let start = Instant::now();
    let mut open_uni_stream_count = 0_usize;
    let mut uni_stream_finish_count = 0_usize;
    let mut uni_stream_acked_count = 0_usize;
    for _ in 0..options.iterations {
        let mut stream = client_connection
            .open_uni()
            .await
            .map_err(|err| bad_live_ekm_auth(format!("open live ekm auth uni stream: {err}")))?;
        open_uni_stream_count += 1;
        stream
            .write_all(&transcript.transcript)
            .await
            .map_err(|err| bad_live_ekm_auth(format!("write live ekm auth uni stream: {err}")))?;
        stream
            .finish()
            .map_err(|err| bad_live_ekm_auth(format!("finish live ekm auth uni stream: {err}")))?;
        uni_stream_finish_count += 1;
        if stream
            .stopped()
            .await
            .map_err(|err| bad_live_ekm_auth(format!("wait live ekm auth uni stream ack: {err}")))?
            .is_none()
        {
            uni_stream_acked_count += 1;
        }
    }
    let elapsed_ns = start.elapsed().as_nanos();
    client_connection.close(0_u32.into(), b"juicity-ekm-auth done");
    client_endpoint.wait_idle().await;

    let server = server_task
        .await
        .map_err(|err| bad_live_ekm_auth(format!("join live ekm auth server task: {err}")))??;
    let quic_handshake_validated =
        client_selected_alpn == DEFAULT_H3_ALPN && server.selected_alpn == DEFAULT_H3_ALPN;
    let live_ekm_auth_stream_validated = quic_handshake_validated
        && client_ekm_token_nonzero
        && server.ekm_token_exported
        && open_uni_stream_count == options.iterations
        && uni_stream_finish_count == options.iterations
        && server.received_count == options.iterations
        && server.transcript_match_count == options.iterations;

    Ok(JuicityLiveEkmAuthReport {
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
        ns_per_juicity_live_ekm_auth_stream_exchange: elapsed_ns as f64 / options.iterations as f64,
        ekm_label_len: uuid.len(),
        ekm_context_len: options.password.len(),
        ekm_token_len: client_token.len(),
        client_ekm_token_nonzero,
        server_ekm_token_exported: server.ekm_token_exported,
        authenticate_header_len: header.encoded.len(),
        dialauth_record_len: dialauth.packed.len(),
        transcript_len: transcript.transcript_len,
        open_uni_stream_count,
        uni_stream_finish_count,
        uni_stream_acked_count,
        server_received_count: server.received_count,
        server_received_len: server.last_received_len,
        server_transcript_match_count: server.transcript_match_count,
        quic_handshake_validated,
        live_ekm_auth_stream_validated,
        juicity_auth_token_live_ekm_admitted: live_ekm_auth_stream_validated,
        juicity_live_ekm_auth_header_admitted: live_ekm_auth_stream_validated,
        juicity_live_ekm_auth_stream_transcript_admitted: live_ekm_auth_stream_validated,
        juicity_dialauth_over_h3_admitted: false,
        juicity_transport_packet_conn_dataplane_admitted: false,
        juicity_stream_packet_conn_dataplane_admitted: false,
        juicity_true_quic_h3_dataplane_admitted: false,
    })
}

#[derive(Debug)]
struct LiveEkmAuthServerReport {
    selected_alpn: String,
    ekm_token_exported: bool,
    received_count: usize,
    last_received_len: usize,
    transcript_match_count: usize,
}

async fn run_live_ekm_auth_server(
    endpoint: quinn::Endpoint,
    uuid: [u8; 16],
    password: Vec<u8>,
    target: String,
    iterations: usize,
) -> Result<LiveEkmAuthServerReport, OutboundError> {
    let connection = endpoint
        .accept()
        .await
        .ok_or_else(|| bad_live_ekm_auth("server accept returned none"))?
        .await
        .map_err(|err| bad_live_ekm_auth(format!("server accept live ekm auth: {err}")))?;
    let selected_alpn = selected_alpn(&connection);
    let server_token = export_juicity_auth_token(&connection, &uuid, &password)?;
    let header = build_authenticate_header(uuid, server_token, "quic-tls-export-keying-material");
    let dialauth = build_dialauth_record_for_port_zero(&target)?;
    let expected = build_auth_stream_transcript(&header, &dialauth).transcript;

    let mut received_count = 0_usize;
    let mut last_received_len = 0_usize;
    let mut transcript_match_count = 0_usize;
    for _ in 0..iterations {
        let mut stream = connection
            .accept_uni()
            .await
            .map_err(|err| bad_live_ekm_auth(format!("accept live ekm auth uni stream: {err}")))?;
        let received = stream
            .read_to_end(expected.len())
            .await
            .map_err(|err| bad_live_ekm_auth(format!("read live ekm auth uni stream: {err}")))?;
        received_count += 1;
        last_received_len = received.len();
        if received == expected {
            transcript_match_count += 1;
        }
    }
    endpoint.wait_idle().await;
    Ok(LiveEkmAuthServerReport {
        selected_alpn,
        ekm_token_exported: true,
        received_count,
        last_received_len,
        transcript_match_count,
    })
}

pub(super) fn export_juicity_auth_token(
    connection: &quinn::Connection,
    uuid: &[u8; 16],
    password: &[u8],
) -> Result<[u8; JUICITY_AUTHENTICATE_TOKEN_LEN], OutboundError> {
    let mut token = [0_u8; JUICITY_AUTHENTICATE_TOKEN_LEN];
    connection
        .export_keying_material(&mut token, uuid, password)
        .map_err(|err| bad_live_ekm_auth(format!("export live ekm auth token: {err:?}")))?;
    Ok(token)
}

fn bad_live_ekm_auth(message: impl Into<String>) -> OutboundError {
    OutboundError::BadJuicity(message.into())
}
