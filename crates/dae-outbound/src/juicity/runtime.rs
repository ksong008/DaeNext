use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use crate::error::OutboundError;
use crate::shared_transport::QuicCongestionController;
use crate::trojan::{TrojanMetadata, TrojanNetwork};

use super::auth_stream::build_authenticate_header;
use super::contract::{
    RUNTIME_ALPN, RUNTIME_HANDSHAKE_IDLE_TIMEOUT_SECONDS, RUNTIME_KEEPALIVE_SECONDS,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityAuthReport {
    pub auth_stream_written: bool,
    pub auth_token_nonzero: bool,
}

#[derive(Debug)]
pub struct JuicityAuthStream {
    stream: quinn::SendStream,
}

impl JuicityAuthStream {
    pub fn request_finish(&mut self) -> Result<(), OutboundError> {
        self.stream
            .finish()
            .map_err(|err| bad_runtime(format!("finish Juicity auth stream: {err}")))
    }

    pub async fn finish(&mut self) -> Result<(), OutboundError> {
        self.request_finish()
    }
}

pub fn build_juicity_runtime_client_config(
    allow_insecure: bool,
    pinned_certchain_sha256: &str,
) -> Result<quinn::ClientConfig, OutboundError> {
    build_juicity_runtime_client_config_with_session_cache(
        allow_insecure,
        pinned_certchain_sha256,
        None,
    )
}

pub fn build_juicity_runtime_client_config_with_session_cache(
    allow_insecure: bool,
    pinned_certchain_sha256: &str,
    session_cache: Option<crate::shared_transport::boring_quic::BoringQuicSessionCache>,
) -> Result<quinn::ClientConfig, OutboundError> {
    build_juicity_runtime_client_config_with_congestion_and_session_cache(
        allow_insecure,
        pinned_certchain_sha256,
        QuicCongestionController::Bbr,
        session_cache,
    )
}

pub fn build_juicity_runtime_client_config_with_congestion(
    allow_insecure: bool,
    pinned_certchain_sha256: &str,
    congestion: QuicCongestionController,
) -> Result<quinn::ClientConfig, OutboundError> {
    build_juicity_runtime_client_config_with_congestion_and_session_cache(
        allow_insecure,
        pinned_certchain_sha256,
        congestion,
        None,
    )
}

pub fn build_juicity_runtime_client_config_with_congestion_and_session_cache(
    allow_insecure: bool,
    pinned_certchain_sha256: &str,
    congestion: QuicCongestionController,
    session_cache: Option<crate::shared_transport::boring_quic::BoringQuicSessionCache>,
) -> Result<quinn::ClientConfig, OutboundError> {
    let transport = Arc::new(transport_config(congestion)?);
    let mut policy = crate::shared_transport::boring_quic::BoringQuicClientPolicy::new([
        RUNTIME_ALPN.as_bytes(),
    ])?
    .allow_insecure(allow_insecure)
    .zero_rtt(false);
    if !pinned_certchain_sha256.is_empty() {
        policy = policy.pinned_certchain_sha256(pinned_certchain_sha256);
    }
    crate::shared_transport::boring_quic::build_boring_quic_client_config_with_session_cache(
        &policy,
        transport,
        session_cache,
    )
    .map_err(|err| bad_runtime(format!("client BoringSSL QUIC TLS config: {err}")))
}

pub async fn authenticate_juicity_connection(
    connection: &quinn::Connection,
    uuid: &str,
    password: &str,
) -> Result<(JuicityAuthReport, JuicityAuthStream), OutboundError> {
    let uuid = parse_juicity_uuid(uuid)?;
    let token = export_juicity_auth_token(connection, &uuid, password.as_bytes())?;
    let token_nonzero = token.iter().any(|byte| *byte != 0);
    let auth_header = build_authenticate_header(uuid, token, "quic-tls-export-keying-material");
    let mut stream = connection
        .open_uni()
        .await
        .map_err(|err| bad_runtime(format!("open Juicity auth stream: {err}")))?;
    stream
        .write_all(&auth_header.encoded)
        .await
        .map_err(|err| bad_runtime(format!("write Juicity auth stream: {err}")))?;
    stream
        .flush()
        .await
        .map_err(|err| bad_runtime(format!("flush Juicity auth stream: {err}")))?;
    Ok((
        JuicityAuthReport {
            auth_stream_written: true,
            auth_token_nonzero: token_nonzero,
        },
        JuicityAuthStream { stream },
    ))
}

pub async fn write_juicity_tcp_request(
    send: &mut quinn::SendStream,
    target: &str,
    initial_payload: &[u8],
) -> Result<usize, OutboundError> {
    let request = build_juicity_tcp_request(target, initial_payload)?;
    send.write_all(&request)
        .await
        .map_err(|err| bad_runtime(format!("write Juicity TCP request: {err}")))?;
    send.flush()
        .await
        .map_err(|err| bad_runtime(format!("flush Juicity TCP request: {err}")))?;
    Ok(request.len())
}

pub fn build_juicity_tcp_request(
    target: &str,
    initial_payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let metadata = TrojanMetadata::parse("tcp", target)?;
    let metadata = metadata.encode()?;
    let mut request = Vec::with_capacity(1 + metadata.len() + initial_payload.len());
    request.push(TrojanNetwork::Tcp.byte());
    request.extend_from_slice(&metadata);
    request.extend_from_slice(initial_payload);
    Ok(request)
}

fn transport_config(
    congestion: QuicCongestionController,
) -> Result<quinn::TransportConfig, OutboundError> {
    let mut transport = quinn::TransportConfig::default();
    congestion.install(&mut transport);
    transport.keep_alive_interval(Some(Duration::from_secs(RUNTIME_KEEPALIVE_SECONDS)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(RUNTIME_HANDSHAKE_IDLE_TIMEOUT_SECONDS)
            .try_into()
            .map_err(|err| bad_runtime(format!("h3 idle timeout config: {err}")))?,
    ));
    transport.datagram_receive_buffer_size(None);
    transport.datagram_send_buffer_size(0);
    Ok(transport)
}

fn export_juicity_auth_token(
    connection: &quinn::Connection,
    uuid: &[u8; 16],
    password: &[u8],
) -> Result<[u8; super::auth_stream::JUICITY_AUTHENTICATE_TOKEN_LEN], OutboundError> {
    let mut token = [0_u8; super::auth_stream::JUICITY_AUTHENTICATE_TOKEN_LEN];
    connection
        .export_keying_material(&mut token, uuid, password)
        .map_err(|err| bad_runtime(format!("export Juicity auth token: {err:?}")))?;
    Ok(token)
}

fn parse_juicity_uuid(input: &str) -> Result<[u8; 16], OutboundError> {
    let compact = input.replace('-', "");
    if compact.len() != 32 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(bad_runtime(format!("parse UUID: {input}")));
    }
    let mut out = [0_u8; 16];
    for index in 0..16 {
        out[index] = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16)
            .map_err(|err| bad_runtime(format!("parse UUID byte: {err}")))?;
    }
    Ok(out)
}

fn bad_runtime(message: impl Into<String>) -> OutboundError {
    OutboundError::BadJuicity(message.into())
}
