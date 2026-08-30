use tokio::io::AsyncWriteExt;

use dae_outbound_core::error::OutboundError;

use super::tls::{
    TuicCongestionController, build_tuic_client_config, build_tuic_client_config_with_congestion,
    build_tuic_client_config_with_session_cache, normalize_alpn,
};
use super::wire::{TUIC_AUTH_TOKEN_LEN, build_authenticate_frame, build_connect_frame, parse_uuid};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TuicAuthReport {
    pub auth_stream_written: bool,
    pub auth_token_nonzero: bool,
}
pub fn build_tuic_runtime_client_config(
    alpn: &[String],
    allow_insecure: bool,
) -> Result<quinn::ClientConfig, OutboundError> {
    build_tuic_client_config(&normalize_alpn(alpn), allow_insecure)
}

pub fn build_tuic_runtime_client_config_with_congestion(
    alpn: &[String],
    allow_insecure: bool,
    congestion: TuicCongestionController,
) -> Result<quinn::ClientConfig, OutboundError> {
    build_tuic_client_config_with_congestion(&normalize_alpn(alpn), allow_insecure, congestion)
}

pub fn build_tuic_runtime_client_config_with_session_cache(
    alpn: &[String],
    allow_insecure: bool,
    congestion: TuicCongestionController,
    session_cache: Option<crate::boring_quic::BoringQuicSessionCache>,
) -> Result<quinn::ClientConfig, OutboundError> {
    build_tuic_client_config_with_session_cache(
        &normalize_alpn(alpn),
        allow_insecure,
        congestion,
        session_cache,
    )
}

pub async fn authenticate_tuic_connection(
    connection: &quinn::Connection,
    uuid: &str,
    password: &str,
) -> Result<TuicAuthReport, OutboundError> {
    let uuid = parse_uuid(uuid)?;
    let token = export_tuic_auth_token(connection, &uuid, password.as_bytes())?;
    let token_nonzero = token.iter().any(|byte| *byte != 0);
    let auth_frame = build_authenticate_frame(uuid, token);
    let mut stream = connection
        .open_uni()
        .await
        .map_err(|err| bad_runtime(format!("open TUIC auth stream: {err}")))?;
    stream
        .write_all(&auth_frame)
        .await
        .map_err(|err| bad_runtime(format!("write TUIC auth stream: {err}")))?;
    stream
        .finish()
        .map_err(|err| bad_runtime(format!("finish TUIC auth stream: {err}")))?;
    Ok(TuicAuthReport {
        auth_stream_written: true,
        auth_token_nonzero: token_nonzero,
    })
}

pub async fn write_tuic_connect_request(
    send: &mut quinn::SendStream,
    target: &str,
) -> Result<(), OutboundError> {
    let connect = build_connect_frame(target)?;
    send.write_all(&connect)
        .await
        .map_err(|err| bad_runtime(format!("write TUIC connect request: {err}")))?;
    send.flush()
        .await
        .map_err(|err| bad_runtime(format!("flush TUIC connect request: {err}")))
}

pub fn export_tuic_auth_token(
    connection: &quinn::Connection,
    uuid: &[u8; 16],
    password: &[u8],
) -> Result<[u8; TUIC_AUTH_TOKEN_LEN], OutboundError> {
    let mut token = [0_u8; TUIC_AUTH_TOKEN_LEN];
    connection
        .export_keying_material(&mut token, uuid, password)
        .map_err(|err| bad_runtime(format!("export TUIC auth token: {err:?}")))?;
    Ok(token)
}

fn bad_runtime(message: impl Into<String>) -> OutboundError {
    OutboundError::BadTuic(message.into())
}
