use tokio::io::AsyncWriteExt;

use crate::error::OutboundError;

use super::quic_loopback::export_tuic_auth_token;
use super::tls::{build_tuic_client_config, normalize_alpn};
use super::wire::{build_authenticate_frame, build_connect_frame, parse_uuid};

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

fn bad_runtime(message: impl Into<String>) -> OutboundError {
    OutboundError::BadTuic(message.into())
}
