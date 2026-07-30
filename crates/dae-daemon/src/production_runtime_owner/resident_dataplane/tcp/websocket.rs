use dae_outbound::shared_transport::{
    HttpUpgradeOptions, http_upgrade_request, validate_http_status,
    validate_websocket_handshake_response, websocket_client_binary_frame_with_random_mask,
    websocket_client_handshake,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time;

use super::super::RESIDENT_CONNECT_TIMEOUT;
use super::super::client::AsyncVlessTlsClient;

mod async_payload;
mod duplex_control;
mod framing;
pub(crate) use async_payload::{
    AsyncWebSocketPayloadChannelReader, AsyncWebSocketPayloadChannelState,
    AsyncWebSocketPayloadReader, AsyncWebSocketPayloadState,
};
pub(crate) use duplex_control::*;
pub(crate) use framing::RESIDENT_WEBSOCKET_MAX_MESSAGE_BYTES;
pub(crate) use framing::WebSocketBinaryFrameDecoder;

pub(in crate::production_runtime_owner::resident_dataplane) async fn websocket_handshake_over_resident_tls_async(
    client: &mut AsyncVlessTlsClient,
    options: &HttpUpgradeOptions,
) -> Result<(), String> {
    let handshake = websocket_client_handshake(options)
        .map_err(|err| format!("build websocket handshake: {err}"))?;
    client
        .write_plain_all(&handshake.request, "write websocket handshake")
        .await?;
    let response =
        read_http_head_over_resident_tls_async(client, "read websocket handshake").await?;
    validate_websocket_handshake_response(&response, &handshake.expected_accept)
        .map_err(|err| format!("validate websocket upgrade: {err}"))
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn httpupgrade_handshake_over_resident_tls_async(
    client: &mut AsyncVlessTlsClient,
    options: &HttpUpgradeOptions,
) -> Result<(), String> {
    let request = http_upgrade_request(options);
    client
        .write_plain_all(&request, "write HTTP Upgrade handshake")
        .await?;
    let response =
        read_http_head_over_resident_tls_async(client, "read HTTP Upgrade handshake").await?;
    validate_http_status(&response, 101).map_err(|err| format!("validate HTTP Upgrade: {err}"))
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn websocket_handshake_over_async_stream<
    S,
>(
    stream: &mut S,
    options: &HttpUpgradeOptions,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let handshake = websocket_client_handshake(options)
        .map_err(|err| format!("build websocket handshake: {err}"))?;
    stream
        .write_all(&handshake.request)
        .await
        .map_err(|err| format!("write websocket handshake: {err}"))?;
    let response = read_http_head_from_async_stream(stream, "read websocket handshake").await?;
    validate_websocket_handshake_response(&response, &handshake.expected_accept)
        .map_err(|err| format!("validate websocket upgrade: {err}"))
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn httpupgrade_handshake_over_async_stream<
    S,
>(
    stream: &mut S,
    options: &HttpUpgradeOptions,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = http_upgrade_request(options);
    stream
        .write_all(&request)
        .await
        .map_err(|err| format!("write HTTP Upgrade handshake: {err}"))?;
    let response = read_http_head_from_async_stream(stream, "read HTTP Upgrade handshake").await?;
    validate_http_status(&response, 101).map_err(|err| format!("validate HTTP Upgrade: {err}"))
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn write_websocket_binary_frame_to_async_stream<
    S,
>(
    stream: &mut S,
    payload: &[u8],
    label: &str,
) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    let frame = websocket_client_binary_frame_with_random_mask(payload)
        .map_err(|err| format!("{label}: {err}"))?;
    stream
        .write_all(&frame)
        .await
        .map_err(|err| format!("{label}: {err}"))
}

async fn read_http_head_over_resident_tls_async(
    client: &mut AsyncVlessTlsClient,
    label: &str,
) -> Result<Vec<u8>, String> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 512];
    loop {
        let read = time::timeout(RESIDENT_CONNECT_TIMEOUT, client.read_plain(&mut buf))
            .await
            .map_err(|_| format!("{label}: timeout"))?
            .map_err(|err| format!("{label}: {err}"))?;
        if read == 0 {
            return Err(format!("{label}: early eof"));
        }
        response.extend_from_slice(&buf[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(response);
        }
        if response.len() > 16 * 1024 {
            return Err(format!("{label}: response head too large"));
        }
    }
}

async fn read_http_head_from_async_stream<S>(stream: &mut S, label: &str) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut response = Vec::new();
    let mut buf = [0_u8; 512];
    loop {
        let read = time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.read(&mut buf))
            .await
            .map_err(|_| format!("{label}: timeout"))?
            .map_err(|err| format!("{label}: {err}"))?;
        if read == 0 {
            return Err(format!("{label}: early eof"));
        }
        response.extend_from_slice(&buf[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(response);
        }
        if response.len() > 16 * 1024 {
            return Err(format!("{label}: response head too large"));
        }
    }
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn write_websocket_binary_frame_over_resident_tls_async(
    client: &mut AsyncVlessTlsClient,
    payload: &[u8],
    label: &str,
) -> Result<(), String> {
    let frame = websocket_client_binary_frame_with_random_mask(payload)
        .map_err(|err| format!("{label}: {err}"))?;
    client.write_plain_all(&frame, label).await
}
