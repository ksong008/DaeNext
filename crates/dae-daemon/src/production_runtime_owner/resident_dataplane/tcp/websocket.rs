use dae_outbound::shared_transport::{
    HttpUpgradeOptions, http_upgrade_request, validate_http_status,
    validate_websocket_handshake_response, websocket_client_binary_frame_with_random_mask,
    websocket_client_handshake, websocket_client_mask_key,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time;

use super::super::RESIDENT_CONNECT_TIMEOUT;
use super::super::client::AsyncVlessTlsClient;
use super::SpawnedLogicalStream;

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

pub(crate) const RESIDENT_WEBSOCKET_RELAY_BUFFER_SIZE: usize = 16 * 1024;

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
        .map_err(|err| format!("{label}: {err}"))?;
    stream
        .flush()
        .await
        .map_err(|err| format!("flush {label}: {err}"))
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn write_websocket_binary_frame_in_place_to_async_stream<
    S,
>(
    stream: &mut S,
    payload: &mut [u8],
    label: &str,
) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    let mask = websocket_client_mask_key().map_err(|err| format!("{label}: {err}"))?;
    let (header, header_len) =
        websocket_binary_header(payload.len(), mask).map_err(|err| format!("{label}: {err}"))?;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % mask.len()];
    }
    super::write_all_vectored_header_payload(stream, &header[..header_len], payload)
        .await
        .map_err(|err| format!("{label}: {err}"))?;
    stream
        .flush()
        .await
        .map_err(|err| format!("flush {label}: {err}"))
}

fn websocket_binary_header(payload_len: usize, mask: [u8; 4]) -> Result<([u8; 8], usize), String> {
    let mut header = [0_u8; 8];
    header[0] = 0x82;
    let header_len = if payload_len < 126 {
        header[1] = 0x80 | payload_len as u8;
        header[2..6].copy_from_slice(&mask);
        6
    } else if payload_len <= u16::MAX as usize {
        header[1] = 0x80 | 126;
        header[2..4].copy_from_slice(&(payload_len as u16).to_be_bytes());
        header[4..8].copy_from_slice(&mask);
        8
    } else {
        return Err(format!(
            "resident websocket upload frame exceeds {} bytes",
            u16::MAX
        ));
    };
    Ok((header, header_len))
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

/// Exposes decoded WebSocket binary payload bytes as a bounded logical stream.
/// VLESS Encryption wraps this stream, so HTTP/WebSocket framing stays outside
/// the encrypted VLESS record layer exactly as it does in Xray.
pub(crate) fn spawn_websocket_payload_stream(client: AsyncVlessTlsClient) -> SpawnedLogicalStream {
    SpawnedLogicalStream::spawn(move |logical| drive_websocket_payload_stream(logical, client))
}

async fn drive_websocket_payload_stream(
    logical: tokio::io::DuplexStream,
    client: AsyncVlessTlsClient,
) -> Result<(), String> {
    let (mut logical_read, mut logical_write) = tokio::io::split(logical);
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (control_tx, mut control_rx) = websocket_control_channel();
    let upload = async {
        let mut buffer = [0_u8; RESIDENT_WEBSOCKET_RELAY_BUFFER_SIZE];
        loop {
            tokio::select! {
                biased;
                control = control_rx.recv() => {
                    let Some(control) = control else {
                        return Ok(());
                    };
                    write_websocket_control_response(
                        &mut client_write,
                        control,
                        "VLESS Encryption websocket",
                    ).await?;
                }
                read = logical_read.read(&mut buffer) => {
                    let read = read.map_err(|error| {
                        format!("read VLESS Encryption websocket logical stream: {error}")
                    })?;
                    if read == 0 {
                        return Ok(());
                    }
                    write_websocket_binary_frame_in_place_to_async_stream(
                        &mut client_write,
                        &mut buffer[..read],
                        "write VLESS Encryption websocket frame",
                    ).await?;
                }
            }
        }
    };
    let download = async {
        let mut decoder = WebSocketBinaryFrameDecoder::default();
        let mut buffer = [0_u8; RESIDENT_WEBSOCKET_RELAY_BUFFER_SIZE];
        loop {
            let read = client_read
                .read(&mut buffer)
                .await
                .map_err(|error| format!("read VLESS Encryption websocket frame: {error}"))?;
            if read == 0 {
                logical_write
                    .shutdown()
                    .await
                    .map_err(|error| format!("shutdown websocket logical stream: {error}"))?;
                return Ok(());
            }
            decoder
                .extend(&buffer[..read])
                .map_err(|error| format!("decode VLESS Encryption websocket frame: {error}"))?;
            while let Some(payload) = decoder
                .next_message()
                .map_err(|error| format!("decode VLESS Encryption websocket frame: {error}"))?
            {
                if !payload.is_empty() {
                    logical_write.write_all(payload).await.map_err(|error| {
                        format!("write VLESS Encryption websocket logical stream: {error}")
                    })?;
                    logical_write.flush().await.map_err(|error| {
                        format!("flush VLESS Encryption websocket logical stream: {error}")
                    })?;
                }
            }
            queue_websocket_control_responses(
                &mut decoder,
                &control_tx,
                "VLESS Encryption websocket",
            )
            .await?;
            if decoder.is_closed() {
                logical_write
                    .shutdown()
                    .await
                    .map_err(|error| format!("shutdown websocket logical stream: {error}"))?;
                return Ok(());
            }
        }
    };
    tokio::select! {
        result = upload => result,
        result = download => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_place_websocket_writer_preserves_binary_payload() {
        let original = vec![0x5a; 16 * 1024];
        let mut payload = original.clone();
        let (mut writer, mut reader) = tokio::io::duplex(32 * 1024);

        let write = async {
            write_websocket_binary_frame_in_place_to_async_stream(
                &mut writer,
                &mut payload,
                "test websocket frame",
            )
            .await
            .unwrap();
            writer.shutdown().await.unwrap();
        };
        let read = async {
            let mut wire = Vec::new();
            reader.read_to_end(&mut wire).await.unwrap();
            wire
        };
        let ((), wire) = tokio::join!(write, read);

        let mut decoder = WebSocketBinaryFrameDecoder::default();
        let messages = decoder.push(&wire).unwrap();
        assert_eq!(messages, vec![original]);
    }
}
