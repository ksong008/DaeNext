use dae_outbound::shared_transport::{
    DEFAULT_WS_KEY, HttpUpgradeOptions, WS_MASK_KEY, http_upgrade_request, validate_http_status,
    websocket_client_binary_frame, websocket_handshake_request,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time;

use super::super::RESIDENT_CONNECT_TIMEOUT;
use super::super::client::AsyncVlessTlsClient;

pub(super) async fn websocket_handshake_over_resident_tls_async(
    client: &mut AsyncVlessTlsClient,
    options: &HttpUpgradeOptions,
) -> Result<(), String> {
    let request = websocket_handshake_request(options, DEFAULT_WS_KEY);
    client
        .write_plain_all(&request, "write websocket handshake")
        .await?;
    let response =
        read_http_head_over_resident_tls_async(client, "read websocket handshake").await?;
    validate_http_status(&response, 101).map_err(|err| format!("validate websocket upgrade: {err}"))
}

pub(super) async fn httpupgrade_handshake_over_resident_tls_async(
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

pub(super) async fn websocket_handshake_over_async_stream<S>(
    stream: &mut S,
    options: &HttpUpgradeOptions,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = websocket_handshake_request(options, DEFAULT_WS_KEY);
    stream
        .write_all(&request)
        .await
        .map_err(|err| format!("write websocket handshake: {err}"))?;
    let response = read_http_head_from_async_stream(stream, "read websocket handshake").await?;
    validate_http_status(&response, 101).map_err(|err| format!("validate websocket upgrade: {err}"))
}

pub(super) async fn httpupgrade_handshake_over_async_stream<S>(
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

pub(super) async fn write_websocket_binary_frame_to_async_stream<S>(
    stream: &mut S,
    payload: &[u8],
    label: &str,
) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    let frame = websocket_client_binary_frame(payload, WS_MASK_KEY)
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

pub(super) async fn write_websocket_binary_frame_over_resident_tls_async(
    client: &mut AsyncVlessTlsClient,
    payload: &[u8],
    label: &str,
) -> Result<(), String> {
    let frame = websocket_client_binary_frame(payload, WS_MASK_KEY)
        .map_err(|err| format!("{label}: {err}"))?;
    client.write_plain_all(&frame, label).await
}

#[derive(Default)]
pub(crate) struct WebSocketBinaryFrameDecoder {
    pending: Vec<u8>,
    closed: bool,
}

impl WebSocketBinaryFrameDecoder {
    pub(crate) fn push(&mut self, input: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        if self.closed {
            return Ok(Vec::new());
        }
        self.pending.extend_from_slice(input);
        let mut frames = Vec::new();
        loop {
            if self.pending.len() < 2 {
                break;
            }
            let fin = self.pending[0] & 0x80 != 0;
            let opcode = self.pending[0] & 0x0f;
            if !fin || !matches!(opcode, 2 | 8) {
                return Err(format!(
                    "unexpected websocket frame: fin={fin} opcode={opcode}"
                ));
            }
            let masked = self.pending[1] & 0x80 != 0;
            let mut len = (self.pending[1] & 0x7f) as usize;
            let mut header_len = 2_usize;
            if len == 126 {
                if self.pending.len() < 4 {
                    break;
                }
                len = u16::from_be_bytes([self.pending[2], self.pending[3]]) as usize;
                header_len = 4;
            } else if len == 127 {
                return Err("websocket 64-bit length unsupported in resident relay".to_owned());
            }
            let mask_key = if masked {
                if self.pending.len() < header_len + 4 {
                    break;
                }
                let key = [
                    self.pending[header_len],
                    self.pending[header_len + 1],
                    self.pending[header_len + 2],
                    self.pending[header_len + 3],
                ];
                header_len += 4;
                Some(key)
            } else {
                None
            };
            if self.pending.len() < header_len + len {
                break;
            }
            let mut payload = self.pending[header_len..header_len + len].to_vec();
            if let Some(mask_key) = mask_key {
                for (index, byte) in payload.iter_mut().enumerate() {
                    *byte ^= mask_key[index % 4];
                }
            }
            self.pending.drain(..header_len + len);
            if opcode == 8 {
                self.closed = true;
                break;
            }
            frames.push(payload);
        }
        Ok(frames)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed
    }
}
