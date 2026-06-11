use std::collections::VecDeque;
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};

use dae_outbound::shadowsocks::{AeadStreamCodec, read_encrypted_chunk_from_async_stream};
use dae_outbound::shared_transport::mux::{
    OPTION_DATA, SESSION_STATUS_END, SESSION_STATUS_KEEP, SESSION_STATUS_KEEPALIVE,
};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

use super::super::client::AsyncResidentTlsClient;
use super::websocket::WebSocketBinaryFrameDecoder;

pub(super) async fn read_shadowsocks_aead_chunk_from_websocket_tls(
    client: &mut AsyncResidentTlsClient,
    state: &mut AsyncWebSocketPayloadState,
    decoder: &mut Option<AeadStreamCodec>,
    cipher: &str,
    password: &str,
    salt_len: usize,
) -> Result<Vec<u8>, String> {
    let mut reader = AsyncWebSocketPayloadReader::new(client, state);
    read_shadowsocks_aead_chunk_from_async_reader(&mut reader, decoder, cipher, password, salt_len)
        .await
}

pub(super) async fn read_shadowsocks_aead_chunk_from_v2ray_plugin_mux(
    client: &mut AsyncResidentTlsClient,
    state: &mut AsyncV2rayPluginMuxPayloadState,
    mux_id: [u8; 2],
    decoder: &mut Option<AeadStreamCodec>,
    cipher: &str,
    password: &str,
    salt_len: usize,
) -> Result<Vec<u8>, String> {
    let mut reader = AsyncV2rayPluginMuxPayloadReader::new(client, state, mux_id);
    read_shadowsocks_aead_chunk_from_async_reader(&mut reader, decoder, cipher, password, salt_len)
        .await
}

async fn read_shadowsocks_aead_chunk_from_async_reader<R>(
    reader: &mut R,
    decoder: &mut Option<AeadStreamCodec>,
    cipher: &str,
    password: &str,
    salt_len: usize,
) -> Result<Vec<u8>, String>
where
    R: AsyncRead + Unpin,
{
    if decoder.is_none() {
        let mut server_salt = vec![0_u8; salt_len];
        reader
            .read_exact(&mut server_salt)
            .await
            .map_err(|err| format!("read Shadowsocks server salt: {err}"))?;
        *decoder = Some(
            AeadStreamCodec::new(cipher, password, &server_salt)
                .map_err(|err| format!("create Shadowsocks response decoder: {err}"))?,
        );
    }
    let decoder = decoder
        .as_mut()
        .ok_or_else(|| "missing Shadowsocks response decoder".to_owned())?;
    read_encrypted_chunk_from_async_stream(reader, decoder)
        .await
        .map_err(|err| format!("read Shadowsocks response chunk: {err}"))
}

#[derive(Default)]
pub(crate) struct AsyncWebSocketPayloadState {
    decoder: WebSocketBinaryFrameDecoder,
    pending: VecDeque<u8>,
}

pub(crate) struct AsyncWebSocketPayloadReader<'a, 'b, R> {
    client: &'a mut R,
    state: &'b mut AsyncWebSocketPayloadState,
}

impl<'a, 'b, R> AsyncWebSocketPayloadReader<'a, 'b, R>
where
    R: AsyncRead + Unpin,
{
    pub(crate) fn new(client: &'a mut R, state: &'b mut AsyncWebSocketPayloadState) -> Self {
        Self { client, state }
    }
}

impl<R> AsyncRead for AsyncWebSocketPayloadReader<'_, '_, R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if drain_async_websocket_payload(self.state, out) || out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            let mut buf = [0_u8; 8192];
            let mut read_buf = ReadBuf::new(&mut buf);
            match Pin::new(&mut *self.client).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let read = read_buf.filled();
                    if read.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    let frames = self
                        .state
                        .decoder
                        .push(read)
                        .map_err(std::io::Error::other)?;
                    for frame in frames {
                        self.state.pending.extend(frame);
                    }
                    if drain_async_websocket_payload(self.state, out) || out.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[derive(Default)]
pub(super) struct AsyncV2rayPluginMuxPayloadState {
    ws_decoder: WebSocketBinaryFrameDecoder,
    mux_bytes: VecDeque<u8>,
    pending_payload: VecDeque<u8>,
    closed: bool,
}

struct AsyncV2rayPluginMuxPayloadReader<'a, 'b> {
    client: &'a mut AsyncResidentTlsClient,
    state: &'b mut AsyncV2rayPluginMuxPayloadState,
    mux_id: [u8; 2],
}

impl<'a, 'b> AsyncV2rayPluginMuxPayloadReader<'a, 'b> {
    fn new(
        client: &'a mut AsyncResidentTlsClient,
        state: &'b mut AsyncV2rayPluginMuxPayloadState,
        mux_id: [u8; 2],
    ) -> Self {
        Self {
            client,
            state,
            mux_id,
        }
    }
}

impl AsyncRead for AsyncV2rayPluginMuxPayloadReader<'_, '_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if drain_v2ray_plugin_mux_payload(self.state, out)? || out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.state.closed {
            return Poll::Ready(Ok(()));
        }

        loop {
            let mux_id = self.mux_id;
            if parse_pending_v2ray_plugin_mux_frames(self.state, mux_id)? {
                if drain_v2ray_plugin_mux_payload(self.state, out)? || out.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
            }
            if self.state.closed {
                return Poll::Ready(Ok(()));
            }

            let mut buf = [0_u8; 8192];
            let mut read_buf = ReadBuf::new(&mut buf);
            match Pin::new(&mut *self.client).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let read = read_buf.filled();
                    if read.is_empty() {
                        self.state.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    let frames = self
                        .state
                        .ws_decoder
                        .push(read)
                        .map_err(std::io::Error::other)?;
                    for frame in frames {
                        self.state.mux_bytes.extend(frame);
                    }
                    continue;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn drain_async_websocket_payload(
    state: &mut AsyncWebSocketPayloadState,
    out: &mut ReadBuf<'_>,
) -> bool {
    let mut copied = false;
    while out.remaining() > 0 {
        let Some(byte) = state.pending.pop_front() else {
            break;
        };
        out.put_slice(&[byte]);
        copied = true;
    }
    copied
}

fn drain_v2ray_plugin_mux_payload(
    state: &mut AsyncV2rayPluginMuxPayloadState,
    out: &mut ReadBuf<'_>,
) -> std::io::Result<bool> {
    let mut copied = false;
    while out.remaining() > 0 {
        let Some(byte) = state.pending_payload.pop_front() else {
            break;
        };
        out.put_slice(&[byte]);
        copied = true;
    }
    Ok(copied)
}

fn parse_pending_v2ray_plugin_mux_frames(
    state: &mut AsyncV2rayPluginMuxPayloadState,
    mux_id: [u8; 2],
) -> std::io::Result<bool> {
    let mut progressed = false;
    loop {
        if state.mux_bytes.len() < 2 {
            break;
        }
        let metadata_len = u16::from_be_bytes([state.mux_bytes[0], state.mux_bytes[1]]) as usize;
        if !(4..=512).contains(&metadata_len) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "invalid v2ray-plugin mux metadata length",
            ));
        }
        if state.mux_bytes.len() < 2 + metadata_len {
            break;
        }

        let status = state.mux_bytes[4];
        let option = state.mux_bytes[5];
        let payload_len = if option == OPTION_DATA {
            if state.mux_bytes.len() < 2 + metadata_len + 2 {
                break;
            }
            u16::from_be_bytes([
                state.mux_bytes[2 + metadata_len],
                state.mux_bytes[2 + metadata_len + 1],
            ]) as usize
        } else {
            0
        };
        let total_len = 2
            + metadata_len
            + if option == OPTION_DATA {
                2 + payload_len
            } else {
                0
            };
        if state.mux_bytes.len() < total_len {
            break;
        }

        let mut frame = Vec::with_capacity(total_len);
        for _ in 0..total_len {
            frame.push(
                state
                    .mux_bytes
                    .pop_front()
                    .expect("mux frame length checked"),
            );
        }

        let metadata = &frame[2..2 + metadata_len];
        let frame_id = [metadata[0], metadata[1]];
        if frame_id != mux_id {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "v2ray-plugin mux frame id mismatch",
            ));
        }
        if status == SESSION_STATUS_KEEPALIVE {
            progressed = true;
            continue;
        }
        if status == SESSION_STATUS_END {
            state.closed = true;
            progressed = true;
            break;
        }
        if status != SESSION_STATUS_KEEP || option != OPTION_DATA {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "v2ray-plugin mux frame status/option mismatch",
            ));
        }
        let payload_start = 2 + metadata_len + 2;
        state.pending_payload.extend(
            frame[payload_start..payload_start + payload_len]
                .iter()
                .copied(),
        );
        progressed = true;
    }
    Ok(progressed)
}
