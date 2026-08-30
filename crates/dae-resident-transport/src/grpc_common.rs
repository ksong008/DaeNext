use super::*;

mod open_stream;
pub use self::open_stream::*;

pub fn grpc_authority(proxy: &ResidentProxyPlan) -> String {
    if proxy.stream_host.is_empty() {
        proxy.server_name.clone()
    } else {
        proxy.stream_host.clone()
    }
}

pub fn grpc_request_path(service_name: &str, mode: GrpcMode) -> String {
    dae_outbound_stream::shared_transport::grpc_request_path(service_name, mode)
}

pub fn grpc_h2_request(proxy: &ResidentProxyPlan) -> Result<http::Request<()>, String> {
    let authority = grpc_authority(proxy);
    let uri = format!(
        "https://{}{}",
        authority,
        grpc_request_path(&proxy.stream_path, proxy.grpc_mode)
    );
    http::Request::builder()
        .method(http::Method::POST)
        .version(http::Version::HTTP_2)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, GRPC_CONTENT_TYPE_APPLICATION)
        .header(GRPC_TE_HEADER, GRPC_TE_TRAILERS)
        .header(GRPC_ENCODING_HEADER, GRPC_IDENTITY_ENCODING)
        .header(GRPC_ACCEPT_ENCODING_HEADER, GRPC_IDENTITY_ENCODING)
        .header(http::header::USER_AGENT, "dae-rust-native-resident")
        .body(())
        .map_err(|err| format!("build gRPC HTTP/2 request: {err}"))
}

pub async fn send_grpc_hunk(
    send_stream: &mut h2::SendStream<Bytes>,
    payload: &[u8],
    end_stream: bool,
) -> Result<(), String> {
    send_grpc_data(send_stream, payload, end_stream, GrpcMode::Gun).await
}

pub async fn send_grpc_data(
    send_stream: &mut h2::SendStream<Bytes>,
    payload: &[u8],
    end_stream: bool,
    mode: GrpcMode,
) -> Result<(), String> {
    let hunk = grpc_data_frame(mode, payload)
        .map_err(|err| format!("build Xray gRPC {} frame: {err}", mode.link_value()))?;
    send_h2_data(send_stream, Bytes::from(hunk), end_stream).await
}

#[cfg(test)]
pub const GRPC_HUNK_IN_PLACE_PREFIX_BYTES: usize = 16;

#[cfg(test)]
pub fn grpc_hunk_from_prefixed_payload(
    mut buffer: Vec<u8>,
    payload_start: usize,
) -> Result<Bytes, String> {
    if payload_start > buffer.len() {
        return Err("gRPC payload start exceeds owned buffer".to_owned());
    }
    let payload_len = buffer.len() - payload_start;
    let mut encoded_len = [0_u8; 10];
    let encoded_len_bytes = encode_grpc_varint(payload_len as u64, &mut encoded_len);
    let message_header_len = 1 + encoded_len_bytes;
    let message_start = payload_start
        .checked_sub(message_header_len)
        .ok_or_else(|| "gRPC owned buffer has no protobuf prefix room".to_owned())?;
    let message_len = message_header_len
        .checked_add(payload_len)
        .ok_or_else(|| "gRPC message length overflow".to_owned())?;
    let message_len = u32::try_from(message_len)
        .map_err(|_| "gRPC message length exceeds the HTTP/2 frame contract".to_owned())?;
    let frame_start = message_start
        .checked_sub(5)
        .ok_or_else(|| "gRPC owned buffer has no frame prefix room".to_owned())?;

    buffer[message_start] = 0x0a;
    buffer[message_start + 1..message_start + message_header_len]
        .copy_from_slice(&encoded_len[..encoded_len_bytes]);
    buffer[frame_start] = 0;
    buffer[frame_start + 1..frame_start + 5].copy_from_slice(&message_len.to_be_bytes());
    let end = buffer.len();
    Ok(Bytes::from(buffer).slice(frame_start..end))
}

#[cfg(test)]
fn encode_grpc_varint(mut value: u64, output: &mut [u8; 10]) -> usize {
    let mut written = 0;
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output[written] = byte;
        written += 1;
        if value == 0 {
            return written;
        }
    }
}

pub async fn send_h2_data(
    send_stream: &mut h2::SendStream<Bytes>,
    data: Bytes,
    end_stream: bool,
) -> Result<(), String> {
    send_h2_data_with_context(send_stream, data, end_stream, "gRPC HTTP/2").await
}

pub async fn send_h2_data_with_context(
    send_stream: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
    end_stream: bool,
    context: &str,
) -> Result<(), String> {
    if data.is_empty() {
        return send_stream
            .send_data(data, end_stream)
            .map_err(|err| format!("send {context} data: {err}"));
    }

    while !data.is_empty() {
        while send_stream.capacity() == 0 {
            send_stream.reserve_capacity(data.len());
            let Some(capacity) = time::timeout(
                RESIDENT_CONNECT_TIMEOUT,
                poll_fn(|cx| send_stream.poll_capacity(cx)),
            )
            .await
            .map_err(|_| format!("{context} send capacity wait timeout"))?
            else {
                return Err(format!(
                    "{context} send stream closed before capacity became available"
                ));
            };
            capacity.map_err(|err| format!("reserve {context} send capacity: {err}"))?;
        }

        let chunk_len = send_stream.capacity().min(data.len());
        let chunk = data.split_to(chunk_len);
        let chunk_ends_stream = end_stream && data.is_empty();
        send_stream
            .send_data(chunk, chunk_ends_stream)
            .map_err(|err| format!("send {context} data: {err}"))?;
    }

    Ok(())
}

pub struct GrpcHunkReadBuffer {
    bytes: Vec<u8>,
    offset: usize,
    mode: GrpcMode,
    decoded: Vec<u8>,
    pending: VecDeque<Vec<u8>>,
}

impl Default for GrpcHunkReadBuffer {
    fn default() -> Self {
        Self::with_mode(GrpcMode::Gun)
    }
}

impl GrpcHunkReadBuffer {
    pub fn with_mode(mode: GrpcMode) -> Self {
        Self {
            bytes: Vec::new(),
            offset: 0,
            mode,
            decoded: Vec::new(),
            pending: VecDeque::new(),
        }
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.compact_if_worthwhile();
        self.bytes.extend_from_slice(data);
    }

    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty() && self.pending.is_empty()
    }

    pub fn pop_payload(&mut self) -> Result<Option<Vec<u8>>, String> {
        self.next_payload()
            .map(|payload| payload.map(<[u8]>::to_vec))
    }

    pub fn next_payload(&mut self) -> Result<Option<&[u8]>, String> {
        if let Some(payload) = self.pending.pop_front() {
            self.decoded = payload;
            return Ok(Some(&self.decoded));
        }
        let Some((message_start, message_len, consumed)) = (|| {
            let buffer = self.as_slice();
            if buffer.len() < 5 {
                return Ok(None);
            }
            if buffer[0] != 0 {
                return Err("compressed gRPC hunk is not admitted by resident relay".to_owned());
            }
            let len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
            if len > RESIDENT_WEBSOCKET_MAX_MESSAGE_BYTES {
                return Err(format!(
                    "gRPC hunk exceeds {} bytes",
                    RESIDENT_WEBSOCKET_MAX_MESSAGE_BYTES
                ));
            }
            if buffer.len() < 5 + len {
                return Ok(None);
            }
            Ok(Some((self.offset + 5, len, 5 + len)))
        })()?
        else {
            return Ok(None);
        };
        let message = &self.bytes[message_start..message_start + message_len];
        self.decoded.clear();
        match self.mode {
            GrpcMode::Gun => self.decoded.extend_from_slice(
                grpc_hunk_payload_ref(message)
                    .map_err(|err| format!("decode gRPC Hunk protobuf payload: {err}"))?,
            ),
            GrpcMode::Multi => {
                for payload in grpc_multi_hunk_payloads(message)
                    .map_err(|err| format!("decode gRPC MultiHunk protobuf payloads: {err}"))?
                {
                    self.pending.push_back(payload.to_vec());
                }
            }
        }
        self.offset += consumed;
        if self.mode == GrpcMode::Multi {
            self.decoded = self.pending.pop_front().unwrap_or_default();
        }
        Ok(Some(&self.decoded))
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[self.offset..]
    }

    fn compact_if_worthwhile(&mut self) {
        if self.offset == 0 {
            return;
        }
        if self.offset >= self.bytes.len() {
            self.bytes.clear();
            self.offset = 0;
            return;
        }
        if self.offset >= 8192 && self.offset * 2 >= self.bytes.len() {
            self.bytes.drain(..self.offset);
            self.offset = 0;
        }
    }
}

#[cfg(test)]
mod tests;
