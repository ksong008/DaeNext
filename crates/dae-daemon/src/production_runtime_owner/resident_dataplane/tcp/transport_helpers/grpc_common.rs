use super::*;

mod open_stream;
pub(crate) use self::open_stream::*;

pub(crate) fn grpc_authority(proxy: &ResidentProxyPlan) -> String {
    if proxy.stream_host.is_empty() {
        proxy.server_name.clone()
    } else {
        proxy.stream_host.clone()
    }
}

pub(crate) fn grpc_request_path(service_name: &str) -> String {
    let service_name = if service_name.is_empty() {
        "GunService"
    } else {
        service_name.trim_start_matches('/')
    };
    format!("/{service_name}/Tun")
}

pub(crate) fn grpc_h2_request(proxy: &ResidentProxyPlan) -> Result<http::Request<()>, String> {
    let authority = grpc_authority(proxy);
    let uri = format!(
        "https://{}{}",
        authority,
        grpc_request_path(&proxy.stream_path)
    );
    http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, GRPC_CONTENT_TYPE_APPLICATION)
        .header(GRPC_TE_HEADER, GRPC_TE_TRAILERS)
        .header(GRPC_ENCODING_HEADER, GRPC_IDENTITY_ENCODING)
        .header(GRPC_ACCEPT_ENCODING_HEADER, GRPC_IDENTITY_ENCODING)
        .header(http::header::USER_AGENT, "dae-rust-native-resident")
        .body(())
        .map_err(|err| format!("build gRPC HTTP/2 request: {err}"))
}

pub(crate) async fn send_grpc_hunk(
    send_stream: &mut h2::SendStream<Bytes>,
    payload: &[u8],
    end_stream: bool,
) -> Result<(), String> {
    let hunk = grpc_hunk_frame(payload).map_err(|err| format!("build gRPC hunk: {err}"))?;
    send_h2_data(send_stream, Bytes::from(hunk), end_stream).await
}

pub(crate) async fn send_h2_data(
    send_stream: &mut h2::SendStream<Bytes>,
    data: Bytes,
    end_stream: bool,
) -> Result<(), String> {
    send_h2_data_with_context(send_stream, data, end_stream, "gRPC HTTP/2").await
}

pub(crate) async fn send_h2_data_with_context(
    send_stream: &mut h2::SendStream<Bytes>,
    data: Bytes,
    end_stream: bool,
    context: &str,
) -> Result<(), String> {
    let required = data.len();
    if required > 0 {
        send_stream.reserve_capacity(required);
        while send_stream.capacity() < required {
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
    }
    send_stream
        .send_data(data, end_stream)
        .map_err(|err| format!("send {context} data: {err}"))
}

#[derive(Default)]
pub(crate) struct GrpcHunkReadBuffer {
    bytes: Vec<u8>,
    offset: usize,
}

impl GrpcHunkReadBuffer {
    pub(crate) fn extend_from_slice(&mut self, data: &[u8]) {
        self.compact_if_worthwhile();
        self.bytes.extend_from_slice(data);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    pub(crate) fn pop_payload(&mut self) -> Result<Option<Vec<u8>>, String> {
        let buffer = self.as_slice();
        if buffer.len() < 5 {
            return Ok(None);
        }
        if buffer[0] != 0 {
            return Err("compressed gRPC hunk is not admitted by resident relay".to_owned());
        }
        let len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
        if buffer.len() < 5 + len {
            return Ok(None);
        }
        let payload = grpc_hunk_payload(&buffer[5..5 + len])
            .map_err(|err| format!("decode gRPC Hunk protobuf payload: {err}"))?;
        self.consume(5 + len);
        Ok(Some(payload))
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[self.offset..]
    }

    fn consume(&mut self, len: usize) {
        self.offset += len;
        if self.offset >= self.bytes.len() {
            self.bytes.clear();
            self.offset = 0;
        } else {
            self.compact_if_worthwhile();
        }
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
