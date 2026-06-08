use super::*;
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
            let Some(capacity) = poll_fn(|cx| send_stream.poll_capacity(cx)).await else {
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

pub(crate) fn pop_grpc_hunk_payload(buffer: &mut Vec<u8>) -> Result<Option<Vec<u8>>, String> {
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
    buffer.drain(..5 + len);
    Ok(Some(payload))
}
