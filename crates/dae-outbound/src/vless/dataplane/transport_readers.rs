use super::*;
pub fn read_tcp_request_from_websocket_stream<S>(
    stream: &mut S,
    payload_len: usize,
) -> Result<VlessWebSocketRequest, OutboundError>
where
    S: Read,
{
    let payload = read_websocket_binary_frame(stream)?;
    let websocket_request_frame_len = payload.len();
    let mut cursor = Cursor::new(payload);
    let request = read_tcp_request_from_stream(&mut cursor, payload_len)?;
    if cursor.position() as usize != websocket_request_frame_len {
        return Err(OutboundError::BadVless(format!(
            "VLESS WebSocket request has trailing bytes: {}",
            websocket_request_frame_len - cursor.position() as usize
        )));
    }
    Ok(VlessWebSocketRequest {
        request,
        websocket_request_frame_len,
    })
}

pub fn read_tcp_request_from_grpc_hunk_stream<S>(
    stream: &mut S,
    payload_len: usize,
) -> Result<VlessGrpcHunkRequest, OutboundError>
where
    S: Read,
{
    let payload = read_grpc_hunk_frame(stream)?;
    let grpc_request_hunk_len = grpc_hunk_frame_len(&payload)?;
    let mut cursor = Cursor::new(&payload);
    let request = read_tcp_request_from_stream(&mut cursor, payload_len)?;
    if cursor.position() as usize != payload.len() {
        return Err(OutboundError::BadVless(format!(
            "VLESS gRPC hunk request has trailing bytes: {}",
            payload.len() - cursor.position() as usize
        )));
    }
    Ok(VlessGrpcHunkRequest {
        request,
        grpc_request_hunk_len,
    })
}

pub fn read_tcp_request_from_meek_polling_stream<S>(
    stream: &mut S,
    payload_len: usize,
    meek_options: &MeekRoundTripOptions,
) -> Result<VlessMeekPollingRequest, OutboundError>
where
    S: Read,
{
    let (request_head, payload) = read_http_message(stream, "meek request")?;
    validate_meek_request_head(&request_head, meek_options)?;
    let mut cursor = Cursor::new(&payload);
    let request = read_tcp_request_from_stream(&mut cursor, payload_len)?;
    if cursor.position() as usize != payload.len() {
        return Err(OutboundError::BadVless(format!(
            "VLESS Meek polling request has trailing bytes: {}",
            payload.len() - cursor.position() as usize
        )));
    }
    Ok(VlessMeekPollingRequest {
        request,
        meek_request_body_len: payload.len(),
        meek_session_id_validated: true,
    })
}

pub fn read_http_transport_request_head_from_stream<S>(
    stream: &mut S,
    http_options: &HttpConnectOptions,
) -> Result<VlessHttpTransportRequestHead, OutboundError>
where
    S: Read,
{
    if !http_options.transport.enabled {
        return Err(OutboundError::BadVless(
            "VLESS HTTP transport request requires transport.enabled=true".to_owned(),
        ));
    }
    let request_head = read_http_head(stream)?;
    validate_http_transport_request_head(&request_head, http_options)
}

pub fn read_tcp_request_from_xhttp_packet_stream<S>(
    stream: &mut S,
    payload_len: usize,
    xhttp_options: &XHttpLifecycleOptions,
) -> Result<VlessXHttpPacketRequest, OutboundError>
where
    S: Read,
{
    let (request_head, payload) = read_http_message(stream, "xhttp request")?;
    let request_path =
        validate_xhttp_packet_request_head(&request_head, payload.len(), xhttp_options)?;
    let mut cursor = Cursor::new(&payload);
    let request = read_tcp_request_from_stream(&mut cursor, payload_len)?;
    if cursor.position() as usize != payload.len() {
        return Err(OutboundError::BadVless(format!(
            "VLESS xHTTP packet request has trailing bytes: {}",
            payload.len() - cursor.position() as usize
        )));
    }
    Ok(VlessXHttpPacketRequest {
        request,
        xhttp_request_body_len: payload.len(),
        xhttp_request_path: request_path,
        xhttp_packet_up_validated: true,
    })
}
