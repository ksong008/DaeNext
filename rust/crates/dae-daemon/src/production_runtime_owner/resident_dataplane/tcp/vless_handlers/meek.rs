use super::*;
pub(crate) fn meek_options_from_proxy(
    selection: &TcpProxySelection,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
) -> MeekRoundTripOptions {
    MeekRoundTripOptions {
        url: format!(
            "https://{}{}",
            selection.proxy.stream_host, selection.proxy.stream_path
        ),
        host: selection.proxy.stream_host.clone(),
        path: selection.proxy.stream_path.clone(),
        session_tag: format!("{}|{}|{}", selection.proxy.graph_id, peer, original_dst).into_bytes(),
    }
}

pub(crate) async fn meek_round_trip_async(
    proxy: &ResidentProxyPlan,
    options: &MeekRoundTripOptions,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let mut client = open_async_resident_tls_client(proxy).await?;
    let request = meek_http_request(options, body);
    client
        .write_plain_all(&request, "write Meek polling request")
        .await?;
    let response = read_meek_http_response_body_async(&mut client).await;
    client.shutdown().await;
    response
}

pub(crate) async fn read_meek_http_response_body_async(
    client: &mut AsyncResidentTlsClient,
) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    let mut buf = [0_u8; 1024];
    let head_end = loop {
        let read = time::timeout(RESIDENT_CONNECT_TIMEOUT, client.read_plain(&mut buf))
            .await
            .map_err(|_| "read Meek response head timeout".to_owned())?
            .map_err(|err| format!("read Meek response head: {err}"))?;
        if read == 0 {
            return Err("Meek response closed before header".to_owned());
        }
        data.extend_from_slice(&buf[..read]);
        if let Some(index) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        if data.len() > 8192 {
            return Err("Meek response header too large".to_owned());
        }
    };
    let head = data[..head_end].to_vec();
    validate_http_status(&head, 200).map_err(|err| format!("validate Meek response: {err}"))?;
    let content_length = http_content_length(&head)?;
    let mut body = data[head_end..].to_vec();
    while body.len() < content_length {
        let read = time::timeout(RESIDENT_CONNECT_TIMEOUT, client.read_plain(&mut buf))
            .await
            .map_err(|_| "read Meek response body timeout".to_owned())?
            .map_err(|err| format!("read Meek response body: {err}"))?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&buf[..read]);
    }
    body.truncate(content_length);
    Ok(body)
}
