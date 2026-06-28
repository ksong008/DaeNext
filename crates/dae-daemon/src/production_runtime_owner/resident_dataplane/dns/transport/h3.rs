use super::super::*;
use super::quic::{append_dns_proxy_udp_bridge_error, connect_dns_quic_endpoint_async};
use super::route::{
    dns_upstream_targets_failed, resolved_upstream_targets, select_dns_upstream_target,
};
use super::wire::{doh_request_target, restore_dns_response_id};

pub(super) async fn forward_dns_h3_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
) -> Result<Vec<u8>, String> {
    let mut failures = Vec::new();
    for remote in resolved_upstream_targets(upstream).await? {
        match select_dns_upstream_target(plan, upstream, remote, L4Proto::Udp) {
            Ok(ResidentDnsUpstreamSelection::Direct { mark }) => {
                match forward_dns_h3_to_target_async(upstream, remote, payload, mark).await {
                    Ok(response) => return Ok(response),
                    Err(err) => failures.push(format!("{remote}: {err}")),
                }
            }
            Ok(ResidentDnsUpstreamSelection::Proxy { proxy }) => {
                match forward_dns_h3_to_proxy_async(upstream, remote, payload, proxy).await {
                    Ok(response) => return Ok(response),
                    Err(err) => failures.push(format!("{remote}: {err}")),
                }
            }
            Err(err) => failures.push(format!("{remote}: {err}")),
        }
    }
    Err(dns_upstream_targets_failed(
        upstream,
        "forward DNS H3 to",
        failures,
    ))
}

async fn forward_dns_h3_to_target_async(
    upstream: &ResidentDnsUpstream,
    remote: SocketAddr,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let (endpoint, connection) = connect_dns_quic_endpoint_async(
        upstream,
        remote,
        mark,
        DNS_DOH3_ALPN,
        "connect DoH3 endpoint",
        "DNS H3 handshake timeout",
        "connect DNS H3 upstream",
    )
    .await?;
    forward_dns_h3_over_connection_async(upstream, payload, endpoint, connection).await
}

async fn forward_dns_h3_to_proxy_async(
    upstream: &ResidentDnsUpstream,
    remote: SocketAddr,
    payload: &[u8],
    proxy: Arc<ResidentProxyPlan>,
) -> Result<Vec<u8>, String> {
    let bridge = open_resident_proxy_udp_bridge_async(Arc::clone(&proxy), remote).await?;
    let (endpoint, connection) = match connect_dns_quic_endpoint_async(
        upstream,
        bridge.local_addr(),
        proxy.mark,
        DNS_DOH3_ALPN,
        "connect DoH3 endpoint",
        "DNS H3 handshake timeout",
        "connect DNS H3 upstream",
    )
    .await
    {
        Ok(connection) => connection,
        Err(err) => {
            let err = append_dns_proxy_udp_bridge_error(err, &bridge);
            bridge.shutdown().await;
            return Err(format!("connect DNS H3 via proxied UDP {remote}: {err}"));
        }
    };
    let result =
        forward_dns_h3_over_connection_async(upstream, payload, endpoint, connection).await;
    bridge.shutdown().await;
    result
}

async fn forward_dns_h3_over_connection_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
) -> Result<Vec<u8>, String> {
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut driver, mut client) = h3::client::new(h3_connection)
        .await
        .map_err(|err| format!("create DNS H3 client: {err:?}"))?;
    let driver_task = tokio::spawn(async move { poll_fn(|cx| driver.poll_close(cx)).await });

    let response = time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, async {
        let doh = build_doh_request(
            &upstream.target.authority,
            &upstream.target.authority,
            &upstream.path,
            payload,
        )
        .map_err(|err| format!("build DoH3 request: {err}"))?;
        let uri = if let Some(query) = doh.dns_query.as_deref() {
            format!(
                "https://{}{}",
                upstream.target.authority,
                doh_request_target(&upstream.path, Some(query))
            )
        } else {
            format!("https://{}{}", upstream.target.authority, upstream.path)
        };
        let mut builder = Request::builder()
            .method(doh.method.as_str())
            .uri(uri)
            .header(http::header::ACCEPT, DOH_MEDIA_TYPE);
        if !doh.content_type.is_empty() {
            builder = builder.header(http::header::CONTENT_TYPE, doh.content_type.as_str());
        }
        let request = builder
            .body(())
            .map_err(|err| format!("build DoH3 HTTP request: {err}"))?;
        let mut stream = client
            .send_request(request)
            .await
            .map_err(|err| format!("send DoH3 request: {err:?}"))?;
        if !doh.body.is_empty() {
            stream
                .send_data(Bytes::copy_from_slice(&doh.body))
                .await
                .map_err(|err| format!("send DoH3 body: {err:?}"))?;
        }
        stream
            .finish()
            .await
            .map_err(|err| format!("finish DoH3 request: {err:?}"))?;
        let response = stream
            .recv_response()
            .await
            .map_err(|err| format!("recv DoH3 response: {err:?}"))?;
        let content_type = response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .map(|value| value.as_bytes().to_vec())
            .unwrap_or_default();
        let status = response.status();
        let mut body = Vec::new();
        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|err| format!("recv DoH3 response body: {err:?}"))?
        {
            let remaining = chunk.remaining();
            if body.len().saturating_add(remaining) > DNS_DOH_RESPONSE_READ_LIMIT {
                return Err(format!(
                    "DoH3 response exceeds read limit {DNS_DOH_RESPONSE_READ_LIMIT}"
                ));
            }
            body.extend_from_slice(&chunk.copy_to_bytes(remaining));
        }
        validate_doh_response(status.as_u16(), status.as_str(), &content_type)
            .map_err(|err| err.to_string())?;
        restore_dns_response_id(payload, &body)
    })
    .await
    .map_err(|_| "DNS H3 exchange timeout".to_owned())?
    .map_err(|err| {
        format!(
            "forward DNS over HTTP/3 to upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })?;
    drop(client);
    connection.close(0_u32.into(), b"dns-query done");
    endpoint.wait_idle().await;
    let _ = driver_task.await;
    Ok(response)
}
