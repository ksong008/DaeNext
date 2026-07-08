use super::super::*;
use super::plain::dns_transport_route_name;
use super::quic::{append_dns_proxy_udp_bridge_error, connect_dns_quic_endpoint_async};
use super::route::{
    ResidentDnsUpstreamRoutedTarget, dns_upstream_targets_failed, resolved_upstream_targets,
    select_dns_upstream_targets,
};
use super::wire::{doh_request_target, restore_dns_response_id};

pub(super) async fn forward_dns_h3_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
    forwarders: &Arc<ResidentDnsForwarderCache>,
) -> Result<Vec<u8>, String> {
    let (targets, mut failures) = select_dns_upstream_targets(
        plan,
        upstream,
        resolved_upstream_targets(upstream).await?,
        L4Proto::Udp,
    )?;
    for remote in targets {
        match forward_dns_h3_to_routed_target_async(upstream, remote, payload, forwarders).await {
            Ok(response) => return Ok(response),
            Err(err) => failures.push(err),
        }
    }
    Err(dns_upstream_targets_failed(
        upstream,
        "forward DNS H3 to",
        failures,
    ))
}

async fn forward_dns_h3_to_routed_target_async(
    upstream: &ResidentDnsUpstream,
    remote: ResidentDnsUpstreamRoutedTarget,
    payload: &[u8],
    forwarders: &Arc<ResidentDnsForwarderCache>,
) -> Result<Vec<u8>, String> {
    let started_at = std::time::Instant::now();
    let target = remote.target;
    let route = dns_transport_route_name(&remote.selection);
    let result = match &remote.selection {
        ResidentDnsUpstreamSelection::Direct { mark } => {
            let forwarder = forwarders.h3_forwarder(upstream, target, *mark, &remote.selection)?;
            forward_dns_h3_cached(upstream, forwarder, payload)
                .await
                .map_err(|err| format!("{target}: {err}"))
        }
        ResidentDnsUpstreamSelection::Proxy { proxy } => {
            forward_dns_h3_to_proxy_async(upstream, target, payload, Arc::clone(proxy))
                .await
                .map_err(|err| format!("{target}: {err}"))
        }
    };
    record_dns_transport_trace(ResidentDnsTransportTraceInput {
        upstream: upstream.tag.clone(),
        scheme: upstream.scheme.as_str(),
        target,
        l4proto: L4Proto::Udp,
        route,
        started_at,
        error: result.as_ref().err().cloned(),
    });
    result
}

impl ResidentDnsH3Forwarder {
    async fn client(
        &mut self,
    ) -> Result<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>, String> {
        if self.client.is_none() {
            self.open_client().await?;
        }
        self.client
            .as_ref()
            .cloned()
            .ok_or_else(|| "DNS H3 client was not initialized".to_owned())
    }

    async fn open_client(&mut self) -> Result<(), String> {
        let (endpoint, connection) = connect_dns_quic_endpoint_async(
            &self.upstream,
            self.target,
            self.mark,
            DNS_DOH3_ALPN,
            "connect DoH3 endpoint",
            "DNS H3 handshake timeout",
            "connect DNS H3 upstream",
        )
        .await?;
        let h3_connection = h3_quinn::Connection::new(connection.clone());
        let (mut driver, client) = h3::client::new(h3_connection)
            .await
            .map_err(|err| format!("create DNS H3 client: {err:?}"))?;
        let driver_task = tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        });
        self.endpoint = Some(endpoint);
        self.connection = Some(connection);
        self.client = Some(client);
        self.driver_task = Some(driver_task);
        Ok(())
    }

    fn close(&mut self) {
        self.client = None;
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), b"dns-query failed");
        }
        self.endpoint = None;
        if let Some(task) = self.driver_task.take() {
            task.abort();
        }
    }
}

async fn forward_dns_h3_cached(
    upstream: &ResidentDnsUpstream,
    forwarder: Arc<AsyncMutex<ResidentDnsH3Forwarder>>,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut client = {
        let mut forwarder = forwarder.lock().await;
        forwarder.client().await?
    };
    match forward_dns_h3_with_client_async(upstream, payload, &mut client).await {
        Ok(response) => Ok(response),
        Err(first_err) => {
            let mut client = {
                let mut forwarder = forwarder.lock().await;
                forwarder.close();
                forwarder.client().await?
            };
            forward_dns_h3_with_client_async(upstream, payload, &mut client)
                .await
                .map_err(|retry_err| {
                    format!("DNS H3 cached forwarder retry failed after {first_err}: {retry_err}")
                })
        }
    }
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

    let response = forward_dns_h3_with_client_async(upstream, payload, &mut client).await?;
    drop(client);
    connection.close(0_u32.into(), b"dns-query done");
    endpoint.wait_idle().await;
    let _ = driver_task.await;
    Ok(response)
}

async fn forward_dns_h3_with_client_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    client: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
) -> Result<Vec<u8>, String> {
    time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, async {
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
    })
}
