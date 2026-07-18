use super::super::*;
use super::ResidentDnsTransportError;
use super::plain::dns_transport_route_name;
use super::quic::{
    DnsQuicEndpointConnectContract, configured_dns_quic_endpoint_context,
    connect_dns_quic_endpoint_async,
};
use super::route::{
    ResidentDnsUpstreamRoutedTarget, dns_upstream_targets_failed, resolved_upstream_targets,
    select_dns_upstream_targets,
};
use super::wire::{doh_request_target, restore_dns_response_id};

mod proxied;

use self::proxied::forward_dns_h3_to_proxy_async;

pub(super) async fn forward_dns_h3_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let (targets, mut failures) = select_dns_upstream_targets(
        plan,
        upstream,
        resolved_upstream_targets(upstream)
            .await
            .map_err(ResidentDnsTransportError::message)?,
        L4Proto::Udp,
    )
    .map_err(ResidentDnsTransportError::message)?;
    for remote in targets {
        match forward_dns_h3_to_routed_target_async(upstream, remote, payload, forwarders, context)
            .await
        {
            Ok(response) => return Ok(response),
            Err(error) => {
                if !error.allows_next_candidate() {
                    return Err(error);
                }
                failures.push(error.to_string());
            }
        }
    }
    Err(ResidentDnsTransportError::message(
        dns_upstream_targets_failed(upstream, "forward DNS H3 to", failures),
    ))
}

async fn forward_dns_h3_to_routed_target_async(
    upstream: &ResidentDnsUpstream,
    remote: ResidentDnsUpstreamRoutedTarget,
    payload: &[u8],
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let started_at = std::time::Instant::now();
    let target = remote.target;
    let route = dns_transport_route_name(&remote.selection);
    let result = match &remote.selection {
        ResidentDnsUpstreamSelection::Direct { mark } => {
            let forwarder = forwarders
                .h3_forwarder(upstream, target, *mark, &remote.selection)
                .map_err(ResidentDnsTransportError::message)?;
            forward_dns_h3_cached(upstream, forwarder, payload)
                .await
                .map_err(|err| format!("{target}: {err}"))
                .map_err(ResidentDnsTransportError::message)
        }
        ResidentDnsUpstreamSelection::Proxy { proxy } => forward_dns_h3_to_proxy_async(
            upstream,
            target,
            payload,
            Arc::clone(proxy),
            Arc::clone(&forwarders.metrics),
            forwarders
                .hysteria2_owner_registry()
                .map_err(ResidentDnsTransportError::message)?,
            context,
        )
        .await
        .map_err(|error| ResidentDnsTransportError::proxy(error.with_context(target))),
    };
    record_dns_transport_trace(ResidentDnsTransportTraceInput {
        upstream: upstream.tag.clone(),
        scheme: upstream.scheme.as_str(),
        target,
        l4proto: L4Proto::Udp,
        route,
        started_at,
        error: result.as_ref().err().map(ToString::to_string),
    });
    result
}

impl ResidentDnsH3Forwarder {
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
    let permits = {
        let forwarder = forwarder.lock().await;
        Arc::clone(&forwarder.permits)
    };
    let _permit = acquire_dns_owned_permit(permits, "DNS H3 stream pool").await?;
    let mut client = cached_dns_h3_client(&forwarder).await?;
    match forward_dns_h3_with_client_async(upstream, payload, &mut client).await {
        Ok(response) => Ok(response),
        Err(first_err) => {
            close_cached_dns_h3_client(&forwarder).await;
            let mut client = cached_dns_h3_client(&forwarder).await?;
            forward_dns_h3_with_client_async(upstream, payload, &mut client)
                .await
                .map_err(|retry_err| {
                    format!("DNS H3 cached forwarder retry failed after {first_err}: {retry_err}")
                })
        }
    }
}

async fn cached_dns_h3_client(
    forwarder: &Arc<AsyncMutex<ResidentDnsH3Forwarder>>,
) -> Result<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>, String> {
    {
        let forwarder = forwarder.lock().await;
        if let Some(client) = forwarder.client.as_ref() {
            return Ok(client.clone());
        }
    }
    let open_lock = {
        let forwarder = forwarder.lock().await;
        Arc::clone(&forwarder.open_lock)
    };
    let _open_guard = open_lock.lock().await;
    {
        let forwarder = forwarder.lock().await;
        if let Some(client) = forwarder.client.as_ref() {
            return Ok(client.clone());
        }
    }
    let (upstream, generation, target, mark) = {
        let forwarder = forwarder.lock().await;
        (
            forwarder.upstream.clone(),
            forwarder.generation,
            forwarder.target,
            forwarder.mark,
        )
    };
    let open_context = configured_dns_quic_endpoint_context(
        QuicEndpointProtocol::DnsOverHttp3,
        &upstream,
        generation,
    );
    let connect_contract = DnsQuicEndpointConnectContract::new(
        open_context,
        DNS_DOH3_ALPN,
        "connect DoH3 endpoint",
        "DNS H3 handshake timeout",
        "connect DNS H3 upstream",
    );
    let (endpoint, connection) =
        connect_dns_quic_endpoint_async(&upstream, target, mark, connect_contract).await?;
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let h3_client = match time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        h3::client::new(h3_connection),
    )
    .await
    {
        Ok(result) => result.map_err(|err| format!("create DNS H3 client: {err:?}")),
        Err(_) => Err("create DNS H3 client timeout".to_owned()),
    };
    let (mut driver, client) = match h3_client {
        Ok(client) => client,
        Err(error) => {
            endpoint.mark_failed();
            return Err(error);
        }
    };
    endpoint.mark_ready();
    let driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let mut forwarder = forwarder.lock().await;
    forwarder.endpoint = Some(endpoint);
    forwarder.connection = Some(connection);
    forwarder.client = Some(client.clone());
    forwarder.driver_task = Some(driver_task);
    Ok(client)
}

async fn close_cached_dns_h3_client(forwarder: &Arc<AsyncMutex<ResidentDnsH3Forwarder>>) {
    let mut forwarder = forwarder.lock().await;
    forwarder.close();
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
