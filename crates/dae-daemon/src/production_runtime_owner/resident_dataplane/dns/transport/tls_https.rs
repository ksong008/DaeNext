use super::super::*;
use super::route::{
    ResidentDnsUpstreamRoutedTarget, dns_upstream_targets_failed, resolved_upstream_targets,
    select_dns_upstream_targets,
};
use super::wire::{
    doh_request_target, forward_dns_framed_stream_async, http1_doh_request_bytes,
    open_dns_tcp_stream_async, parse_doh_http_response, read_to_end_capped_async,
    resident_dns_tls_client_config,
};

pub(super) async fn forward_dns_tls_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
) -> Result<Vec<u8>, String> {
    let (targets, mut failures) = select_dns_upstream_targets(
        plan,
        upstream,
        resolved_upstream_targets(upstream).await?,
        L4Proto::Tcp,
    )?;
    for target in targets {
        match forward_dns_tls_to_routed_target_async(upstream, target, payload).await {
            Ok(response) => return Ok(response),
            Err(err) => failures.push(err),
        }
    }
    Err(dns_upstream_targets_failed(
        upstream,
        "forward DNS TLS to",
        failures,
    ))
}

async fn forward_dns_tls_to_routed_target_async(
    upstream: &ResidentDnsUpstream,
    target: ResidentDnsUpstreamRoutedTarget,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    match target.selection {
        ResidentDnsUpstreamSelection::Direct { mark } => {
            forward_dns_tls_to_target_async(upstream, target.target, payload, mark)
                .await
                .map_err(|err| format!("{}: {err}", target.target))
        }
        ResidentDnsUpstreamSelection::Proxy { proxy } => {
            forward_dns_tls_to_proxy_async(upstream, target.target, payload, proxy)
                .await
                .map_err(|err| format!("{}: {err}", target.target))
        }
    }
}

async fn forward_dns_tls_to_target_async(
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let stream = open_dns_tcp_stream_async(upstream, target, mark).await?;
    forward_dns_tls_over_stream_async(upstream, stream, payload).await
}

async fn forward_dns_tls_to_proxy_async(
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    payload: &[u8],
    proxy: Arc<ResidentProxyPlan>,
) -> Result<Vec<u8>, String> {
    let target = target.to_string();
    exchange_resident_proxy_tcp_stream_async(
        proxy,
        &target,
        true,
        Vec::new(),
        upstream.target.host.clone(),
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        |stream| async move { forward_dns_tls_over_stream_async(upstream, stream, payload).await },
    )
    .await
    .map_err(|err| {
        format!(
            "forward DNS over proxied TLS to upstream {} {} via {}: {err}",
            upstream.tag, upstream.target.authority, target
        )
    })
}

async fn forward_dns_tls_over_stream_async(
    upstream: &ResidentDnsUpstream,
    stream: TokioTcpStream,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let config = resident_dns_tls_client_config(&[])?;
    let server_name = ServerName::try_from(upstream.target.host.clone()).map_err(|err| {
        format!(
            "invalid DNS TLS server name {}: {err}",
            upstream.target.host
        )
    })?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let mut tls = time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| "DNS TLS handshake timeout".to_owned())?
    .map_err(|err| {
        format!(
            "connect DNS TLS upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })?;
    time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        forward_dns_framed_stream_async(&mut tls, payload),
    )
    .await
    .map_err(|_| "DNS TLS exchange timeout".to_owned())?
    .map_err(|err| {
        format!(
            "forward DNS over TLS to upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })
}

pub(super) async fn forward_dns_https_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
) -> Result<Vec<u8>, String> {
    let (targets, mut failures) = select_dns_upstream_targets(
        plan,
        upstream,
        resolved_upstream_targets(upstream).await?,
        L4Proto::Tcp,
    )?;
    for target in targets {
        match forward_dns_https_to_routed_target_async(upstream, target, payload).await {
            Ok(response) => return Ok(response),
            Err(err) => failures.push(err),
        }
    }
    Err(dns_upstream_targets_failed(
        upstream,
        "forward DNS HTTPS to",
        failures,
    ))
}

async fn forward_dns_https_to_routed_target_async(
    upstream: &ResidentDnsUpstream,
    target: ResidentDnsUpstreamRoutedTarget,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    match target.selection {
        ResidentDnsUpstreamSelection::Direct { mark } => {
            forward_dns_https_to_target_async(upstream, target.target, payload, mark)
                .await
                .map_err(|err| format!("{}: {err}", target.target))
        }
        ResidentDnsUpstreamSelection::Proxy { proxy } => {
            forward_dns_https_to_proxy_async(upstream, target.target, payload, proxy)
                .await
                .map_err(|err| format!("{}: {err}", target.target))
        }
    }
}

async fn forward_dns_https_to_target_async(
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let stream = open_dns_tcp_stream_async(upstream, target, mark).await?;
    forward_dns_https_over_stream_async(upstream, stream, payload).await
}

async fn forward_dns_https_to_proxy_async(
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    payload: &[u8],
    proxy: Arc<ResidentProxyPlan>,
) -> Result<Vec<u8>, String> {
    let target = target.to_string();
    exchange_resident_proxy_tcp_stream_async(
        proxy,
        &target,
        true,
        Vec::new(),
        upstream.target.host.clone(),
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        |stream| async move { forward_dns_https_over_stream_async(upstream, stream, payload).await },
    )
    .await
    .map_err(|err| {
        format!(
            "forward DNS over proxied HTTPS to upstream {} {} via {}: {err}",
            upstream.tag, upstream.target.authority, target
        )
    })
}

async fn forward_dns_https_over_stream_async(
    upstream: &ResidentDnsUpstream,
    stream: TokioTcpStream,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let config = resident_dns_tls_client_config(&["http/1.1"])?;
    let server_name = ServerName::try_from(upstream.target.host.clone()).map_err(|err| {
        format!(
            "invalid DNS HTTPS server name {}: {err}",
            upstream.target.host
        )
    })?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let mut tls = time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| "DNS HTTPS TLS handshake timeout".to_owned())?
    .map_err(|err| {
        format!(
            "connect DNS HTTPS upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })?;
    let doh = build_doh_request(
        &upstream.target.authority,
        &upstream.target.authority,
        &upstream.path,
        payload,
    )
    .map_err(|err| format!("build DoH request: {err}"))?;
    let request_target = doh_request_target(&upstream.path, doh.dns_query.as_deref());
    let request = http1_doh_request_bytes(&doh, &request_target);
    time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, async {
        tls.write_all(&request)
            .await
            .map_err(|err| format!("write DoH request: {err}"))?;
        tls.flush()
            .await
            .map_err(|err| format!("flush DoH request: {err}"))?;
        let raw = read_to_end_capped_async(&mut tls, DNS_DOH_RESPONSE_READ_LIMIT).await?;
        parse_doh_http_response(payload, &raw)
    })
    .await
    .map_err(|_| "DNS HTTPS exchange timeout".to_owned())?
    .map_err(|err| {
        format!(
            "forward DNS over HTTPS to upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })
}
