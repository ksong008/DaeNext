use super::super::*;
use super::route::{
    ResidentDnsUpstreamRoutedTarget, dns_upstream_targets_failed, resolved_upstream_targets,
    select_dns_upstream_targets,
};
use super::wire::{
    read_dns_tcp_message_async, resident_dns_quic_client_config, restore_dns_response_id,
    write_dns_tcp_message_async,
};

async fn forward_dns_quic_cached(
    forwarder: Arc<AsyncMutex<ResidentDnsQuicForwarder>>,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let (connection, upstream) = {
        let mut forwarder = forwarder.lock().await;
        (forwarder.connection().await?, forwarder.upstream.clone())
    };
    match forward_dns_over_quic_connection(&upstream, &connection, payload).await {
        Ok(response) => Ok(response),
        Err(first_err) => {
            let (connection, upstream) = {
                let mut forwarder = forwarder.lock().await;
                forwarder.close_connection();
                (forwarder.connection().await?, forwarder.upstream.clone())
            };
            forward_dns_over_quic_connection(&upstream, &connection, payload)
                .await
                .map_err(|retry_err| {
                    format!("DNS QUIC cached forwarder retry failed after {first_err}: {retry_err}")
                })
        }
    }
}

pub(super) async fn forward_dns_quic_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
    forwarders: &Arc<ResidentDnsForwarderCache>,
) -> Result<Vec<u8>, String> {
    if plan.upstream_router.is_none() {
        let forwarder = forwarders.quic_forwarder(upstream, plan.mark)?;
        return forward_dns_quic_cached(forwarder, payload).await;
    }

    let (targets, mut failures) = select_dns_upstream_targets(
        plan,
        upstream,
        resolved_upstream_targets(upstream).await?,
        L4Proto::Udp,
    )?;
    for remote in targets {
        match forward_dns_quic_to_routed_target_async(upstream, remote, payload).await {
            Ok(response) => return Ok(response),
            Err(err) => failures.push(err),
        }
    }
    Err(dns_upstream_targets_failed(
        upstream,
        "forward DNS QUIC to",
        failures,
    ))
}

async fn forward_dns_quic_to_routed_target_async(
    upstream: &ResidentDnsUpstream,
    remote: ResidentDnsUpstreamRoutedTarget,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    match remote.selection {
        ResidentDnsUpstreamSelection::Direct { mark } => {
            forward_dns_quic_to_target_async(upstream, remote.target, payload, mark)
                .await
                .map_err(|err| format!("{}: {err}", remote.target))
        }
        ResidentDnsUpstreamSelection::Proxy { proxy } => {
            forward_dns_quic_to_proxy_async(upstream, remote.target, payload, proxy)
                .await
                .map_err(|err| format!("{}: {err}", remote.target))
        }
    }
}

async fn forward_dns_quic_to_target_async(
    upstream: &ResidentDnsUpstream,
    remote: SocketAddr,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let mut forwarder = ResidentDnsQuicForwarder {
        upstream: upstream.clone(),
        mark,
        endpoint: None,
        connection: None,
    };
    let connection = forwarder.connect_remote(remote).await?;
    forward_dns_over_quic_connection(upstream, &connection, payload).await
}

async fn forward_dns_quic_to_proxy_async(
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
        DNS_DOQ_ALPN,
        "connect DoQ endpoint",
        "DNS QUIC handshake timeout",
        "connect DNS QUIC upstream",
    )
    .await
    {
        Ok(connection) => connection,
        Err(err) => {
            let err = append_dns_proxy_udp_bridge_error(err, &bridge);
            bridge.shutdown().await;
            return Err(format!("connect DNS QUIC via proxied UDP {remote}: {err}"));
        }
    };
    let result = forward_dns_over_quic_connection(upstream, &connection, payload).await;
    connection.close(0_u32.into(), b"dns-query done");
    endpoint.wait_idle().await;
    bridge.shutdown().await;
    result
}

impl ResidentDnsQuicForwarder {
    async fn connection(&mut self) -> Result<quinn::Connection, String> {
        if let Some(connection) = self.connection.as_ref() {
            return Ok(connection.clone());
        }
        let mut failures = Vec::new();
        for remote in resolved_upstream_targets(&self.upstream).await? {
            match self.connect_remote(remote).await {
                Ok(connection) => return Ok(connection),
                Err(err) => failures.push(format!("{remote}: {err}")),
            }
        }
        Err(dns_upstream_targets_failed(
            &self.upstream,
            "connect DNS QUIC to",
            failures,
        ))
    }

    async fn connect_remote(&mut self, remote: SocketAddr) -> Result<quinn::Connection, String> {
        let (endpoint, connection) = connect_dns_quic_endpoint_async(
            &self.upstream,
            remote,
            self.mark,
            DNS_DOQ_ALPN,
            "connect DoQ endpoint",
            "DNS QUIC handshake timeout",
            "connect DNS QUIC upstream",
        )
        .await?;
        self.endpoint = Some(endpoint);
        self.connection = Some(connection.clone());
        Ok(connection)
    }

    fn close_connection(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), b"dns-query failed");
        }
    }
}

async fn forward_dns_over_quic_connection(
    upstream: &ResidentDnsUpstream,
    connection: &quinn::Connection,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let (mut send, mut recv) = time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, connection.open_bi())
        .await
        .map_err(|_| "DNS QUIC stream open timeout".to_owned())?
        .map_err(|err| format!("open DNS QUIC stream: {err}"))?;
    let query = dns_data_with_zero_id(payload);
    time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, async {
        write_dns_tcp_message_async(&mut send, &query).await?;
        send.finish()
            .map_err(|err| format!("finish DNS QUIC request stream: {err}"))?;
        let response = read_dns_tcp_message_async(&mut recv).await?;
        restore_dns_response_id(payload, &response)
    })
    .await
    .map_err(|_| "DNS QUIC exchange timeout".to_owned())?
    .map_err(|err| {
        format!(
            "forward DNS over QUIC to upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })
}

pub(super) async fn connect_dns_quic_endpoint_async(
    upstream: &ResidentDnsUpstream,
    remote: SocketAddr,
    mark: u32,
    alpn: &str,
    endpoint_context: &'static str,
    handshake_timeout: &'static str,
    upstream_context: &'static str,
) -> Result<(quinn::Endpoint, quinn::Connection), String> {
    let mut endpoint = open_marked_quic_endpoint_for_remote(mark, remote)?;
    endpoint.set_default_client_config(resident_dns_quic_client_config(alpn)?);
    let connection = time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        endpoint
            .connect(remote, &upstream.target.host)
            .map_err(|err| format!("{endpoint_context}: {err}"))?,
    )
    .await
    .map_err(|_| handshake_timeout.to_owned())?
    .map_err(|err| {
        format!(
            "{upstream_context} {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })?;
    Ok((endpoint, connection))
}

pub(super) fn append_dns_proxy_udp_bridge_error(
    err: String,
    bridge: &ResidentProxyUdpBridge,
) -> String {
    match bridge.last_error() {
        Some(bridge_err) => format!("{err}; proxy UDP bridge: {bridge_err}"),
        None => err,
    }
}
