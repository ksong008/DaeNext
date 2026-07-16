use super::super::*;
use super::ResidentDnsTransportError;
use super::plain::dns_transport_route_name;
use super::route::{
    ResidentDnsUpstreamRoutedTarget, dns_upstream_targets_failed, resolved_upstream_targets,
    select_dns_upstream_targets,
};
use super::wire::{
    read_dns_tcp_message_async, resident_dns_quic_client_config, restore_dns_response_id,
    write_dns_tcp_message_async,
};

mod proxy;

use self::proxy::forward_dns_quic_to_proxy_async;

async fn forward_dns_quic_cached(
    forwarder: Arc<AsyncMutex<ResidentDnsQuicForwarder>>,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let permits = {
        let forwarder = forwarder.lock().await;
        Arc::clone(&forwarder.permits)
    };
    let _permit = acquire_dns_owned_permit(permits, "DNS QUIC stream pool").await?;
    let (connection, upstream) = cached_dns_quic_connection(&forwarder).await?;
    match forward_dns_over_quic_connection(&upstream, &connection, payload).await {
        Ok(response) => Ok(response),
        Err(first_err) => {
            close_cached_dns_quic_connection(&forwarder).await;
            let (connection, upstream) = cached_dns_quic_connection(&forwarder).await?;
            forward_dns_over_quic_connection(&upstream, &connection, payload)
                .await
                .map_err(|retry_err| {
                    format!("DNS QUIC cached forwarder retry failed after {first_err}: {retry_err}")
                })
        }
    }
}

async fn cached_dns_quic_connection(
    forwarder: &Arc<AsyncMutex<ResidentDnsQuicForwarder>>,
) -> Result<(quinn::Connection, ResidentDnsUpstream), String> {
    {
        let forwarder = forwarder.lock().await;
        if let Some(connection) = forwarder.connection.as_ref() {
            return Ok((connection.clone(), forwarder.upstream.clone()));
        }
    }
    let open_lock = {
        let forwarder = forwarder.lock().await;
        Arc::clone(&forwarder.open_lock)
    };
    let _open_guard = open_lock.lock().await;
    {
        let forwarder = forwarder.lock().await;
        if let Some(connection) = forwarder.connection.as_ref() {
            return Ok((connection.clone(), forwarder.upstream.clone()));
        }
    }
    let (upstream, generation, mark, fixed_remote) = {
        let forwarder = forwarder.lock().await;
        (
            forwarder.upstream.clone(),
            forwarder.generation,
            forwarder.mark,
            forwarder.fixed_remote,
        )
    };
    let mut failures = Vec::new();
    let remotes = match fixed_remote {
        Some(remote) => vec![remote],
        None => resolved_upstream_targets(&upstream).await?,
    };
    for remote in remotes {
        let open_context = configured_dns_quic_endpoint_context(
            QuicEndpointProtocol::DnsOverQuic,
            &upstream,
            generation,
        );
        let connect_contract = DnsQuicEndpointConnectContract::new(
            open_context,
            DNS_DOQ_ALPN,
            "connect DoQ endpoint",
            "DNS QUIC handshake timeout",
            "connect DNS QUIC upstream",
        );
        match connect_dns_quic_endpoint_async(&upstream, remote, mark, connect_contract).await {
            Ok((endpoint, connection)) => {
                endpoint.mark_ready();
                let mut forwarder = forwarder.lock().await;
                forwarder.endpoint = Some(endpoint);
                forwarder.connection = Some(connection.clone());
                return Ok((connection, upstream));
            }
            Err(err) => failures.push(format!("{remote}: {err}")),
        }
    }
    Err(dns_upstream_targets_failed(
        &upstream,
        "connect DNS QUIC to",
        failures,
    ))
}

async fn close_cached_dns_quic_connection(forwarder: &Arc<AsyncMutex<ResidentDnsQuicForwarder>>) {
    let mut forwarder = forwarder.lock().await;
    forwarder.close_connection();
}

pub(super) async fn forward_dns_quic_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    if plan.upstream_router.is_none() {
        let forwarder = forwarders
            .quic_forwarder(upstream, plan.mark)
            .map_err(ResidentDnsTransportError::message)?;
        return forward_dns_quic_cached(forwarder, payload)
            .await
            .map_err(ResidentDnsTransportError::message);
    }

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
        match forward_dns_quic_to_routed_target_async(
            upstream, remote, payload, forwarders, context,
        )
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
        dns_upstream_targets_failed(upstream, "forward DNS QUIC to", failures),
    ))
}

async fn forward_dns_quic_to_routed_target_async(
    upstream: &ResidentDnsUpstream,
    remote: ResidentDnsUpstreamRoutedTarget,
    payload: &[u8],
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let started_at = std::time::Instant::now();
    let target = remote.target;
    let route = dns_transport_route_name(&remote.selection);
    let result = match remote.selection {
        ResidentDnsUpstreamSelection::Direct { mark } => {
            let forwarder = forwarders
                .quic_forwarder_for_target(
                    upstream,
                    target,
                    mark,
                    &ResidentDnsUpstreamSelection::Direct { mark },
                )
                .map_err(ResidentDnsTransportError::message)?;
            forward_dns_quic_cached(forwarder, payload)
                .await
                .map_err(|err| format!("{target}: {err}"))
                .map_err(ResidentDnsTransportError::message)
        }
        ResidentDnsUpstreamSelection::Proxy { proxy } => {
            forward_dns_quic_to_proxy_async(upstream, target, payload, proxy, context)
                .await
                .map_err(|error| ResidentDnsTransportError::proxy(error.with_context(target)))
        }
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

impl ResidentDnsQuicForwarder {
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

pub(super) struct DnsQuicEndpointConnectContract {
    open_context: QuicEndpointOpenContext,
    alpn: &'static str,
    connect_context: &'static str,
    handshake_timeout: &'static str,
    upstream_context: &'static str,
}

impl DnsQuicEndpointConnectContract {
    pub(super) const fn new(
        open_context: QuicEndpointOpenContext,
        alpn: &'static str,
        connect_context: &'static str,
        handshake_timeout: &'static str,
        upstream_context: &'static str,
    ) -> Self {
        Self {
            open_context,
            alpn,
            connect_context,
            handshake_timeout,
            upstream_context,
        }
    }
}

pub(super) async fn connect_dns_quic_endpoint_async(
    upstream: &ResidentDnsUpstream,
    remote: SocketAddr,
    mark: u32,
    contract: DnsQuicEndpointConnectContract,
) -> Result<(ObservedQuicEndpoint, quinn::Connection), String> {
    let client_config = resident_dns_quic_client_config(contract.alpn)?;
    let mut endpoint = open_marked_quic_endpoint_for_remote(mark, remote, contract.open_context)?;
    endpoint.set_default_client_config(client_config);
    let connection = match endpoint
        .connect(remote, &upstream.target.host)
        .map_err(|err| format!("{}: {err}", contract.connect_context))
    {
        Ok(connecting) => match time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, connecting).await {
            Ok(result) => result.map_err(|err| {
                format!(
                    "{} {} {}: {err}",
                    contract.upstream_context, upstream.tag, upstream.target.authority
                )
            }),
            Err(_) => Err(contract.handshake_timeout.to_owned()),
        },
        Err(error) => Err(error),
    };
    match connection {
        Ok(connection) => Ok((endpoint, connection)),
        Err(error) => {
            endpoint.mark_failed();
            Err(error)
        }
    }
}

pub(super) fn configured_dns_quic_endpoint_context(
    protocol: QuicEndpointProtocol,
    upstream: &ResidentDnsUpstream,
    generation: u64,
) -> QuicEndpointOpenContext {
    let port = upstream.target.port.to_be_bytes();
    QuicEndpointOpenContext::from_identity_parts(
        protocol,
        QuicEndpointCallerClass::ConfiguredDns,
        dae_runtime_control::OwnerGeneration::new(generation),
        QuicEndpointIdentityRole::ConfiguredDns,
        &[
            upstream.tag.as_bytes(),
            upstream.scheme.as_str().as_bytes(),
            upstream.target.authority.as_bytes(),
            upstream.target.host.as_bytes(),
            &port,
            upstream.path.as_bytes(),
        ],
    )
}

pub(super) fn managed_dns_quic_endpoint_context(
    protocol: QuicEndpointProtocol,
    upstream: &ResidentDnsUpstream,
    remote: SocketAddr,
    proxy: &ResidentProxyPlan,
) -> QuicEndpointOpenContext {
    let port = upstream.target.port.to_be_bytes();
    let remote = remote.to_string();
    QuicEndpointOpenContext::for_proxy(
        protocol,
        QuicEndpointCallerClass::ManagedDns,
        proxy,
        QuicEndpointIdentityRole::ManagedDnsOuter,
        &[
            upstream.tag.as_bytes(),
            upstream.scheme.as_str().as_bytes(),
            upstream.target.authority.as_bytes(),
            upstream.target.host.as_bytes(),
            &port,
            upstream.path.as_bytes(),
            remote.as_bytes(),
        ],
    )
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
