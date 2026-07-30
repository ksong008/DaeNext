use super::super::*;
use super::ResidentDnsTransportError;
use super::plain::dns_transport_route_name;
use super::route::{
    ResidentDnsUpstreamRoutedTarget, dns_upstream_targets_failed, race_dns_upstream_targets,
    resolved_upstream_targets, select_dns_upstream_targets,
};
use super::wire::{
    read_dns_tcp_message_async, resident_dns_quic_client_config, restore_dns_response_id,
    write_dns_tcp_message_async,
};
use crate::production_runtime_owner::resident_dataplane::tcp::{
    inherit_quic_endpoint_observation, wait_quic_endpoint_idle_after_close,
};
use serde_json::{Value, json};

mod proxy;

use self::proxy::forward_dns_quic_to_proxy_async;
pub(super) use self::proxy::shutdown_cached_proxy_dns_quic;

async fn forward_dns_quic_cached(
    forwarder: Arc<AsyncMutex<ResidentDnsQuicForwarder>>,
    payload: &[u8],
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, String> {
    let permits = {
        let forwarder = lock_dns_quic_forwarder(&forwarder, context, "read stream permits").await?;
        Arc::clone(&forwarder.permits)
    };
    let _permit = context
        .run(
            ProxyDnsRequestStage::OwnerAcquire,
            ProxyDnsRequestFailure::Capacity,
            permits.acquire_owned(),
        )
        .await
        .map_err(|error| error.to_string())?;
    let (connection, upstream) = cached_dns_quic_connection(&forwarder, context).await?;
    let exchange = context
        .run(
            ProxyDnsRequestStage::Send,
            ProxyDnsRequestFailure::Network,
            forward_dns_over_quic_connection(&upstream, &connection, payload),
        )
        .await;
    match exchange {
        Ok(response) => Ok(response),
        Err(first_err) => {
            close_cached_dns_quic_connection(&forwarder, connection.stable_id(), context).await?;
            context
                .ensure(ProxyDnsRequestStage::Retry)
                .map_err(|error| error.to_string())?;
            let (connection, upstream) = cached_dns_quic_connection(&forwarder, context).await?;
            context
                .run(
                    ProxyDnsRequestStage::Send,
                    ProxyDnsRequestFailure::Network,
                    forward_dns_over_quic_connection(&upstream, &connection, payload),
                )
                .await
                .map_err(|retry_err| {
                    format!("DNS QUIC cached forwarder retry failed after {first_err}: {retry_err}")
                })
        }
    }
}

async fn cached_dns_quic_connection(
    forwarder: &Arc<AsyncMutex<ResidentDnsQuicForwarder>>,
    context: ProxyDnsRequestContext,
) -> Result<(quinn::Connection, ResidentDnsUpstream), String> {
    let task_executor = {
        let forwarder = lock_dns_quic_forwarder(forwarder, context, "read connection").await?;
        if forwarder.closing {
            return Err("DNS QUIC forwarder is closing".to_owned());
        }
        if let Some(connection) = forwarder.connection.as_ref() {
            return Ok((connection.clone(), forwarder.upstream.clone()));
        }
        Arc::clone(&forwarder.task_executor)
    };
    let task_forwarder = Arc::clone(forwarder);
    task_executor
        .execute_owned_task(inherit_quic_endpoint_observation(async move {
            open_cached_dns_quic_connection(&task_forwarder, context).await
        }))
        .await?
}

async fn open_cached_dns_quic_connection(
    forwarder: &Arc<AsyncMutex<ResidentDnsQuicForwarder>>,
    context: ProxyDnsRequestContext,
) -> Result<(quinn::Connection, ResidentDnsUpstream), String> {
    let open_lock = {
        let forwarder = lock_dns_quic_forwarder(forwarder, context, "read open lock").await?;
        Arc::clone(&forwarder.open_lock)
    };
    let _open_guard = time::timeout_at(context.deadline(), open_lock.lock())
        .await
        .map_err(|_| "DNS QUIC open lock absolute deadline elapsed".to_owned())?;
    {
        let forwarder = lock_dns_quic_forwarder(forwarder, context, "recheck connection").await?;
        if forwarder.closing {
            return Err("DNS QUIC forwarder is closing".to_owned());
        }
        if let Some(connection) = forwarder.connection.as_ref() {
            return Ok((connection.clone(), forwarder.upstream.clone()));
        }
    }
    let (upstream, generation, mark, fixed_remote) = {
        let forwarder = lock_dns_quic_forwarder(forwarder, context, "read endpoint plan").await?;
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
        None => context
            .run(
                ProxyDnsRequestStage::OwnerAcquire,
                ProxyDnsRequestFailure::Network,
                resolved_upstream_targets(&upstream),
            )
            .await
            .map_err(|error| error.to_string())?
            .to_vec(),
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
        let connected = context
            .run(
                ProxyDnsRequestStage::Connect,
                ProxyDnsRequestFailure::Network,
                connect_dns_quic_endpoint_async(&upstream, remote, mark, connect_contract),
            )
            .await;
        match connected {
            Ok((endpoint, connection)) => {
                endpoint.mark_ready();
                let mut forwarder =
                    match lock_dns_quic_forwarder(forwarder, context, "install connection").await {
                        Ok(forwarder) => forwarder,
                        Err(error) => {
                            connection.close(0_u32.into(), b"DNS QUIC install deadline elapsed");
                            endpoint.close(0_u32.into(), b"DNS QUIC install deadline elapsed");
                            let _ =
                                time::timeout_at(context.deadline(), endpoint.wait_idle()).await;
                            return Err(error);
                        }
                    };
                if forwarder.closing {
                    drop(forwarder);
                    connection.close(0_u32.into(), b"DNS QUIC forwarder closing");
                    endpoint.close(0_u32.into(), b"DNS QUIC forwarder closing");
                    wait_quic_endpoint_idle_after_close(&endpoint).await;
                    return Err("DNS QUIC forwarder closed during connect".to_owned());
                }
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

async fn close_cached_dns_quic_connection(
    forwarder: &Arc<AsyncMutex<ResidentDnsQuicForwarder>>,
    failed_connection_id: usize,
    context: ProxyDnsRequestContext,
) -> Result<(), String> {
    let endpoint = {
        let mut forwarder =
            lock_dns_quic_forwarder(forwarder, context, "reset failed connection").await?;
        if forwarder
            .connection
            .as_ref()
            .is_none_or(|connection| connection.stable_id() != failed_connection_id)
        {
            return Ok(());
        }
        if let Some(connection) = forwarder.connection.take() {
            connection.close(0_u32.into(), b"DNS QUIC cached connection failed");
        }
        forwarder.endpoint.take()
    };
    if let Some(endpoint) = endpoint {
        endpoint.close(0_u32.into(), b"DNS QUIC cached connection failed");
        time::timeout_at(context.deadline(), endpoint.wait_idle())
            .await
            .map_err(|_| "DNS QUIC reset endpoint idle deadline elapsed".to_owned())?;
    }
    Ok(())
}

async fn lock_dns_quic_forwarder<'a>(
    forwarder: &'a Arc<AsyncMutex<ResidentDnsQuicForwarder>>,
    context: ProxyDnsRequestContext,
    action: &str,
) -> Result<tokio::sync::MutexGuard<'a, ResidentDnsQuicForwarder>, String> {
    time::timeout_at(context.deadline(), forwarder.lock())
        .await
        .map_err(|_| format!("DNS QUIC forwarder {action} absolute deadline elapsed"))
}

pub(super) async fn shutdown_cached_dns_quic(
    forwarder: Arc<AsyncMutex<ResidentDnsQuicForwarder>>,
    deadline: time::Instant,
) -> Value {
    let state = time::timeout_at(deadline, forwarder.lock()).await;
    let Ok(mut state) = state else {
        return json!({
            "status": "fail",
            "transport": "doq",
            "error": "DNS QUIC forwarder lock deadline elapsed",
        });
    };
    state.closing = true;
    state.permits.close();
    let connection = state.connection.take();
    let endpoint = state.endpoint.take();
    drop(state);
    if let Some(connection) = connection {
        connection.close(0_u32.into(), b"DNS QUIC cache shutdown");
    }
    let mut idle = true;
    if let Some(endpoint) = endpoint {
        endpoint.close(0_u32.into(), b"DNS QUIC cache shutdown");
        idle = time::timeout_at(deadline, endpoint.wait_idle())
            .await
            .is_ok();
    }
    json!({
        "status": if idle { "pass" } else { "fail" },
        "transport": "doq",
        "endpointIdle": idle,
    })
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
        return forward_dns_quic_cached(forwarder, payload, context)
            .await
            .map_err(ResidentDnsTransportError::message);
    }

    let resolved = resolved_upstream_targets(upstream)
        .await
        .map_err(ResidentDnsTransportError::message)?;
    let (targets, failures) =
        select_dns_upstream_targets(plan, upstream, resolved.to_vec(), L4Proto::Udp)
            .map_err(ResidentDnsTransportError::message)?;
    race_dns_upstream_targets(
        upstream,
        &resolved,
        "forward DNS QUIC to",
        targets,
        failures,
        forwarders.resources.upstream_candidate_race_width(),
        |remote| async move {
            forward_dns_quic_to_routed_target_async(upstream, remote, payload, forwarders, context)
                .await
        },
    )
    .await
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
    let result = match &remote.selection {
        ResidentDnsUpstreamSelection::Direct { mark } => {
            let forwarder = forwarders
                .quic_forwarder_for_target(upstream, target, *mark, &remote.selection)
                .map_err(ResidentDnsTransportError::message)?;
            forward_dns_quic_cached(forwarder, payload, context)
                .await
                .map_err(|err| format!("{target}: {err}"))
                .map_err(ResidentDnsTransportError::message)
        }
        ResidentDnsUpstreamSelection::Proxy { binding } => {
            let forwarder = forwarders
                .proxy_quic_forwarder(upstream, target, binding.clone(), &remote.selection)
                .map_err(ResidentDnsTransportError::message)?;
            forward_dns_quic_to_proxy_async(upstream, payload, forwarder, context)
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
    let deadline = dae_runtime_control::AbsoluteDeadline::from_now(
        Instant::now(),
        RESIDENT_UDP_RESPONSE_TIMEOUT,
    );
    let cancellation = dae_runtime_control::OwnerCancellationSignal::new();
    let client_config = resident_dns_quic_client_config(contract.alpn)?;
    let mut endpoint = open_marked_quic_endpoint_for_remote(
        mark,
        remote,
        contract.open_context,
        deadline,
        &cancellation,
    )?;
    endpoint.set_default_client_config(client_config);
    let connection = match endpoint
        .connect(remote, &upstream.target.host)
        .map_err(|err| format!("{}: {err}", contract.connect_context))
    {
        Ok(connecting) => match deadline.remaining_at(Instant::now()) {
            None => Err(contract.handshake_timeout.to_owned()),
            Some(remaining) => match time::timeout(remaining, connecting).await {
                Ok(result) => result.map_err(|err| {
                    format!(
                        "{} {} {}: {err}",
                        contract.upstream_context, upstream.tag, upstream.target.authority
                    )
                }),
                Err(_) => Err(contract.handshake_timeout.to_owned()),
            },
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
    binding: &ResidentProxyBinding,
) -> QuicEndpointOpenContext {
    let port = upstream.target.port.to_be_bytes();
    let remote = remote.to_string();
    QuicEndpointOpenContext::for_proxy(
        protocol,
        QuicEndpointCallerClass::ManagedDns,
        binding.runtime_generation(),
        binding.plan(),
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
