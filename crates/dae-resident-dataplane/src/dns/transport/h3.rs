use super::super::*;
use super::ResidentDnsTransportError;
use super::plain::dns_transport_route_name;
use super::quic::{
    DnsQuicEndpointConnectContract, configured_dns_quic_endpoint_context,
    connect_dns_quic_endpoint_async,
};
use super::route::{
    ResidentDnsUpstreamRoutedTarget, race_dns_upstream_targets_with_refresh,
    refresh_dns_upstream_targets, resolved_upstream_targets, select_dns_upstream_targets,
};
use super::wire::{doh_request_target, restore_dns_response_id};
use crate::inherit_quic_endpoint_observation;
use serde_json::{Value, json};

mod proxied;

use self::proxied::forward_dns_h3_to_proxy_async;
pub(super) use self::proxied::shutdown_cached_proxy_dns_h3;

pub(super) async fn forward_dns_h3_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let resolved = resolved_upstream_targets(upstream, context.deadline())
        .await
        .map_err(ResidentDnsTransportError::message)?;
    let (targets, failures) =
        select_dns_upstream_targets(plan, upstream, resolved.to_vec(), L4Proto::Udp)
            .map_err(ResidentDnsTransportError::message)?;
    race_dns_upstream_targets_with_refresh(
        upstream,
        &resolved,
        "forward DNS H3 to",
        targets,
        failures,
        forwarders.resources.upstream_candidate_race_width(),
        context,
        || async {
            refresh_dns_upstream_targets(
                plan,
                upstream,
                &resolved,
                L4Proto::Udp,
                context.deadline(),
            )
            .await
        },
        |remote| async move {
            forward_dns_h3_to_routed_target_async(upstream, remote, payload, forwarders, context)
                .await
        },
    )
    .await
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
            forward_dns_h3_cached(upstream, forwarder, payload, context)
                .await
                .map_err(|error| {
                    if error.failure() == ProxyDnsRequestFailure::Protocol {
                        ResidentDnsTransportError::protocol(format!("{target}: {error}"))
                    } else {
                        ResidentDnsTransportError::proxy(error.with_context(target))
                    }
                })
        }
        ResidentDnsUpstreamSelection::Proxy { binding } => {
            let forwarder = forwarders
                .proxy_h3_forwarder(upstream, target, binding.clone(), &remote.selection)
                .map_err(ResidentDnsTransportError::message)?;
            forward_dns_h3_to_proxy_async(upstream, payload, forwarder, context)
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

async fn forward_dns_h3_cached(
    upstream: &ResidentDnsUpstream,
    forwarder: Arc<AsyncMutex<ResidentDnsH3Forwarder>>,
    payload: &[u8],
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ProxyDnsRequestError> {
    let permits = {
        let forwarder = lock_dns_h3_forwarder(&forwarder, context, "read stream permits")
            .await
            .map_err(|error| {
                direct_dns_h3_internal_error(context, ProxyDnsRequestStage::OwnerAcquire, error)
            })?;
        Arc::clone(&forwarder.permits)
    };
    let _permit = context
        .run(
            ProxyDnsRequestStage::OwnerAcquire,
            ProxyDnsRequestFailure::Capacity,
            permits.acquire_owned(),
        )
        .await?;
    let (mut client, connection_id) =
        cached_dns_h3_client(&forwarder, context)
            .await
            .map_err(|error| {
                direct_dns_h3_internal_error(context, ProxyDnsRequestStage::Connect, error)
            })?;
    let exchange = context
        .run(
            ProxyDnsRequestStage::Send,
            ProxyDnsRequestFailure::Protocol,
            forward_dns_h3_with_client_async(upstream, payload, &mut client),
        )
        .await;
    match exchange {
        Ok(response) => Ok(response),
        Err(first_err) => {
            reset_cached_dns_h3_client(&forwarder, connection_id, context)
                .await
                .map_err(|error| {
                    ProxyDnsRequestError::new(
                        ProxyDnsRequestStage::Cleanup,
                        ProxyDnsRequestFailure::Network,
                        error,
                    )
                })?;
            context.ensure(ProxyDnsRequestStage::Retry)?;
            let (mut client, _) =
                cached_dns_h3_client(&forwarder, context)
                    .await
                    .map_err(|error| {
                        direct_dns_h3_internal_error(context, ProxyDnsRequestStage::Connect, error)
                    })?;
            context
                .run(
                    ProxyDnsRequestStage::Send,
                    ProxyDnsRequestFailure::Protocol,
                    forward_dns_h3_with_client_async(upstream, payload, &mut client),
                )
                .await
                .map_err(|retry_err| {
                    retry_err.with_context(format!(
                        "DNS H3 cached forwarder retry failed after {first_err}"
                    ))
                })
        }
    }
}

fn direct_dns_h3_internal_error(
    context: ProxyDnsRequestContext,
    stage: ProxyDnsRequestStage,
    error: impl Into<String>,
) -> ProxyDnsRequestError {
    if time::Instant::now() >= context.deadline() {
        ProxyDnsRequestError::deadline(stage)
    } else {
        ProxyDnsRequestError::new(stage, ProxyDnsRequestFailure::Network, error)
    }
}

async fn cached_dns_h3_client(
    forwarder: &Arc<AsyncMutex<ResidentDnsH3Forwarder>>,
    context: ProxyDnsRequestContext,
) -> Result<(h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>, usize), String> {
    let task_executor = {
        let forwarder = lock_dns_h3_forwarder(forwarder, context, "read client").await?;
        if forwarder.closing {
            return Err("DNS H3 forwarder is closing".to_owned());
        }
        if let (Some(client), Some(connection)) =
            (forwarder.client.as_ref(), forwarder.connection.as_ref())
        {
            return Ok((client.clone(), connection.stable_id()));
        }
        Arc::clone(&forwarder.task_executor)
    };
    let task_forwarder = Arc::clone(forwarder);
    task_executor
        .execute_owned_task(inherit_quic_endpoint_observation(async move {
            open_cached_dns_h3_client(&task_forwarder, context).await
        }))
        .await?
}

async fn open_cached_dns_h3_client(
    forwarder: &Arc<AsyncMutex<ResidentDnsH3Forwarder>>,
    context: ProxyDnsRequestContext,
) -> Result<(h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>, usize), String> {
    let open_lock = {
        let forwarder = lock_dns_h3_forwarder(forwarder, context, "read open lock").await?;
        Arc::clone(&forwarder.open_lock)
    };
    let _open_guard = time::timeout_at(context.deadline(), open_lock.lock())
        .await
        .map_err(|_| "DNS H3 open lock absolute deadline elapsed".to_owned())?;
    {
        let forwarder = lock_dns_h3_forwarder(forwarder, context, "recheck client").await?;
        if forwarder.closing {
            return Err("DNS H3 forwarder is closing".to_owned());
        }
        if let (Some(client), Some(connection)) =
            (forwarder.client.as_ref(), forwarder.connection.as_ref())
        {
            return Ok((client.clone(), connection.stable_id()));
        }
    }
    let (upstream, generation, target, mark, session_cache, quic_endpoint_transport) = {
        let forwarder = lock_dns_h3_forwarder(forwarder, context, "read endpoint plan").await?;
        (
            forwarder.upstream.clone(),
            forwarder.generation,
            forwarder.target,
            forwarder.mark,
            forwarder.session_cache.clone(),
            Arc::clone(&forwarder.quic_endpoint_transport),
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
    let (endpoint, connection) = context
        .run(
            ProxyDnsRequestStage::Connect,
            ProxyDnsRequestFailure::Network,
            connect_dns_quic_endpoint_async(
                quic_endpoint_transport.as_ref(),
                &upstream,
                target,
                mark,
                connect_contract,
                session_cache,
            ),
        )
        .await
        .map_err(|error| error.to_string())?;
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let h3_client = context
        .run(
            ProxyDnsRequestStage::Authenticate,
            ProxyDnsRequestFailure::Network,
            h3::client::new(h3_connection),
        )
        .await
        .map_err(|error| error.to_string());
    let (mut driver, client) = match h3_client {
        Ok(client) => client,
        Err(error) => {
            endpoint.mark_failed();
            connection.close(0_u32.into(), b"DNS H3 client creation failed");
            endpoint.close(0_u32.into(), b"DNS H3 client creation failed");
            let _ = time::timeout_at(context.deadline(), endpoint.wait_idle()).await;
            return Err(error);
        }
    };
    let connection_id = connection.stable_id();
    endpoint.mark_ready();
    let driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let mut forwarder = match lock_dns_h3_forwarder(forwarder, context, "install client").await {
        Ok(forwarder) => forwarder,
        Err(error) => {
            drop(client);
            connection.close(0_u32.into(), b"DNS H3 install deadline elapsed");
            endpoint.close(0_u32.into(), b"DNS H3 install deadline elapsed");
            driver_task.abort();
            let _ = time::timeout_at(context.deadline(), async {
                let _ = driver_task.await;
                endpoint.wait_idle().await;
            })
            .await;
            return Err(error);
        }
    };
    if forwarder.closing {
        drop(forwarder);
        drop(client);
        connection.close(0_u32.into(), b"DNS H3 forwarder closing");
        endpoint.close(0_u32.into(), b"DNS H3 forwarder closing");
        driver_task.abort();
        let _ = time::timeout_at(context.deadline(), async {
            let _ = driver_task.await;
            endpoint.wait_idle().await;
        })
        .await;
        return Err("DNS H3 forwarder closed during connect".to_owned());
    }
    forwarder.endpoint = Some(endpoint);
    forwarder.connection = Some(connection);
    forwarder.client = Some(client.clone());
    forwarder.driver_task = Some(driver_task);
    Ok((client, connection_id))
}

async fn reset_cached_dns_h3_client(
    forwarder: &Arc<AsyncMutex<ResidentDnsH3Forwarder>>,
    failed_connection_id: usize,
    context: ProxyDnsRequestContext,
) -> Result<(), String> {
    let (connection, endpoint, driver_task) = {
        let mut forwarder =
            lock_dns_h3_forwarder(forwarder, context, "reset failed client").await?;
        if forwarder
            .connection
            .as_ref()
            .is_none_or(|connection| connection.stable_id() != failed_connection_id)
        {
            return Ok(());
        }
        forwarder.client = None;
        (
            forwarder.connection.take(),
            forwarder.endpoint.take(),
            forwarder.driver_task.take(),
        )
    };
    if let Some(connection) = connection {
        connection.close(0_u32.into(), b"DNS H3 cached connection failed");
    }
    if let Some(mut task) = driver_task {
        task.abort();
        let _ = time::timeout_at(context.deadline(), &mut task)
            .await
            .map_err(|_| "DNS H3 reset driver join deadline elapsed".to_owned())?;
    }
    if let Some(endpoint) = endpoint {
        endpoint.close(0_u32.into(), b"DNS H3 cached connection failed");
        time::timeout_at(context.deadline(), endpoint.wait_idle())
            .await
            .map_err(|_| "DNS H3 reset endpoint idle deadline elapsed".to_owned())?;
    }
    Ok(())
}

async fn lock_dns_h3_forwarder<'a>(
    forwarder: &'a Arc<AsyncMutex<ResidentDnsH3Forwarder>>,
    context: ProxyDnsRequestContext,
    action: &str,
) -> Result<tokio::sync::MutexGuard<'a, ResidentDnsH3Forwarder>, String> {
    time::timeout_at(context.deadline(), forwarder.lock())
        .await
        .map_err(|_| format!("DNS H3 forwarder {action} absolute deadline elapsed"))
}

pub(super) async fn shutdown_cached_dns_h3(
    forwarder: Arc<AsyncMutex<ResidentDnsH3Forwarder>>,
    deadline: time::Instant,
) -> Value {
    let state = time::timeout_at(deadline, forwarder.lock()).await;
    let Ok(mut state) = state else {
        return json!({
            "status": "fail",
            "transport": "doh3",
            "error": "DNS H3 forwarder lock deadline elapsed",
        });
    };
    state.closing = true;
    let _ = state.session_cache.clear();
    state.permits.close();
    state.client = None;
    let connection = state.connection.take();
    let endpoint = state.endpoint.take();
    let driver_task = state.driver_task.take();
    drop(state);
    if let Some(connection) = connection {
        connection.close(0_u32.into(), b"DNS H3 cache shutdown");
    }
    let mut driver_joined = true;
    if let Some(mut task) = driver_task {
        task.abort();
        driver_joined = time::timeout_at(deadline, &mut task).await.is_ok();
    }
    let mut endpoint_idle = true;
    if let Some(endpoint) = endpoint {
        endpoint.close(0_u32.into(), b"DNS H3 cache shutdown");
        endpoint_idle = time::timeout_at(deadline, endpoint.wait_idle())
            .await
            .is_ok();
    }
    json!({
        "status": if endpoint_idle && driver_joined { "pass" } else { "fail" },
        "transport": "doh3",
        "endpointIdle": endpoint_idle,
        "driverJoined": driver_joined,
    })
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
