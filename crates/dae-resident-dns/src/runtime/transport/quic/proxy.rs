use super::*;
use dae_resident_core::ResidentOwnedTaskShutdownCompletion;
use serde_json::{Value, json};

pub async fn forward_dns_quic_to_proxy_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    forwarder: Arc<AsyncMutex<ResidentDnsProxyQuicForwarder>>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ProxyDnsRequestError> {
    let generation = {
        let forwarder =
            lock_proxy_dns_quic_forwarder(&forwarder, context, "read generation").await?;
        forwarder.binding.runtime_generation()
    };
    scope_quic_endpoint_observation(
        QuicEndpointCallerClass::ManagedDns,
        Some(generation),
        forward_dns_quic_to_proxy_with_context(upstream, payload, forwarder, context),
    )
    .await
}

async fn forward_dns_quic_to_proxy_with_context(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    forwarder: Arc<AsyncMutex<ResidentDnsProxyQuicForwarder>>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ProxyDnsRequestError> {
    let permits = {
        let forwarder =
            lock_proxy_dns_quic_forwarder(&forwarder, context, "read stream permits").await?;
        Arc::clone(&forwarder.permits)
    };
    let _permit = context
        .run(
            ProxyDnsRequestStage::OwnerAcquire,
            ProxyDnsRequestFailure::Capacity,
            permits.acquire_owned(),
        )
        .await?;

    let connection = cached_proxy_dns_quic_connection(&forwarder, context).await?;
    match forward_proxy_dns_over_quic(upstream, &connection, payload, context).await {
        Ok(response) => Ok(response),
        Err(first_error) => {
            let cleanup =
                close_cached_proxy_dns_quic(&forwarder, connection.stable_id(), context).await;
            if cleanup.is_err() {
                return Err(append_cleanup_error(first_error, cleanup));
            }
            context.ensure(ProxyDnsRequestStage::Retry)?;
            let connection = cached_proxy_dns_quic_connection(&forwarder, context).await?;
            forward_proxy_dns_over_quic(upstream, &connection, payload, context)
                .await
                .map_err(|retry_error| {
                    ProxyDnsRequestError::new(
                        retry_error.stage(),
                        retry_error.failure(),
                        format!(
                            "proxied DoQ cached retry failed after {first_error}: {retry_error}"
                        ),
                    )
                })
        }
    }
}

async fn cached_proxy_dns_quic_connection(
    forwarder: &Arc<AsyncMutex<ResidentDnsProxyQuicForwarder>>,
    context: ProxyDnsRequestContext,
) -> Result<quinn::Connection, ProxyDnsRequestError> {
    let task_executor = {
        let forwarder =
            lock_proxy_dns_quic_forwarder(forwarder, context, "read connection").await?;
        if forwarder.closing {
            return Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::OwnerAcquire,
                ProxyDnsRequestFailure::Network,
                "proxied DoQ forwarder is closing",
            ));
        }
        if let Some(connection) = forwarder.connection.as_ref() {
            return Ok(connection.clone());
        }
        Arc::clone(&forwarder.task_executor)
    };
    let task_forwarder = Arc::clone(forwarder);
    task_executor
        .execute_owned_task(inherit_quic_endpoint_observation(async move {
            open_cached_proxy_dns_quic_connection(&task_forwarder, context).await
        }))
        .await
        .map_err(|error| {
            ProxyDnsRequestError::new(
                ProxyDnsRequestStage::OwnerAcquire,
                ProxyDnsRequestFailure::Network,
                error,
            )
        })?
}

async fn open_cached_proxy_dns_quic_connection(
    forwarder: &Arc<AsyncMutex<ResidentDnsProxyQuicForwarder>>,
    context: ProxyDnsRequestContext,
) -> Result<quinn::Connection, ProxyDnsRequestError> {
    let open_lock = {
        let forwarder = lock_proxy_dns_quic_forwarder(forwarder, context, "read open lock").await?;
        Arc::clone(&forwarder.open_lock)
    };
    context.ensure(ProxyDnsRequestStage::OwnerAcquire)?;
    let _open_guard = time::timeout_at(context.deadline(), open_lock.lock())
        .await
        .map_err(|_| ProxyDnsRequestError::deadline(ProxyDnsRequestStage::OwnerAcquire))?;
    {
        let forwarder =
            lock_proxy_dns_quic_forwarder(forwarder, context, "recheck connection").await?;
        if forwarder.closing {
            return Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::OwnerAcquire,
                ProxyDnsRequestFailure::Network,
                "proxied DoQ forwarder is closing",
            ));
        }
        if let Some(connection) = forwarder.connection.as_ref() {
            return Ok(connection.clone());
        }
    }
    let (upstream, remote, proxy, proxy_udp_transport, quic_endpoint_transport, client_config) = {
        let forwarder =
            lock_proxy_dns_quic_forwarder(forwarder, context, "read endpoint plan").await?;
        (
            forwarder.upstream.clone(),
            forwarder.remote,
            forwarder.binding.clone(),
            Arc::clone(&forwarder.proxy_udp_transport),
            Arc::clone(&forwarder.quic_endpoint_transport),
            proxy_dns_quic_client_config(&forwarder)?,
        )
    };
    let bridge = context
        .run(
            ProxyDnsRequestStage::OwnerAcquire,
            ProxyDnsRequestFailure::Network,
            proxy_udp_transport.open_bridge(
                proxy.clone(),
                remote,
                Some(dae_runtime_control::AbsoluteDeadline::at(
                    context.deadline().into_std(),
                )),
            ),
        )
        .await?;
    let mut endpoint = match open_proxy_dns_quic_endpoint(
        &upstream,
        remote,
        bridge.local_addr(),
        &proxy,
        quic_endpoint_transport.as_ref(),
        client_config,
        context,
    ) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            let error = append_bridge_error(error, bridge.as_ref());
            let cleanup = shutdown_proxy_dns_bridge(bridge, context).await;
            return Err(append_cleanup_error(error, cleanup));
        }
    };
    let connection = match connect_proxy_dns_quic_connection(
        &upstream,
        &mut endpoint,
        bridge.local_addr(),
        context,
    )
    .await
    {
        Ok(connection) => connection,
        Err(error) => {
            let error = append_bridge_error(error, bridge.as_ref());
            let cleanup = shutdown_proxy_dns_quic(endpoint, bridge, context).await;
            return Err(append_cleanup_error(error, cleanup));
        }
    };
    let mut state =
        match lock_proxy_dns_quic_forwarder(forwarder, context, "install connection").await {
            Ok(state) => state,
            Err(error) => {
                connection.close(0_u32.into(), b"proxied DoQ install deadline elapsed");
                let cleanup = shutdown_proxy_dns_quic(endpoint, bridge, context).await;
                return Err(append_cleanup_error(error, cleanup));
            }
        };
    if state.closing {
        drop(state);
        connection.close(0_u32.into(), b"proxied DoQ forwarder closing");
        let cleanup = shutdown_proxy_dns_quic(endpoint, bridge, context).await;
        return match cleanup {
            Ok(()) => Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::OwnerAcquire,
                ProxyDnsRequestFailure::Network,
                "proxied DoQ forwarder closed during connect",
            )),
            Err(error) => Err(error),
        };
    }
    state.bridge = Some(bridge);
    state.endpoint = Some(endpoint);
    state.connection = Some(connection.clone());
    Ok(connection)
}

async fn close_cached_proxy_dns_quic(
    forwarder: &Arc<AsyncMutex<ResidentDnsProxyQuicForwarder>>,
    failed_connection_id: usize,
    context: ProxyDnsRequestContext,
) -> Result<(), ProxyDnsRequestError> {
    let (connection, endpoint, bridge) = {
        let mut forwarder =
            lock_proxy_dns_quic_forwarder(forwarder, context, "reset failed connection").await?;
        if forwarder
            .connection
            .as_ref()
            .is_none_or(|connection| connection.stable_id() != failed_connection_id)
        {
            return Ok(());
        }
        (
            forwarder.connection.take(),
            forwarder.endpoint.take(),
            forwarder.bridge.take(),
        )
    };
    if let Some(connection) = connection {
        connection.close(0_u32.into(), b"proxied DoQ connection reset");
    }
    cleanup_proxy_dns_quic_resources(endpoint, bridge, context)
        .await
        .result()
}

async fn lock_proxy_dns_quic_forwarder<'a>(
    forwarder: &'a Arc<AsyncMutex<ResidentDnsProxyQuicForwarder>>,
    context: ProxyDnsRequestContext,
    action: &str,
) -> Result<tokio::sync::MutexGuard<'a, ResidentDnsProxyQuicForwarder>, ProxyDnsRequestError> {
    time::timeout_at(context.deadline(), forwarder.lock())
        .await
        .map_err(|_| {
            ProxyDnsRequestError::new(
                ProxyDnsRequestStage::OwnerAcquire,
                ProxyDnsRequestFailure::Deadline,
                format!("proxied DoQ forwarder {action} absolute deadline elapsed"),
            )
        })
}

pub(in super::super) async fn shutdown_cached_proxy_dns_quic(
    forwarder: Arc<AsyncMutex<ResidentDnsProxyQuicForwarder>>,
    deadline: time::Instant,
) -> Value {
    let state = time::timeout_at(deadline, forwarder.lock()).await;
    let Ok(mut state) = state else {
        return json!({
            "status": "fail",
            "transport": "proxied-doq",
            "error": "proxied DoQ forwarder lock deadline elapsed",
        });
    };
    state.closing = true;
    let _ = state.session_cache.clear();
    let connection = state.connection.take();
    let endpoint = state.endpoint.take();
    let bridge = state.bridge.take();
    drop(state);
    if let Some(connection) = connection {
        connection.close(0_u32.into(), b"proxied DoQ cache shutdown");
    }
    let mut drain = dae_resident_transport::QuicEndpointDrainReport::default();
    if let Some(endpoint) = endpoint {
        endpoint.close(0_u32.into(), b"proxied DoQ cache shutdown");
        drain =
            dae_resident_transport::shutdown_quic_endpoints_until(vec![endpoint], deadline).await;
    }
    let context = ProxyDnsRequestContext::from_deadline(deadline);
    let cleanup = cleanup_proxy_dns_quic_resources(None, bridge, context).await;
    json!({
        "status": if cleanup.failed() || !drain.is_complete() { "fail" } else { "pass" },
        "transport": "proxied-doq",
        "endpointIdle": drain.idle_completed() == drain.requested(),
        "endpointReleased": drain.is_complete(),
        "bridgeCompletion": cleanup.bridge_label(),
        "forced": cleanup.bridge_aborted(),
        "failures": cleanup.failures,
    })
}

fn open_proxy_dns_quic_endpoint(
    upstream: &ResidentDnsUpstream,
    upstream_remote: SocketAddr,
    bridge_remote: SocketAddr,
    binding: &ResidentProxyBinding,
    quic_endpoint_transport: &dyn ResidentDnsQuicEndpointTransport,
    client_config: quinn::ClientConfig,
    context: ProxyDnsRequestContext,
) -> Result<ObservedQuicEndpoint, ProxyDnsRequestError> {
    context.ensure(ProxyDnsRequestStage::OwnerAcquire)?;
    let open_context = managed_dns_quic_endpoint_context(
        QuicEndpointProtocol::DnsOverQuic,
        upstream,
        upstream_remote,
        binding,
    );
    let deadline = dae_runtime_control::AbsoluteDeadline::at(context.deadline().into_std());
    let cancellation = dae_runtime_control::OwnerCancellationSignal::new();
    let mut endpoint = quic_endpoint_transport
        .open_marked_endpoint(
            binding.effective_socket_mark(),
            bridge_remote,
            open_context,
            deadline,
            &cancellation,
        )
        .map_err(|error| {
            ProxyDnsRequestError::new(
                ProxyDnsRequestStage::OwnerAcquire,
                ProxyDnsRequestFailure::Network,
                format!("open proxied DoQ endpoint: {error}"),
            )
        })?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

fn proxy_dns_quic_client_config(
    _forwarder: &ResidentDnsProxyQuicForwarder,
) -> Result<quinn::ClientConfig, ProxyDnsRequestError> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(config) = _forwarder.client_config_override.as_ref() {
        return Ok(config.clone());
    }
    resident_dns_quic_client_config(DNS_DOQ_ALPN, _forwarder.session_cache.clone()).map_err(
        |error| {
            ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Authenticate,
                ProxyDnsRequestFailure::Protocol,
                error,
            )
        },
    )
}

async fn connect_proxy_dns_quic_connection(
    upstream: &ResidentDnsUpstream,
    endpoint: &mut ObservedQuicEndpoint,
    remote: SocketAddr,
    context: ProxyDnsRequestContext,
) -> Result<quinn::Connection, ProxyDnsRequestError> {
    let connecting = match endpoint.connect(remote, &upstream.target.host) {
        Ok(connecting) => connecting,
        Err(error) => {
            endpoint.mark_failed();
            return Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Connect,
                ProxyDnsRequestFailure::Network,
                format!("connect proxied DoQ endpoint: {error}"),
            ));
        }
    };
    let connection = match context
        .run(
            ProxyDnsRequestStage::Authenticate,
            ProxyDnsRequestFailure::Network,
            connecting,
        )
        .await
    {
        Ok(connection) => connection,
        Err(error) => {
            endpoint.mark_failed();
            return Err(error);
        }
    };
    endpoint.mark_ready();
    Ok(connection)
}

async fn forward_proxy_dns_over_quic(
    upstream: &ResidentDnsUpstream,
    connection: &quinn::Connection,
    payload: &[u8],
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ProxyDnsRequestError> {
    let (mut send, mut recv) = context
        .run(
            ProxyDnsRequestStage::OwnerAcquire,
            ProxyDnsRequestFailure::Network,
            connection.open_bi(),
        )
        .await?;
    let query = dns_data_with_zero_id(payload);
    context
        .run(
            ProxyDnsRequestStage::Send,
            ProxyDnsRequestFailure::Network,
            write_dns_tcp_message_async(&mut send, &query),
        )
        .await?;
    send.finish().map_err(|error| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Send,
            ProxyDnsRequestFailure::Network,
            format!("finish proxied DoQ request stream: {error}"),
        )
    })?;
    let response = context
        .run(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Network,
            read_dns_tcp_message_async(&mut recv),
        )
        .await?;
    restore_dns_response_id(payload, &response).map_err(|error| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Protocol,
            format!(
                "forward proxied DNS over QUIC to upstream {} {}: {error}",
                upstream.tag, upstream.target.authority
            ),
        )
    })
}

fn append_bridge_error(
    error: ProxyDnsRequestError,
    bridge: &dyn ResidentDnsProxyUdpBridge,
) -> ProxyDnsRequestError {
    let Some(bridge_error) = bridge.last_error() else {
        return error;
    };
    ProxyDnsRequestError::new(
        error.stage(),
        error.failure(),
        format!("{error}; proxy UDP bridge: {bridge_error}"),
    )
}

async fn shutdown_proxy_dns_bridge(
    bridge: Box<dyn ResidentDnsProxyUdpBridge>,
    context: ProxyDnsRequestContext,
) -> Result<(), ProxyDnsRequestError> {
    cleanup_proxy_dns_quic_resources(None, Some(bridge), context)
        .await
        .result()
}

async fn shutdown_proxy_dns_quic(
    endpoint: ObservedQuicEndpoint,
    bridge: Box<dyn ResidentDnsProxyUdpBridge>,
    context: ProxyDnsRequestContext,
) -> Result<(), ProxyDnsRequestError> {
    cleanup_proxy_dns_quic_resources(Some(endpoint), Some(bridge), context)
        .await
        .result()
}

#[derive(Debug)]
struct ProxyDnsQuicCleanupOutcome {
    endpoint_idle: Option<bool>,
    bridge: Option<ResidentOwnedTaskShutdownCompletion>,
    failures: Vec<String>,
}

impl ProxyDnsQuicCleanupOutcome {
    fn failed(&self) -> bool {
        !self.failures.is_empty()
    }

    fn bridge_aborted(&self) -> bool {
        self.bridge == Some(ResidentOwnedTaskShutdownCompletion::Aborted)
    }

    fn bridge_label(&self) -> &'static str {
        match self.bridge {
            Some(ResidentOwnedTaskShutdownCompletion::Joined) => "joined",
            Some(ResidentOwnedTaskShutdownCompletion::Aborted) => "aborted",
            None => "not-acquired",
        }
    }

    fn result(&self) -> Result<(), ProxyDnsRequestError> {
        if !self.failed() {
            return Ok(());
        }
        let failure = if self.endpoint_idle == Some(false) {
            ProxyDnsRequestFailure::Deadline
        } else {
            ProxyDnsRequestFailure::Network
        };
        Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Cleanup,
            failure,
            format!(
                "proxied DoQ cleanup failed: endpoint_idle={}, bridge={}, failures={}",
                self.endpoint_idle
                    .map_or_else(|| "not-acquired".to_owned(), |idle| idle.to_string()),
                self.bridge_label(),
                self.failures.join("; ")
            ),
        ))
    }
}

async fn cleanup_proxy_dns_quic_resources(
    endpoint: Option<ObservedQuicEndpoint>,
    bridge: Option<Box<dyn ResidentDnsProxyUdpBridge>>,
    context: ProxyDnsRequestContext,
) -> ProxyDnsQuicCleanupOutcome {
    let deadline = context.deadline();
    let task = tokio::spawn(async move {
        let endpoint_idle = match endpoint {
            Some(endpoint) => {
                endpoint.close(0_u32.into(), b"proxied DNS QUIC owner cleanup");
                Some(
                    time::timeout_at(deadline, endpoint.wait_idle())
                        .await
                        .is_ok(),
                )
            }
            None => None,
        };
        let mut failures = Vec::new();
        if endpoint_idle == Some(false) {
            failures.push("endpoint idle absolute deadline elapsed".to_owned());
        }
        let bridge = match bridge {
            Some(bridge) => match bridge.shutdown_and_join_until(deadline).await {
                Ok(completion) => Some(completion),
                Err(error) => {
                    failures.push(error);
                    None
                }
            },
            None => None,
        };
        ProxyDnsQuicCleanupOutcome {
            endpoint_idle,
            bridge,
            failures,
        }
    });
    match task.await {
        Ok(outcome) => outcome,
        Err(error) => ProxyDnsQuicCleanupOutcome {
            endpoint_idle: None,
            bridge: None,
            failures: vec![format!("join proxied DoQ cleanup task: {error}")],
        },
    }
}

pub fn append_cleanup_error(
    error: ProxyDnsRequestError,
    cleanup: Result<(), ProxyDnsRequestError>,
) -> ProxyDnsRequestError {
    let Err(cleanup_error) = cleanup else {
        return error;
    };
    ProxyDnsRequestError::new(
        cleanup_error.stage(),
        cleanup_error.failure(),
        format!("exchange_error={error}; cleanup_error={cleanup_error}"),
    )
}
