use super::lifecycle::{ProxiedDoh3CleanupDeadline, ProxiedDoh3CleanupOutcome};
use super::request::forward_proxied_dns_h3_request;
use super::resources::ProxiedDoh3Resources;
use super::*;
use serde_json::{Value, json};

pub(super) async fn forward_cached_proxy_dns_h3(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    forwarder: Arc<AsyncMutex<ResidentDnsProxyH3Forwarder>>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ProxyDnsRequestError> {
    let permits = {
        let forwarder =
            lock_proxy_dns_h3_forwarder(&forwarder, context, "read stream permits").await?;
        Arc::clone(&forwarder.permits)
    };
    let _permit = context
        .run(
            ProxyDnsRequestStage::OwnerAcquire,
            ProxyDnsRequestFailure::Capacity,
            permits.acquire_owned(),
        )
        .await?;
    let (mut client, connection_id) = cached_proxy_dns_h3_client(&forwarder, context).await?;
    match forward_proxied_dns_h3_request(upstream, payload, &mut client, context).await {
        Ok(response) => Ok(response),
        Err(first_error) => {
            let cleanup = reset_cached_proxy_dns_h3(&forwarder, connection_id, context).await?;
            if cleanup.failed() {
                return Err(ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::Cleanup,
                    ProxyDnsRequestFailure::Network,
                    format!("exchange_error={first_error}; cleanup_error={cleanup}"),
                ));
            }
            context.ensure(ProxyDnsRequestStage::Retry)?;
            let (mut client, _) = cached_proxy_dns_h3_client(&forwarder, context).await?;
            forward_proxied_dns_h3_request(upstream, payload, &mut client, context)
                .await
                .map_err(|retry_error| {
                    ProxyDnsRequestError::new(
                        retry_error.stage(),
                        retry_error.failure(),
                        format!(
                            "proxied DoH3 cached retry failed after {first_error}: {retry_error}"
                        ),
                    )
                })
        }
    }
}

async fn cached_proxy_dns_h3_client(
    forwarder: &Arc<AsyncMutex<ResidentDnsProxyH3Forwarder>>,
    context: ProxyDnsRequestContext,
) -> Result<(h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>, usize), ProxyDnsRequestError> {
    let task_executor = {
        let forwarder = lock_proxy_dns_h3_forwarder(forwarder, context, "read client").await?;
        if forwarder.closing {
            return Err(closing_error());
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
            open_cached_proxy_dns_h3_client(&task_forwarder, context).await
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

async fn open_cached_proxy_dns_h3_client(
    forwarder: &Arc<AsyncMutex<ResidentDnsProxyH3Forwarder>>,
    context: ProxyDnsRequestContext,
) -> Result<(h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>, usize), ProxyDnsRequestError> {
    let open_lock = {
        let forwarder = lock_proxy_dns_h3_forwarder(forwarder, context, "read open lock").await?;
        Arc::clone(&forwarder.open_lock)
    };
    context.ensure(ProxyDnsRequestStage::OwnerAcquire)?;
    let _open_guard = time::timeout_at(context.deadline(), open_lock.lock())
        .await
        .map_err(|_| ProxyDnsRequestError::deadline(ProxyDnsRequestStage::OwnerAcquire))?;
    {
        let forwarder = lock_proxy_dns_h3_forwarder(forwarder, context, "recheck client").await?;
        if forwarder.closing {
            return Err(closing_error());
        }
        if let (Some(client), Some(connection)) =
            (forwarder.client.as_ref(), forwarder.connection.as_ref())
        {
            return Ok((client.clone(), connection.stable_id()));
        }
    }
    let (upstream, remote, proxy, owners, metrics, client_config) = {
        let forwarder =
            lock_proxy_dns_h3_forwarder(forwarder, context, "read endpoint plan").await?;
        (
            forwarder.upstream.clone(),
            forwarder.remote,
            Arc::clone(&forwarder.proxy),
            forwarder.owners.clone(),
            Arc::clone(&forwarder.metrics),
            proxy_dns_h3_client_config(&forwarder)?,
        )
    };
    let bridge = context
        .run(
            ProxyDnsRequestStage::OwnerAcquire,
            ProxyDnsRequestFailure::Network,
            open_resident_proxy_udp_bridge_async(
                Arc::clone(&proxy),
                remote,
                owners.hysteria2(),
                owners.tuic(),
                owners.juicity(),
                owners.anytls(),
                Some(dae_runtime_control::AbsoluteDeadline::at(
                    context.deadline().into_std(),
                )),
            ),
        )
        .await?;
    let bridge_addr = bridge.local_addr();
    context.ensure(ProxyDnsRequestStage::OwnerAcquire)?;
    let open_context = managed_dns_quic_endpoint_context(
        QuicEndpointProtocol::DnsOverHttp3,
        &upstream,
        remote,
        &proxy,
    );
    let deadline = dae_runtime_control::AbsoluteDeadline::at(context.deadline().into_std());
    let cancellation = dae_runtime_control::OwnerCancellationSignal::new();
    let mut endpoint = match open_marked_quic_endpoint_for_remote(
        proxy.mark,
        bridge_addr,
        open_context,
        deadline,
        &cancellation,
    ) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            let mut resources = ProxiedDoh3Resources {
                bridge: Some(bridge),
                ..ProxiedDoh3Resources::default()
            };
            let cleanup = cleanup_proxied_doh3_resources(
                &mut resources,
                ProxiedDoh3CleanupDeadline::from_instant(context.deadline()),
            )
            .await;
            cleanup.record_metrics(&metrics);
            return Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::OwnerAcquire,
                ProxyDnsRequestFailure::Network,
                format!("open proxied DoH3 endpoint: {error}; cleanup={cleanup}"),
            ));
        }
    };
    endpoint.set_default_client_config(client_config);
    let connecting = endpoint
        .connect(bridge_addr, &upstream.target.host)
        .map_err(|error| {
            endpoint.mark_failed();
            ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Connect,
                ProxyDnsRequestFailure::Network,
                format!("connect proxied DoH3 endpoint: {error}"),
            )
        });
    let connecting = match connecting {
        Ok(connecting) => connecting,
        Err(error) => {
            let mut resources = ProxiedDoh3Resources {
                bridge: Some(bridge),
                endpoint: Some(endpoint),
                ..ProxiedDoh3Resources::default()
            };
            let cleanup = cleanup_proxied_doh3_resources(
                &mut resources,
                ProxiedDoh3CleanupDeadline::from_instant(context.deadline()),
            )
            .await;
            cleanup.record_metrics(&metrics);
            return Err(ProxyDnsRequestError::new(
                error.stage(),
                error.failure(),
                format!("{error}; cleanup={cleanup}"),
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
            let mut resources = ProxiedDoh3Resources {
                bridge: Some(bridge),
                endpoint: Some(endpoint),
                ..ProxiedDoh3Resources::default()
            };
            let cleanup = cleanup_proxied_doh3_resources(
                &mut resources,
                ProxiedDoh3CleanupDeadline::from_instant(context.deadline()),
            )
            .await;
            cleanup.record_metrics(&metrics);
            return Err(ProxyDnsRequestError::new(
                error.stage(),
                error.failure(),
                format!("{error}; cleanup={cleanup}"),
            ));
        }
    };
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut driver, client) = match context
        .run(
            ProxyDnsRequestStage::Authenticate,
            ProxyDnsRequestFailure::Network,
            h3::client::new(h3_connection),
        )
        .await
    {
        Ok(client) => client,
        Err(error) => {
            endpoint.mark_failed();
            let mut resources = ProxiedDoh3Resources {
                bridge: Some(bridge),
                endpoint: Some(endpoint),
                connection: Some(connection),
                ..ProxiedDoh3Resources::default()
            };
            let cleanup = cleanup_proxied_doh3_resources(
                &mut resources,
                ProxiedDoh3CleanupDeadline::from_instant(context.deadline()),
            )
            .await;
            cleanup.record_metrics(&metrics);
            return Err(ProxyDnsRequestError::new(
                error.stage(),
                error.failure(),
                format!("{error}; cleanup={cleanup}"),
            ));
        }
    };
    endpoint.mark_ready();
    let connection_id = connection.stable_id();
    let driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let mut state = match lock_proxy_dns_h3_forwarder(forwarder, context, "install client").await {
        Ok(state) => state,
        Err(error) => {
            let mut resources = ProxiedDoh3Resources {
                bridge: Some(bridge),
                endpoint: Some(endpoint),
                connection: Some(connection),
                client: Some(client),
                driver_task: Some(driver_task),
            };
            let cleanup = cleanup_proxied_doh3_resources(
                &mut resources,
                ProxiedDoh3CleanupDeadline::from_instant(context.deadline()),
            )
            .await;
            cleanup.record_metrics(&metrics);
            return Err(ProxyDnsRequestError::new(
                error.stage(),
                error.failure(),
                format!("{error}; cleanup={cleanup}"),
            ));
        }
    };
    if state.closing {
        let metrics = Arc::clone(&state.metrics);
        drop(state);
        let mut resources = ProxiedDoh3Resources {
            bridge: Some(bridge),
            endpoint: Some(endpoint),
            connection: Some(connection),
            client: Some(client),
            driver_task: Some(driver_task),
        };
        let cleanup = cleanup_proxied_doh3_resources(
            &mut resources,
            ProxiedDoh3CleanupDeadline::from_instant(context.deadline()),
        )
        .await;
        cleanup.record_metrics(&metrics);
        return Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::OwnerAcquire,
            ProxyDnsRequestFailure::Network,
            format!("proxied DoH3 forwarder closed during connect; cleanup={cleanup}"),
        ));
    }
    state.bridge = Some(bridge);
    state.endpoint = Some(endpoint);
    state.connection = Some(connection);
    state.client = Some(client.clone());
    state.driver_task = Some(driver_task);
    Ok((client, connection_id))
}

fn closing_error() -> ProxyDnsRequestError {
    ProxyDnsRequestError::new(
        ProxyDnsRequestStage::OwnerAcquire,
        ProxyDnsRequestFailure::Network,
        "proxied DoH3 forwarder is closing",
    )
}

fn proxy_dns_h3_client_config(
    _forwarder: &ResidentDnsProxyH3Forwarder,
) -> Result<quinn::ClientConfig, ProxyDnsRequestError> {
    #[cfg(test)]
    if let Some(config) = _forwarder.client_config_override.as_ref() {
        return Ok(config.clone());
    }
    resident_dns_quic_client_config(DNS_DOH3_ALPN).map_err(|error| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Authenticate,
            ProxyDnsRequestFailure::Protocol,
            error,
        )
    })
}

async fn reset_cached_proxy_dns_h3(
    forwarder: &Arc<AsyncMutex<ResidentDnsProxyH3Forwarder>>,
    failed_connection_id: usize,
    context: ProxyDnsRequestContext,
) -> Result<ProxiedDoh3CleanupOutcome, ProxyDnsRequestError> {
    let (mut resources, metrics) = {
        let mut forwarder =
            lock_proxy_dns_h3_forwarder(forwarder, context, "reset failed client").await?;
        if forwarder
            .connection
            .as_ref()
            .is_none_or(|connection| connection.stable_id() != failed_connection_id)
        {
            return Ok(ProxiedDoh3CleanupOutcome {
                deadline: ProxiedDoh3CleanupDeadline::from_instant(context.deadline()),
                client_discarded: false,
                connection_closed: false,
                endpoint: None,
                driver: None,
                bridge: None,
                failures: Vec::new(),
            });
        }
        (
            take_resources(&mut forwarder),
            Arc::clone(&forwarder.metrics),
        )
    };
    let outcome = cleanup_proxied_doh3_resources(
        &mut resources,
        ProxiedDoh3CleanupDeadline::from_instant(context.deadline()),
    )
    .await;
    outcome.record_metrics(&metrics);
    Ok(outcome)
}

async fn lock_proxy_dns_h3_forwarder<'a>(
    forwarder: &'a Arc<AsyncMutex<ResidentDnsProxyH3Forwarder>>,
    context: ProxyDnsRequestContext,
    action: &str,
) -> Result<tokio::sync::MutexGuard<'a, ResidentDnsProxyH3Forwarder>, ProxyDnsRequestError> {
    time::timeout_at(context.deadline(), forwarder.lock())
        .await
        .map_err(|_| {
            ProxyDnsRequestError::new(
                ProxyDnsRequestStage::OwnerAcquire,
                ProxyDnsRequestFailure::Deadline,
                format!("proxied DoH3 forwarder {action} absolute deadline elapsed"),
            )
        })
}

pub(in super::super::super) async fn shutdown_cached_proxy_dns_h3(
    forwarder: Arc<AsyncMutex<ResidentDnsProxyH3Forwarder>>,
    deadline: time::Instant,
) -> Value {
    let state = time::timeout_at(deadline, forwarder.lock()).await;
    let Ok(mut state) = state else {
        return json!({
            "status": "fail",
            "transport": "proxied-doh3",
            "error": "proxied DoH3 forwarder lock deadline elapsed",
        });
    };
    state.closing = true;
    let mut resources = take_resources(&mut state);
    let metrics = Arc::clone(&state.metrics);
    drop(state);
    let outcome = cleanup_proxied_doh3_resources(
        &mut resources,
        ProxiedDoh3CleanupDeadline::from_instant(deadline),
    )
    .await;
    outcome.record_metrics(&metrics);
    json!({
        "status": if outcome.failed() { "fail" } else { "pass" },
        "transport": "proxied-doh3",
        "cleanup": outcome.to_string(),
        "forced": outcome.has_forced_completion(),
        "failures": outcome.failures,
    })
}

fn take_resources(forwarder: &mut ResidentDnsProxyH3Forwarder) -> ProxiedDoh3Resources {
    ProxiedDoh3Resources {
        bridge: forwarder.bridge.take(),
        endpoint: forwarder.endpoint.take(),
        connection: forwarder.connection.take(),
        client: forwarder.client.take(),
        driver_task: forwarder.driver_task.take(),
    }
}

async fn cleanup_proxied_doh3_resources(
    resources: &mut ProxiedDoh3Resources,
    deadline: ProxiedDoh3CleanupDeadline,
) -> ProxiedDoh3CleanupOutcome {
    let client_discarded = resources.discard_client();
    let connection_closed = resources.close_connection();
    let endpoint = resources.close_endpoint_and_wait_idle(deadline).await;
    let mut failures = Vec::new();
    let driver = match resources.finish_driver(deadline).await {
        Ok(driver) => driver,
        Err(error) => {
            failures.push(error);
            None
        }
    };
    let bridge = match resources.shutdown_bridge(deadline).await {
        Ok(bridge) => bridge,
        Err(error) => {
            failures.push(error);
            None
        }
    };
    ProxiedDoh3CleanupOutcome {
        deadline,
        client_discarded,
        connection_closed,
        endpoint,
        driver,
        bridge,
        failures,
    }
}
