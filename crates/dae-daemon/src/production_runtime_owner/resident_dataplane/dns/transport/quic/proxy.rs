use super::*;

pub(super) async fn forward_dns_quic_to_proxy_async(
    upstream: &ResidentDnsUpstream,
    remote: SocketAddr,
    payload: &[u8],
    proxy: Arc<ResidentProxyPlan>,
    hysteria2_owner_registry: Hysteria2OwnerRegistryHandle,
    tuic_owner_registry: TuicOwnerRegistryHandle,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ProxyDnsRequestError> {
    let generation = proxy.execution_plan().runtime_generation();
    scope_quic_endpoint_observation(
        QuicEndpointCallerClass::ManagedDns,
        Some(generation),
        forward_dns_quic_to_proxy_with_context(
            upstream,
            remote,
            payload,
            proxy,
            hysteria2_owner_registry,
            tuic_owner_registry,
            context,
        ),
    )
    .await
}

async fn forward_dns_quic_to_proxy_with_context(
    upstream: &ResidentDnsUpstream,
    remote: SocketAddr,
    payload: &[u8],
    proxy: Arc<ResidentProxyPlan>,
    hysteria2_owner_registry: Hysteria2OwnerRegistryHandle,
    tuic_owner_registry: TuicOwnerRegistryHandle,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ProxyDnsRequestError> {
    let bridge = context
        .run(
            ProxyDnsRequestStage::OwnerAcquire,
            ProxyDnsRequestFailure::Network,
            open_resident_proxy_udp_bridge_async(
                Arc::clone(&proxy),
                remote,
                Some(hysteria2_owner_registry),
                Some(tuic_owner_registry),
                Some(dae_runtime_control::AbsoluteDeadline::at(
                    context.deadline().into_std(),
                )),
            ),
        )
        .await?;
    let mut endpoint = match open_proxy_dns_quic_endpoint(
        upstream,
        remote,
        bridge.local_addr(),
        &proxy,
        context,
    ) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            let error = append_bridge_error(error, &bridge);
            let cleanup = shutdown_proxy_dns_bridge(bridge, context).await;
            return Err(append_cleanup_error(error, cleanup));
        }
    };
    let connection = match connect_proxy_dns_quic_connection(
        upstream,
        &mut endpoint,
        bridge.local_addr(),
        context,
    )
    .await
    {
        Ok(connection) => connection,
        Err(error) => {
            let error = append_bridge_error(error, &bridge);
            let cleanup = shutdown_proxy_dns_quic(endpoint, bridge, context).await;
            return Err(append_cleanup_error(error, cleanup));
        }
    };
    let result = forward_proxy_dns_over_quic(upstream, &connection, payload, context).await;
    connection.close(0_u32.into(), b"dns-query done");
    drop(connection);
    let cleanup = shutdown_proxy_dns_quic(endpoint, bridge, context).await;
    match (result, cleanup) {
        (Ok(response), Ok(())) => Ok(response),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), cleanup) => Err(append_cleanup_error(error, cleanup)),
    }
}

fn open_proxy_dns_quic_endpoint(
    upstream: &ResidentDnsUpstream,
    upstream_remote: SocketAddr,
    bridge_remote: SocketAddr,
    proxy: &ResidentProxyPlan,
    context: ProxyDnsRequestContext,
) -> Result<ObservedQuicEndpoint, ProxyDnsRequestError> {
    context.ensure(ProxyDnsRequestStage::OwnerAcquire)?;
    let config = resident_dns_quic_client_config(DNS_DOQ_ALPN).map_err(|error| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Authenticate,
            ProxyDnsRequestFailure::Protocol,
            error,
        )
    })?;
    let open_context = managed_dns_quic_endpoint_context(
        QuicEndpointProtocol::DnsOverQuic,
        upstream,
        upstream_remote,
        proxy,
    );
    let deadline = dae_runtime_control::AbsoluteDeadline::at(context.deadline().into_std());
    let cancellation = dae_runtime_control::OwnerCancellationSignal::new();
    let mut endpoint = open_marked_quic_endpoint_for_remote(
        proxy.mark,
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
    endpoint.set_default_client_config(config);
    Ok(endpoint)
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
    bridge: &ResidentProxyUdpBridge,
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
    bridge: ResidentProxyUdpBridge,
    context: ProxyDnsRequestContext,
) -> Result<(), ProxyDnsRequestError> {
    run_proxy_dns_cleanup(context, async move { bridge.shutdown_and_join().await }).await
}

async fn shutdown_proxy_dns_quic(
    endpoint: ObservedQuicEndpoint,
    bridge: ResidentProxyUdpBridge,
    context: ProxyDnsRequestContext,
) -> Result<(), ProxyDnsRequestError> {
    run_proxy_dns_cleanup(context, async move {
        endpoint.close(0_u32.into(), b"dns-query done");
        endpoint.wait_idle().await;
        bridge.shutdown_and_join().await
    })
    .await
}

async fn run_proxy_dns_cleanup<F>(
    context: ProxyDnsRequestContext,
    cleanup: F,
) -> Result<(), ProxyDnsRequestError>
where
    F: std::future::Future<Output = Result<(), String>> + Send + 'static,
{
    let mut task = tokio::spawn(cleanup);
    match time::timeout_at(context.deadline(), &mut task).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(error))) => Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Cleanup,
            ProxyDnsRequestFailure::Network,
            error,
        )),
        Ok(Err(error)) => Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Cleanup,
            ProxyDnsRequestFailure::Network,
            format!("join proxy DNS cleanup task: {error}"),
        )),
        Err(_) => {
            drop(task);
            Err(ProxyDnsRequestError::deadline(
                ProxyDnsRequestStage::Cleanup,
            ))
        }
    }
}

fn append_cleanup_error(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expired_deadline_detaches_but_does_not_cancel_cleanup() {
        let (release, wait_for_release) = tokio::sync::oneshot::channel();
        let (finished, wait_for_finish) = tokio::sync::oneshot::channel();
        let context = ProxyDnsRequestContext::from_deadline(time::Instant::now());
        let error = run_proxy_dns_cleanup(context, async move {
            let _ = wait_for_release.await;
            let _ = finished.send(());
            Ok(())
        })
        .await
        .unwrap_err();

        assert_eq!(error.stage(), ProxyDnsRequestStage::Cleanup);
        assert_eq!(error.failure(), ProxyDnsRequestFailure::Deadline);
        release.send(()).unwrap();
        time::timeout(std::time::Duration::from_secs(1), wait_for_finish)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn cleanup_failure_remains_typed() {
        let context = ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(1));
        let error = run_proxy_dns_cleanup(context, async { Err("fixture cleanup failure".into()) })
            .await
            .unwrap_err();

        assert_eq!(error.stage(), ProxyDnsRequestStage::Cleanup);
        assert_eq!(error.failure(), ProxyDnsRequestFailure::Network);
        assert!(error.to_string().contains("fixture cleanup failure"));
    }

    #[test]
    fn cleanup_uncertainty_is_terminal_when_the_exchange_also_failed() {
        let exchange_error = ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Network,
            "fixture exchange failure",
        );
        let cleanup_error = ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Cleanup,
            ProxyDnsRequestFailure::Network,
            "fixture cleanup failure",
        );
        let error = append_cleanup_error(exchange_error, Err(cleanup_error));

        assert_eq!(error.stage(), ProxyDnsRequestStage::Cleanup);
        assert_eq!(error.failure(), ProxyDnsRequestFailure::Network);
        assert!(error.to_string().contains("fixture exchange failure"));
        assert!(error.to_string().contains("cleanup_error="));
    }
}
