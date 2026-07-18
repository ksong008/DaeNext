use super::*;

pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentConnectedQuicEndpoint {
    pub(in crate::production_runtime_owner::resident_dataplane) remote: SocketAddr,
    pub(in crate::production_runtime_owner::resident_dataplane) endpoint: ObservedQuicEndpoint,
    pub(in crate::production_runtime_owner::resident_dataplane) connection: quinn::Connection,
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn open_hysteria2_quic_connection_candidates_async(
    proxy: &ResidentProxyPlan,
    mark: u32,
    obfs: &ResidentHysteria2ObfsPlan,
    port_hop_ports: &[u16],
    tls_identity: &dae_outbound::hysteria2::Hysteria2TlsIdentity,
    deadline: dae_runtime_control::AbsoluteDeadline,
    caller: QuicEndpointCallerClass,
) -> Result<ResidentConnectedQuicEndpoint, String> {
    let candidates =
        resolve_hysteria2_quic_remote_candidates_async(proxy, port_hop_ports, deadline).await?;
    let client_config = build_hysteria2_runtime_client_config_with_udp_overhead(
        tls_identity,
        obfs.udp_packet_overhead(),
    )
    .map_err(|err| format!("build Hysteria2 QUIC client config: {err}"))?;
    let endpoint_context = QuicEndpointOpenContext::for_proxy(
        QuicEndpointProtocol::Hysteria2,
        caller,
        proxy,
        QuicEndpointIdentityRole::ProtocolCarrier,
        &[],
    );
    let (remote, endpoint, connection) = connect_quic_endpoint_candidates_async(
        &candidates,
        tls_identity.server_name(),
        deadline,
        "connect Hysteria2 QUIC endpoint",
        |remote, deadline, cancellation| {
            let mut endpoint = open_marked_hysteria2_quic_endpoint_for_remote(
                mark,
                obfs,
                remote,
                endpoint_context.clone(),
                deadline,
                cancellation,
            )?;
            endpoint.set_default_client_config(client_config.clone());
            Ok(endpoint)
        },
    )
    .await?;
    Ok(ResidentConnectedQuicEndpoint {
        remote,
        endpoint,
        connection,
    })
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn open_tuic_quic_connection_candidates_async(
    proxy: &ResidentProxyPlan,
    mark: u32,
    alpn: &[String],
    allow_insecure: bool,
    timeout: Duration,
    caller: QuicEndpointCallerClass,
) -> Result<ResidentConnectedQuicEndpoint, String> {
    let deadline = dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), timeout);
    let candidates = resolve_proxy_udp_addr_candidates_async(proxy, deadline).await?;
    let client_config = build_tuic_runtime_client_config(alpn, allow_insecure)
        .map_err(|err| format!("build TUIC QUIC client config: {err}"))?;
    let endpoint_context = QuicEndpointOpenContext::for_proxy(
        QuicEndpointProtocol::Tuic,
        caller,
        proxy,
        QuicEndpointIdentityRole::ProtocolCarrier,
        &[],
    );
    let (remote, endpoint, connection) = connect_quic_endpoint_candidates_async(
        &candidates,
        &proxy.server_name,
        deadline,
        "connect TUIC QUIC endpoint",
        |remote, deadline, cancellation| {
            let mut endpoint = open_marked_quic_endpoint_for_remote(
                mark,
                remote,
                endpoint_context.clone(),
                deadline,
                cancellation,
            )?;
            endpoint.set_default_client_config(client_config.clone());
            Ok(endpoint)
        },
    )
    .await?;
    Ok(ResidentConnectedQuicEndpoint {
        remote,
        endpoint,
        connection,
    })
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn open_juicity_quic_connection_candidates_async(
    proxy: &ResidentProxyPlan,
    mark: u32,
    allow_insecure: bool,
    pinned_certchain_sha256: &str,
    timeout: Duration,
    caller: QuicEndpointCallerClass,
) -> Result<ResidentConnectedQuicEndpoint, String> {
    let deadline = dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), timeout);
    let candidates = resolve_proxy_udp_addr_candidates_async(proxy, deadline).await?;
    let client_config =
        build_juicity_runtime_client_config(allow_insecure, pinned_certchain_sha256)
            .map_err(|err| format!("build Juicity QUIC client config: {err}"))?;
    let endpoint_context = QuicEndpointOpenContext::for_proxy(
        QuicEndpointProtocol::Juicity,
        caller,
        proxy,
        QuicEndpointIdentityRole::ProtocolCarrier,
        &[],
    );
    let (remote, endpoint, connection) = connect_quic_endpoint_candidates_async(
        &candidates,
        &proxy.server_name,
        deadline,
        "connect Juicity QUIC endpoint",
        |remote, deadline, cancellation| {
            let mut endpoint = open_marked_quic_endpoint_for_remote(
                mark,
                remote,
                endpoint_context.clone(),
                deadline,
                cancellation,
            )?;
            endpoint.set_default_client_config(client_config.clone());
            Ok(endpoint)
        },
    )
    .await?;
    Ok(ResidentConnectedQuicEndpoint {
        remote,
        endpoint,
        connection,
    })
}
