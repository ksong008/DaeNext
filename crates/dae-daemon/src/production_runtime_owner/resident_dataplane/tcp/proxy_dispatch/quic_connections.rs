use super::*;

pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentConnectedQuicEndpoint {
    pub(in crate::production_runtime_owner::resident_dataplane) remote: SocketAddr,
    pub(in crate::production_runtime_owner::resident_dataplane) endpoint: ObservedQuicEndpoint,
    pub(in crate::production_runtime_owner::resident_dataplane) connection: quinn::Connection,
}

pub(in crate::production_runtime_owner::resident_dataplane) struct Hysteria2QuicConnectionRequest<
    'a,
> {
    pub(in crate::production_runtime_owner::resident_dataplane) proxy: &'a ResidentProxyPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane) obfs: &'a ResidentHysteria2ObfsPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) port_hop_ports: &'a [u16],
    pub(in crate::production_runtime_owner::resident_dataplane) port_hop_interval: Duration,
    pub(in crate::production_runtime_owner::resident_dataplane) tls_identity:
        &'a dae_outbound::hysteria2::Hysteria2TlsIdentity,
    pub(in crate::production_runtime_owner::resident_dataplane) congestion:
        Arc<Hysteria2CongestionRuntime>,
    pub(in crate::production_runtime_owner::resident_dataplane) resources:
        Hysteria2OwnerResourceProfile,
    pub(in crate::production_runtime_owner::resident_dataplane) port_hopping_metrics:
        Arc<Hysteria2PortHoppingMetrics>,
    pub(in crate::production_runtime_owner::resident_dataplane) caller: QuicEndpointCallerClass,
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn open_hysteria2_quic_connection_candidates_async(
    request: Hysteria2QuicConnectionRequest<'_>,
    deadline: dae_runtime_control::AbsoluteDeadline,
) -> Result<ResidentConnectedQuicEndpoint, Hysteria2Failure> {
    let Hysteria2QuicConnectionRequest {
        proxy,
        mark,
        obfs,
        port_hop_ports,
        port_hop_interval,
        tls_identity,
        congestion,
        resources,
        port_hopping_metrics,
        caller,
    } = request;
    let candidates = resolve_hysteria2_quic_remote_candidates_async(
        proxy,
        port_hop_ports,
        resources.port_hop_resolved_candidate_limit(),
        deadline,
    )
    .await
    .map_err(|_| {
        Hysteria2Failure::new(
            Hysteria2FailureClass::NetworkAddress,
            "hysteria2-resolve",
            "resolve Hysteria2 server address failed",
        )
    })?;
    let client_config = build_hysteria2_runtime_client_config_with_congestion(
        tls_identity,
        obfs.udp_packet_overhead(),
        Some(congestion),
    )
    .map_err(|_| {
        Hysteria2Failure::new(
            Hysteria2FailureClass::Configuration,
            "hysteria2-client-configuration",
            "build Hysteria2 QUIC client configuration failed",
        )
    })?;
    let endpoint_context = QuicEndpointOpenContext::for_proxy(
        QuicEndpointProtocol::Hysteria2,
        caller,
        proxy,
        QuicEndpointIdentityRole::ProtocolCarrier,
        &[],
    );
    let (remote, endpoint, connection) = connect_hysteria2_quic_endpoint_candidates_async(
        &candidates,
        tls_identity.server_name(),
        tls_identity.policy().has_leaf_certificate_pin(),
        tls_identity.policy().requires_webpki(),
        deadline,
        |remote, deadline, cancellation| {
            let port_hopping = if port_hop_ports.is_empty() {
                None
            } else {
                let remotes = candidates
                    .iter()
                    .copied()
                    .filter(|candidate| candidate.is_ipv4() == remote.is_ipv4())
                    .collect::<Vec<_>>();
                Some(
                    Hysteria2PortHoppingRuntimeConfig::new(
                        remotes,
                        port_hop_interval,
                        mark,
                        resources.port_hop_transition_socket_limit(),
                        Arc::clone(&port_hopping_metrics),
                    )
                    .map_err(|_| {
                        Hysteria2Failure::new(
                            Hysteria2FailureClass::Configuration,
                            "hysteria2-port-hopping-configuration",
                            "build Hysteria2 port-hopping configuration failed",
                        )
                    })?,
                )
            };
            let mut endpoint = open_marked_hysteria2_quic_endpoint_for_remote(
                mark,
                obfs,
                port_hopping,
                remote,
                endpoint_context.clone(),
                deadline,
                cancellation,
            )
            .map_err(|_| {
                Hysteria2Failure::new(
                    Hysteria2FailureClass::Resource,
                    "hysteria2-endpoint-open",
                    "Hysteria2 QUIC Endpoint resources are unavailable",
                )
            })?;
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
    congestion: TuicCongestionController,
    deadline: dae_runtime_control::AbsoluteDeadline,
    caller: QuicEndpointCallerClass,
) -> Result<ResidentConnectedQuicEndpoint, String> {
    let candidates = resolve_proxy_udp_addr_candidates_async(proxy, deadline).await?;
    let client_config =
        build_tuic_runtime_client_config_with_congestion(alpn, allow_insecure, congestion)
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
    deadline: dae_runtime_control::AbsoluteDeadline,
    caller: QuicEndpointCallerClass,
) -> Result<ResidentConnectedQuicEndpoint, String> {
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
