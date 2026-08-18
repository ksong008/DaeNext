use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dae_outbound::hysteria2::{
    Hysteria2CongestionRuntime, build_hysteria2_runtime_client_config_with_session_cache,
};
use dae_outbound::tuic::{
    TuicCongestionController, build_tuic_runtime_client_config_with_session_cache,
};
use dae_resident_core::Hysteria2OwnerResourceProfile;
use dae_resident_plan::{ResidentHysteria2ObfsPlan, ResidentProxyBinding, ResidentProxyPlan};
use dae_runtime_control::OwnerGeneration;

use crate::hysteria2_failure::{Hysteria2Failure, Hysteria2FailureClass};
use crate::hysteria2_port_hopping::{
    Hysteria2PortHoppingMetrics, Hysteria2PortHoppingRuntimeConfig,
};
use crate::quic_transport::{
    Hysteria2ConnectionFailure, connect_hysteria2_quic_endpoint_candidates_async,
    connect_quic_endpoint_candidates_async, hysteria2_initial_remote_candidates,
    open_marked_hysteria2_quic_endpoint_for_remote, resolve_hysteria2_quic_remote_plan_async,
    resolve_proxy_udp_addr_candidates_async,
};
use crate::{
    ObservedQuicEndpoint, QuicEndpointCallerClass, QuicEndpointIdentityRole,
    QuicEndpointOpenContext, QuicEndpointOpenError, QuicEndpointProtocol,
    open_marked_quic_endpoint_for_remote,
};

fn quic_endpoint_context_for_proxy(
    protocol: QuicEndpointProtocol,
    default_caller: QuicEndpointCallerClass,
    default_generation: OwnerGeneration,
    proxy: &ResidentProxyPlan,
    role: QuicEndpointIdentityRole,
    additional_identity: &[&[u8]],
) -> QuicEndpointOpenContext {
    let mut identity_parts = Vec::new();
    let mut current = Some(proxy);
    while let Some(node) = current {
        identity_parts.push(node.graph_id.as_bytes());
        identity_parts.push(node.graph_link_hash.as_bytes());
        current = node.chain_parent.as_deref();
    }
    identity_parts.extend_from_slice(additional_identity);
    QuicEndpointOpenContext::from_identity_parts(
        protocol,
        default_caller,
        default_generation,
        role,
        &identity_parts,
    )
}

pub(crate) struct ResidentConnectedQuicEndpoint {
    pub(crate) remote: SocketAddr,
    pub(crate) endpoint: ObservedQuicEndpoint,
    pub(crate) connection: quinn::Connection,
}

pub(crate) struct Hysteria2QuicConnectionRequest<'a> {
    pub(crate) proxy: &'a ResidentProxyPlan,
    pub(crate) generation: OwnerGeneration,
    pub(crate) mark: u32,
    pub(crate) obfs: &'a ResidentHysteria2ObfsPlan,
    pub(crate) port_hop_ports: &'a [u16],
    pub(crate) port_hop_interval: Duration,
    pub(crate) tls_identity: &'a dae_outbound::hysteria2::Hysteria2TlsIdentity,
    pub(crate) congestion: Arc<Hysteria2CongestionRuntime>,
    pub(crate) resources: Hysteria2OwnerResourceProfile,
    pub(crate) port_hopping_metrics: Arc<Hysteria2PortHoppingMetrics>,
    pub(crate) caller: QuicEndpointCallerClass,
    pub(crate) cancellation: &'a dae_runtime_control::OwnerCancellationSignal,
    pub(crate) session_cache:
        Option<dae_outbound::shared_transport::boring_quic::BoringQuicSessionCache>,
}

pub(crate) async fn open_hysteria2_quic_connection_candidates_async(
    request: Hysteria2QuicConnectionRequest<'_>,
    deadline: dae_runtime_control::AbsoluteDeadline,
) -> Result<ResidentConnectedQuicEndpoint, Hysteria2ConnectionFailure> {
    let Hysteria2QuicConnectionRequest {
        proxy,
        generation,
        mark,
        obfs,
        port_hop_ports,
        port_hop_interval,
        tls_identity,
        congestion,
        resources,
        port_hopping_metrics,
        caller,
        cancellation,
        session_cache,
    } = request;
    let remote_plan = resolve_hysteria2_quic_remote_plan_async(proxy, port_hop_ports, deadline)
        .await
        .map_err(|_| {
            Hysteria2ConnectionFailure::without_endpoint(Hysteria2Failure::new(
                Hysteria2FailureClass::NetworkAddress,
                "hysteria2-resolve",
                "resolve Hysteria2 server address failed",
            ))
        })?;
    let candidates = hysteria2_initial_remote_candidates(
        &remote_plan,
        resources.initial_connect_attempt_limit(),
    )
    .map_err(|_| {
        Hysteria2ConnectionFailure::without_endpoint(Hysteria2Failure::new(
            Hysteria2FailureClass::Configuration,
            "hysteria2-initial-remote-plan",
            "select Hysteria2 initial remote failed",
        ))
    })?;
    let client_config = build_hysteria2_runtime_client_config_with_session_cache(
        tls_identity,
        obfs.udp_packet_overhead(),
        Some(congestion),
        session_cache,
    )
    .map_err(|_| {
        Hysteria2ConnectionFailure::without_endpoint(Hysteria2Failure::new(
            Hysteria2FailureClass::Configuration,
            "hysteria2-client-configuration",
            "build Hysteria2 QUIC client configuration failed",
        ))
    })?;
    let endpoint_context = quic_endpoint_context_for_proxy(
        QuicEndpointProtocol::Hysteria2,
        caller,
        generation,
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
        cancellation,
        |remote, deadline, cancellation| {
            let addresses = remote_plan
                .addresses
                .iter()
                .copied()
                .filter(|address| address.is_ipv4() == remote.is_ipv4())
                .collect::<Vec<_>>();
            let ports = Arc::clone(&remote_plan.ports);
            let port_hopping = remote_plan.port_hopping;
            let port_hopping_metrics = Arc::clone(&port_hopping_metrics);
            let endpoint_context = endpoint_context.clone();
            let client_config = client_config.clone();
            async move {
                let port_hopping = if !port_hopping {
                    None
                } else {
                    Some(
                        Hysteria2PortHoppingRuntimeConfig::new(
                            addresses,
                            ports,
                            port_hop_interval,
                            mark,
                            resources.port_hop_transition_socket_limit(),
                            port_hopping_metrics,
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
                    endpoint_context,
                    deadline,
                    &cancellation,
                )
                .await
                .map_err(hysteria2_endpoint_open_failure)?;
                endpoint.set_default_client_config(client_config);
                Ok(endpoint)
            }
        },
    )
    .await?;
    Ok(ResidentConnectedQuicEndpoint {
        remote,
        endpoint,
        connection,
    })
}

fn hysteria2_endpoint_open_failure(error: QuicEndpointOpenError) -> Hysteria2Failure {
    match error {
        QuicEndpointOpenError::Admission(
            dae_runtime_control::OwnerAdmissionRejection::Cancelled(
                dae_runtime_control::OwnerCancellation::DeadlineElapsed,
            ),
        ) => Hysteria2Failure::new(
            Hysteria2FailureClass::Deadline,
            "hysteria2-endpoint-admission-deadline",
            "Hysteria2 QUIC Endpoint admission deadline elapsed",
        ),
        QuicEndpointOpenError::Admission(
            dae_runtime_control::OwnerAdmissionRejection::Cancelled(_),
        ) => Hysteria2Failure::new(
            Hysteria2FailureClass::Cancelled,
            "hysteria2-endpoint-admission-cancelled",
            "Hysteria2 QUIC Endpoint admission was cancelled",
        ),
        QuicEndpointOpenError::Admission(
            dae_runtime_control::OwnerAdmissionRejection::Draining(_)
            | dae_runtime_control::OwnerAdmissionRejection::Closed(_),
        ) => Hysteria2Failure::new(
            Hysteria2FailureClass::Draining,
            "hysteria2-endpoint-admission-draining",
            "Hysteria2 QUIC Endpoint admission is draining",
        ),
        QuicEndpointOpenError::Admission(
            dae_runtime_control::OwnerAdmissionRejection::LimitsExceeded { .. },
        )
        | QuicEndpointOpenError::Construction => Hysteria2Failure::new(
            Hysteria2FailureClass::Resource,
            "hysteria2-endpoint-open",
            "Hysteria2 QUIC Endpoint resources are unavailable",
        ),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn open_tuic_quic_connection_candidates_async(
    binding: &ResidentProxyBinding,
    alpn: &[String],
    allow_insecure: bool,
    congestion: TuicCongestionController,
    udp_relay_mode: dae_outbound::tuic::TuicUdpRelayMode,
    deadline: dae_runtime_control::AbsoluteDeadline,
    caller: QuicEndpointCallerClass,
    session_cache: Option<dae_outbound::shared_transport::boring_quic::BoringQuicSessionCache>,
) -> Result<ResidentConnectedQuicEndpoint, String> {
    let proxy = binding.plan();
    let candidates = resolve_proxy_udp_addr_candidates_async(proxy, deadline).await?;
    let client_config = build_tuic_runtime_client_config_with_session_cache(
        alpn,
        allow_insecure,
        congestion,
        session_cache,
    )
    .map_err(|err| format!("build TUIC QUIC client config: {err}"))?;
    let endpoint_context = quic_endpoint_context_for_proxy(
        QuicEndpointProtocol::Tuic,
        caller,
        binding.runtime_generation(),
        proxy,
        QuicEndpointIdentityRole::ProtocolCarrier,
        &[
            congestion.as_str().as_bytes(),
            udp_relay_mode.as_str().as_bytes(),
        ],
    );
    let (remote, endpoint, connection) = connect_quic_endpoint_candidates_async(
        &candidates,
        &proxy.server_name,
        deadline,
        "connect TUIC QUIC endpoint",
        |remote, deadline, cancellation| {
            let mut endpoint = open_marked_quic_endpoint_for_remote(
                binding.effective_socket_mark(),
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

pub(crate) async fn open_juicity_quic_connection_candidates_async(
    binding: &ResidentProxyBinding,
    allow_insecure: bool,
    pinned_certchain_sha256: &str,
    congestion: dae_outbound::juicity::JuicityCongestionController,
    deadline: dae_runtime_control::AbsoluteDeadline,
    caller: QuicEndpointCallerClass,
    session_cache: Option<dae_outbound::shared_transport::boring_quic::BoringQuicSessionCache>,
) -> Result<ResidentConnectedQuicEndpoint, String> {
    let proxy = binding.plan();
    let candidates = resolve_proxy_udp_addr_candidates_async(proxy, deadline).await?;
    let client_config = dae_outbound::juicity::build_juicity_runtime_client_config_with_congestion_and_session_cache(
        allow_insecure,
        pinned_certchain_sha256,
        congestion,
        session_cache,
    )
    .map_err(|err| format!("build Juicity QUIC client config: {err}"))?;
    let endpoint_context = quic_endpoint_context_for_proxy(
        QuicEndpointProtocol::Juicity,
        caller,
        binding.runtime_generation(),
        proxy,
        QuicEndpointIdentityRole::ProtocolCarrier,
        &[congestion.as_str().as_bytes()],
    );
    let (remote, endpoint, connection) = connect_quic_endpoint_candidates_async(
        &candidates,
        &proxy.server_name,
        deadline,
        "connect Juicity QUIC endpoint",
        |remote, deadline, cancellation| {
            let mut endpoint = open_marked_quic_endpoint_for_remote(
                binding.effective_socket_mark(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hysteria2_endpoint_admission_preserves_terminal_failure_class() {
        let deadline = hysteria2_endpoint_open_failure(QuicEndpointOpenError::Admission(
            dae_runtime_control::OwnerAdmissionRejection::Cancelled(
                dae_runtime_control::OwnerCancellation::DeadlineElapsed,
            ),
        ));
        assert_eq!(deadline.class(), Hysteria2FailureClass::Deadline);

        let draining = hysteria2_endpoint_open_failure(QuicEndpointOpenError::Admission(
            dae_runtime_control::OwnerAdmissionRejection::Draining(
                dae_runtime_control::OwnerDrainReason::Reload,
            ),
        ));
        assert_eq!(draining.class(), Hysteria2FailureClass::Draining);

        let resource = hysteria2_endpoint_open_failure(QuicEndpointOpenError::Admission(
            dae_runtime_control::OwnerAdmissionRejection::LimitsExceeded {
                count: true,
                charged_bytes: false,
            },
        ));
        assert_eq!(resource.class(), Hysteria2FailureClass::Resource);
        assert!(!deadline.allows_candidate_retry());
        assert!(!draining.allows_candidate_retry());
        assert!(!resource.allows_candidate_retry());
    }
}
