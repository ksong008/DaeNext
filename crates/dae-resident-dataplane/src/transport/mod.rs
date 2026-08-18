pub(crate) mod dns_tcp_wire {
    #[cfg(test)]
    pub(crate) use dae_resident_transport::read_dns_tcp_payload_async;
    pub(crate) use dae_resident_transport::{DnsTcpFrameReader, write_dns_tcp_payload_async};
}

pub(crate) mod quic_endpoint {
    use dae_runtime_control::{OwnerGeneration, OwnerResourceBudget};
    use std::num::NonZeroUsize;

    use crate::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    #[cfg(not(test))]
    use crate::ResidentRuntimeProfileSelection;
    use crate::plan::ResidentProxyPlan;

    pub(crate) use dae_resident_transport::{
        ObservedQuicEndpoint, QuicEndpointCallerClass, QuicEndpointIdentityRole,
        QuicEndpointOpenContext, QuicEndpointProtocol, inherit_quic_endpoint_observation,
        scope_quic_endpoint_observation,
    };

    #[derive(Clone, Copy, Debug, Default)]
    pub(crate) struct ResidentDnsQuicEndpointPolicy;

    impl dae_resident_dns::ResidentDnsQuicEndpointTransport for ResidentDnsQuicEndpointPolicy {
        fn open_marked_endpoint(
            &self,
            mark: u32,
            remote: std::net::SocketAddr,
            context: QuicEndpointOpenContext,
            deadline: dae_runtime_control::AbsoluteDeadline,
            cancellation: &dae_runtime_control::OwnerCancellationSignal,
        ) -> Result<ObservedQuicEndpoint, String> {
            open_marked_quic_endpoint_for_remote(mark, remote, context, deadline, cancellation)
        }
    }

    fn selected_admission_budget() -> OwnerResourceBudget {
        #[cfg(test)]
        let budget = OwnerResourceBudget::new(
            NonZeroUsize::new(4096).expect("test QUIC endpoint limit is nonzero"),
            NonZeroUsize::new(usize::MAX / 4).expect("test QUIC endpoint byte limit is nonzero"),
        );
        #[cfg(not(test))]
        let profile = ResidentRuntimeProfileSelection::selected().profile;
        #[cfg(not(test))]
        let budget = OwnerResourceBudget::new(
            NonZeroUsize::new(profile.quic_endpoint_limit_default())
                .expect("resident QUIC endpoint count profile is nonzero"),
            NonZeroUsize::new(profile.quic_endpoint_charged_bytes_default())
                .expect("resident QUIC endpoint byte profile is nonzero"),
        );
        budget
    }

    fn configure_admission() -> Result<(), String> {
        dae_resident_transport::configure_quic_endpoint_admission(selected_admission_budget())?;
        dae_resident_transport::configure_quic_endpoint_observability_retention({
            #[cfg(test)]
            {
                128
            }
            #[cfg(not(test))]
            {
                2
            }
        })
    }

    pub(crate) fn quic_endpoint_context_for_proxy(
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

    pub(crate) fn open_marked_quic_endpoint_for_remote(
        mark: u32,
        remote: std::net::SocketAddr,
        context: QuicEndpointOpenContext,
        deadline: dae_runtime_control::AbsoluteDeadline,
        cancellation: &dae_runtime_control::OwnerCancellationSignal,
    ) -> Result<ObservedQuicEndpoint, String> {
        configure_admission()?;
        dae_resident_transport::open_marked_quic_endpoint_for_remote(
            mark,
            remote,
            context,
            deadline,
            cancellation,
        )
    }

    pub(crate) async fn wait_quic_endpoint_idle_after_close(
        endpoint: &ObservedQuicEndpoint,
    ) -> bool {
        dae_resident_transport::wait_quic_endpoint_idle_after_close_for(
            endpoint,
            RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE,
        )
        .await
    }

    pub(crate) fn quic_endpoint_metrics_snapshot(generation: u64) -> serde_json::Value {
        let _ = configure_admission();
        dae_resident_transport::quic_endpoint_metrics_snapshot(generation)
    }
}
