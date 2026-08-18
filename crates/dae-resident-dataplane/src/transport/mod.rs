pub(crate) mod dns_tcp_wire {
    #[cfg(test)]
    pub(crate) use dae_resident_transport::read_dns_tcp_payload_async;
    pub(crate) use dae_resident_transport::{DnsTcpFrameReader, write_dns_tcp_payload_async};
}

pub(crate) mod quic_endpoint {
    use dae_runtime_control::OwnerResourceBudget;
    use std::num::NonZeroUsize;

    #[cfg(not(test))]
    use crate::ResidentRuntimeProfileSelection;

    pub(crate) use dae_resident_transport::{ObservedQuicEndpoint, QuicEndpointOpenContext};

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

    #[cfg(test)]
    pub(crate) fn quic_endpoint_metrics_snapshot(generation: u64) -> serde_json::Value {
        let _ = configure_admission();
        dae_resident_transport::quic_endpoint_metrics_snapshot(generation)
    }
}
