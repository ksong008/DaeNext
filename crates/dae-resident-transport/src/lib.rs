mod dns_tcp_wire;
mod quic_endpoint;

pub use dns_tcp_wire::{
    DnsTcpFrameReader, read_dns_tcp_payload_async, write_dns_tcp_payload_async,
};
pub use quic_endpoint::{
    ObservedQuicEndpoint, QuicEndpointAdmissionContext, QuicEndpointCallerClass,
    QuicEndpointDrainReport, QuicEndpointIdentityRole, QuicEndpointOpenContext,
    QuicEndpointOpenError, QuicEndpointProtocol, QuicEndpointUnderlay,
    configure_quic_endpoint_admission, configure_quic_endpoint_observability_retention,
    inherit_quic_endpoint_observation, open_observed_quic_endpoint,
    open_observed_quic_endpoint_waiting, quic_endpoint_drain_deadlines,
    quic_endpoint_metrics_snapshot, scope_quic_endpoint_observation,
    wait_quic_endpoint_idle_after_close_for, wait_quic_endpoints_idle_or_released_until,
    wait_quic_endpoints_idle_until,
};
