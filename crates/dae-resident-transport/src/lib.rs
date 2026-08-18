mod direct_dial;
mod dns_name;
mod dns_request;
mod dns_tcp_wire;
mod quic_endpoint;
mod resolver;

pub use direct_dial::{DirectTcpConnection, open_direct_tcp_connection_async};
pub use dns_name::encode_dns_qname;
pub use dns_request::{
    ProxyDnsPendingRequestBytes, ProxyDnsQueuedRequestBytes, ProxyDnsRequestContext,
    ProxyDnsRequestError, ProxyDnsRequestFailure, ProxyDnsRequestOutcome, ProxyDnsRequestStage,
    ProxyDnsResponseBytes, exchange_proxy_dns_framed_stream,
};
pub use dns_tcp_wire::{
    DnsTcpFrameReader, read_dns_tcp_payload_async, write_dns_tcp_payload_async,
};
pub use quic_endpoint::{
    ObservedQuicEndpoint, QuicEndpointAdmissionContext, QuicEndpointCallerClass,
    QuicEndpointDrainReport, QuicEndpointIdentityRole, QuicEndpointOpenContext,
    QuicEndpointOpenError, QuicEndpointProtocol, QuicEndpointUnderlay,
    configure_quic_endpoint_admission, configure_quic_endpoint_observability_retention,
    inherit_quic_endpoint_observation, open_marked_quic_endpoint_for_remote,
    open_observed_quic_endpoint, open_observed_quic_endpoint_waiting,
    quic_endpoint_drain_deadlines, quic_endpoint_metrics_snapshot, scope_quic_endpoint_observation,
    wait_quic_endpoint_idle_after_close_for, wait_quic_endpoints_idle_or_released_until,
    wait_quic_endpoints_idle_until,
};
pub use resolver::{
    ResolvedHostAddrs, SocketAddressResolutionError, SocketCandidateAttemptError,
    SocketCandidateFailure, TcpCandidateRacePolicy, authority_from_host_port,
    resolve_host_addrs_with_bootstrap_dns_ttl, resolve_host_addrs_with_configured_fallback_dns_ttl,
    resolve_socket_addr_candidates, try_socket_addr_candidates, try_tcp_socket_addr_candidates,
};
