#![recursion_limit = "256"]

mod anytls_frame;
mod anytls_owner;
mod direct_dial;
mod dns_name;
mod dns_request;
mod dns_tcp_wire;
mod h2_carrier_owner;
mod http_connect_head;
mod meek_transport_owner;
mod proxy_handshake;
mod quic_endpoint;
mod resolver;
mod tls_client;
mod transport_identity;
mod vless_mux_owner;

pub use anytls_frame::AnyTlsFrameReader;
pub use anytls_owner::{
    AnyTlsLogicalStreamLease, AnyTlsOwnerRegistryHandle, start_anytls_owner_registry,
    start_anytls_owner_registry_on,
};
#[cfg(any(test, feature = "test-support"))]
pub use anytls_owner::{
    anytls_owner_key_digest_for_test, start_anytls_owner_registry_with_resources,
};
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
#[cfg(any(test, feature = "test-support"))]
pub use h2_carrier_owner::start_h2_carrier_generation_owner;
pub use h2_carrier_owner::{
    H2CarrierGenerationOwnerHandle, H2CarrierLease, H2CarrierResponseFuture, acquire_h2_carrier,
    start_h2_carrier_generation_owner_on,
};
pub use meek_transport_owner::{
    MeekTransportGenerationOwnerHandle, MeekTransportLease, acquire_meek_transport,
    start_meek_transport_generation_owner_on,
};
#[cfg(any(test, feature = "test-support"))]
pub use meek_transport_owner::{
    start_meek_transport_generation_owner, start_meek_transport_generation_owner_for_test,
};
pub use proxy_handshake::{http_proxy_connect_plain_async, socks5_connect_async};
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
pub use tls_client::{
    AsyncResidentTlsClient, AsyncVlessTlsClient, ResidentTlsConfigCacheClearReport,
    async_resident_tls_underlay_name, async_tls_underlay_name, clear_resident_tls_config_caches,
    open_async_resident_tls_client_with_binding,
    open_async_vless_tls_client_with_flow_at_candidates, open_async_xhttp_endpoint_tls_client,
    open_async_xhttp_endpoint_tls_client_at_candidates, open_proxy_tcp_stream_with_binding,
    take_boring_tls_io_profile_snapshot,
};
pub use transport_identity::resident_transport_binding_identity_digest;
pub use vless_mux_owner::{
    VlessMuxGenerationOwnerHandle, VlessMuxLogicalStream, acquire_vless_mux_logical_stream,
    start_vless_mux_generation_owner_on,
};
#[cfg(any(test, feature = "test-support"))]
pub use vless_mux_owner::{
    start_vless_mux_generation_owner, start_vless_mux_generation_owner_for_test,
};
