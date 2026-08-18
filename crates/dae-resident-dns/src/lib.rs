mod cache;
mod domain_routing;
mod error_response;
mod geodata;
mod proxy_transport;
mod udp_response;
mod udp_runtime;

use std::time::{SystemTime, UNIX_EPOCH};

pub use cache::{
    ResidentDnsFlightPermit, ResidentDnsResponseCacheKey, ResidentDnsResponseCacheScope,
    ResidentDnsRuntimeCache, ResidentDnsRuntimeCacheSnapshot,
};
pub use domain_routing::{
    ResidentDnsDomainRouting, ResidentDnsDomainRoutingMaintenanceHandle,
    ResidentDnsDomainRoutingReloadSnapshot, ResidentDnsDomainRoutingRestoreReport,
    ResidentDomainRoutingGenerationFence,
};
pub use error_response::{build_dns_server_failure_response, build_reject_response};
pub use geodata::ResidentDnsGeodata;
pub use proxy_transport::{
    ResidentDnsProxyFuture, ResidentDnsProxyTcpOpenRequest, ResidentDnsProxyTcpSession,
    ResidentDnsProxyTcpTransport, ResidentDnsProxyUdpBridge, ResidentDnsProxyUdpForwarder,
    ResidentDnsProxyUdpTransport, ResidentDnsQuicEndpointTransport,
    ResidentDnsTransportOwnerObservation, exchange_resident_proxy_dns_tcp_stream,
    run_resident_proxy_dns_tcp_connection,
};
pub use udp_response::fit_dns_response_to_udp_request;
pub use udp_runtime::ResidentDnsUdpRuntimeConfig;

pub const DNS_MAX_UDP_MESSAGE_SIZE: usize = u16::MAX as usize;

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}
