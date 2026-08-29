mod cache;
mod domain_routing;
mod error_response;
mod geodata;
mod proxy_probe;
mod proxy_transport;
mod runtime;
mod udp_response;
mod udp_runtime;

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use dae_resident_core::{ResidentDnsUdpFuture, ResidentDnsUdpResolver};

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
pub use proxy_probe::probe_resident_proxy_dns_udp_with_forwarder_async;
pub use proxy_transport::{
    ResidentDnsProxyFuture, ResidentDnsProxySelection, ResidentDnsProxySelectionError,
    ResidentDnsProxySelector, ResidentDnsProxyTcpOpenRequest, ResidentDnsProxyTcpSession,
    ResidentDnsProxyTcpTransport, ResidentDnsProxyUdpBridge, ResidentDnsProxyUdpForwarder,
    ResidentDnsProxyUdpTransport, ResidentDnsQuicEndpointTransport,
    ResidentDnsTransportOwnerObservation, ResidentDnsTransportPorts,
    exchange_resident_proxy_dns_tcp_stream, run_resident_proxy_dns_tcp_connection,
};
pub use runtime::{
    DNS_TRANSPORT_OUTCOME_ERROR, DNS_TRANSPORT_OUTCOME_SUCCESS, DNS_TRANSPORT_ROUTE_DIRECT,
    DNS_TRANSPORT_ROUTE_PROXY, DNS_TRANSPORT_TARGET_FAMILY_IPV4, DNS_TRANSPORT_TARGET_FAMILY_IPV6,
    DnsRequestIdAllocator, ResidentDnsDispatcher, ResidentDnsPlan, ResidentDnsQueryResult,
    ResidentDnsReloadHandle, ResidentDnsReloadSnapshot, ResidentDnsResolver,
    ResidentDnsTraceSummary, ResidentDnsTransportTrace, ResidentDnsUdpActorCompletion,
    ResidentDnsUdpActorExecutor, ResidentDnsUdpActorLifecycle, ResidentDnsUdpActorRegistration,
    ResidentDnsUpstreamRouter, build_resident_dns_plan_with_refresh_interval,
    handle_resident_dns_local_trace_async,
};
pub use udp_response::fit_dns_response_to_udp_request;
pub use udp_runtime::ResidentDnsUdpRuntimeConfig;

pub const DNS_MAX_UDP_MESSAGE_SIZE: usize = u16::MAX as usize;

impl ResidentDnsUdpResolver for ResidentDnsDispatcher {
    fn query_udp<'a>(
        &'a self,
        original_dst: SocketAddr,
        request: &'a [u8],
    ) -> ResidentDnsUdpFuture<'a> {
        Box::pin(async move { ResidentDnsDispatcher::query_udp(self, original_dst, request).await })
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}
