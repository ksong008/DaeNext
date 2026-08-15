use super::super::quic::managed_dns_quic_endpoint_context;
use super::super::wire::resident_dns_quic_client_config;
use super::*;

const PROXIED_DOH3_CLOSE_REASON: &[u8] = b"proxied dns h3 owner cleanup";

mod cached;
mod lifecycle;
mod request;
mod resources;

use self::cached::forward_cached_proxy_dns_h3;
pub(in super::super) use self::cached::shutdown_cached_proxy_dns_h3;

#[cfg(test)]
use self::lifecycle::{
    PROXIED_DOH3_CANCELLED, ProxiedDoh3Cancellation, ProxiedDoh3CleanupDeadline,
    ProxiedDoh3CleanupOutcome, ProxiedDoh3DriverCompletion, ProxiedDoh3EndpointCompletion,
    ProxiedDoh3ExchangeTarget, run_owned_proxied_doh3_exchange,
};
#[cfg(test)]
use self::resources::ProxiedDoh3Resources;
#[cfg(test)]
use crate::udp::ResidentProxyUdpBridgeShutdownCompletion;

#[cfg(test)]
mod tests;

pub(super) async fn forward_dns_h3_to_proxy_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    forwarder: Arc<AsyncMutex<ResidentDnsProxyH3Forwarder>>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ProxyDnsRequestError> {
    let generation = {
        let forwarder = time::timeout_at(context.deadline(), forwarder.lock())
            .await
            .map_err(|_| ProxyDnsRequestError::deadline(ProxyDnsRequestStage::OwnerAcquire))?;
        forwarder.binding.runtime_generation()
    };
    scope_quic_endpoint_observation(
        QuicEndpointCallerClass::ManagedDns,
        Some(generation),
        forward_cached_proxy_dns_h3(upstream, payload, forwarder, context),
    )
    .await
}
