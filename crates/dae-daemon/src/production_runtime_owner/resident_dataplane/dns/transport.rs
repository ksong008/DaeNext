use super::*;

mod cache;
mod h3;
mod plain;
mod quic;
mod route;
mod tls_https;
mod wire;

use h3::forward_dns_h3_async;
pub(super) use plain::{forward_dns_tcp_asis_async, forward_dns_udp_async};
use plain::{forward_dns_tcp_async, forward_dns_tcp_udp_async, forward_dns_udp_upstream_async};
use quic::forward_dns_quic_async;
use tls_https::{forward_dns_https_async, forward_dns_tls_async};
#[cfg(test)]
pub(super) use wire::parse_doh_http_response;

pub(super) async fn forward_dns_to_upstream_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
    forwarders: &Arc<ResidentDnsForwarderCache>,
) -> Result<Vec<u8>, String> {
    match upstream.scheme {
        ResidentDnsUpstreamScheme::Udp => {
            forward_dns_udp_upstream_async(upstream, payload, plan).await
        }
        ResidentDnsUpstreamScheme::Tcp => forward_dns_tcp_async(upstream, payload, plan).await,
        ResidentDnsUpstreamScheme::TcpUdp => {
            forward_dns_tcp_udp_async(upstream, payload, plan).await
        }
        ResidentDnsUpstreamScheme::Tls => forward_dns_tls_async(upstream, payload, plan).await,
        ResidentDnsUpstreamScheme::Https => forward_dns_https_async(upstream, payload, plan).await,
        ResidentDnsUpstreamScheme::Quic => {
            forward_dns_quic_async(upstream, payload, plan, forwarders).await
        }
        ResidentDnsUpstreamScheme::Http3 => forward_dns_h3_async(upstream, payload, plan).await,
    }
}
