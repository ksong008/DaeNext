use super::*;

mod cache;
mod error;
mod h3;
mod plain;
mod quic;
mod route;
mod tcp_udp;
mod tls_https;
pub(in crate::production_runtime_owner::resident_dataplane) mod udp_multiplex;
mod wire;

use error::ResidentDnsTransportError;
use h3::forward_dns_h3_async;
pub(super) use plain::{forward_dns_tcp_asis_async, forward_dns_udp_async};
use plain::{forward_dns_tcp_async, forward_dns_udp_upstream_async};
use quic::forward_dns_quic_async;
#[cfg(test)]
pub(super) use route::{
    dns_upstream_candidates_for_l4protos, select_dns_upstream_candidates,
    select_dns_upstream_targets,
};
use tcp_udp::forward_dns_tcp_udp_async;
use tls_https::{forward_dns_https_async, forward_dns_tls_async};
#[cfg(test)]
pub(super) use wire::parse_doh_http_response;

pub(super) async fn forward_dns_to_upstream_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    match upstream.scheme {
        ResidentDnsUpstreamScheme::Udp => {
            forward_dns_udp_upstream_async(upstream, payload, plan, forwarders, context).await
        }
        ResidentDnsUpstreamScheme::Tcp => {
            forward_dns_tcp_async(upstream, payload, plan, forwarders, context).await
        }
        ResidentDnsUpstreamScheme::TcpUdp => {
            forward_dns_tcp_udp_async(upstream, payload, plan, forwarders, context).await
        }
        ResidentDnsUpstreamScheme::Tls => {
            forward_dns_tls_async(upstream, payload, plan, forwarders, context).await
        }
        ResidentDnsUpstreamScheme::Https => {
            forward_dns_https_async(upstream, payload, plan, forwarders, context).await
        }
        ResidentDnsUpstreamScheme::Quic => {
            forward_dns_quic_async(upstream, payload, plan, forwarders, context).await
        }
        ResidentDnsUpstreamScheme::Http3 => {
            forward_dns_h3_async(upstream, payload, plan, forwarders, context).await
        }
    }
}
