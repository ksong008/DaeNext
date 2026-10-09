use std::{future::Future, pin::Pin};

use super::*;

pub mod cache;
pub mod error;
pub mod h3;
mod health_forwarder;
pub mod plain;
pub mod quic;
pub mod route;
mod tcp_multiplex;
pub mod tcp_udp;

mod tls_https;
pub mod udp_multiplex;
pub mod wire;

use error::ResidentDnsTransportError;
use h3::forward_dns_h3_async;
pub use plain::forward_dns_tcp_asis_async;
use plain::{forward_dns_tcp_async, forward_dns_udp_upstream_async};
use quic::forward_dns_quic_async;
#[cfg(any(test, feature = "test-support"))]
pub use route::{
    dns_upstream_candidates_for_l4protos, select_dns_upstream_candidates,
    select_dns_upstream_targets,
};
pub use tcp_multiplex::ResidentDnsTcpMultiplexHandle;
use tcp_udp::forward_dns_tcp_udp_async;
use tls_https::{forward_dns_https_async, forward_dns_tls_async};
#[cfg(any(test, feature = "test-support"))]
pub use wire::parse_doh_http_response;

type ResidentDnsUpstreamExchangeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, ResidentDnsTransportError>> + Send + 'a>>;

pub fn forward_dns_to_upstream_async<'a>(
    upstream: &'a ResidentDnsUpstream,
    payload: &'a [u8],
    plan: &'a ResidentDnsPlan,
    forwarders: &'a Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> ResidentDnsUpstreamExchangeFuture<'a> {
    match upstream.scheme {
        ResidentDnsUpstreamScheme::Udp => Box::pin(forward_dns_udp_upstream_async(
            upstream, payload, plan, forwarders, context,
        )),
        ResidentDnsUpstreamScheme::Tcp => Box::pin(forward_dns_tcp_async(
            upstream, payload, plan, forwarders, context,
        )),
        ResidentDnsUpstreamScheme::TcpUdp => Box::pin(forward_dns_tcp_udp_async(
            upstream, payload, plan, forwarders, context,
        )),
        ResidentDnsUpstreamScheme::Tls => Box::pin(forward_dns_tls_async(
            upstream, payload, plan, forwarders, context,
        )),
        ResidentDnsUpstreamScheme::Https => Box::pin(forward_dns_https_async(
            upstream, payload, plan, forwarders, context,
        )),
        ResidentDnsUpstreamScheme::Quic => Box::pin(forward_dns_quic_async(
            upstream, payload, plan, forwarders, context,
        )),
        ResidentDnsUpstreamScheme::Http3 => Box::pin(forward_dns_h3_async(
            upstream, payload, plan, forwarders, context,
        )),
    }
}
