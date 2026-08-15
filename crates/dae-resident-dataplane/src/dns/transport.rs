use std::{future::Future, pin::Pin};

use super::*;

mod cache;
mod error;
mod h3;
mod health_forwarder;
mod plain;
mod quic;
mod route;
mod tcp_multiplex;
pub(in crate::dns) mod tcp_udp;
#[cfg(test)]
mod test_support;
mod tls_https;
pub(crate) mod udp_multiplex;
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
pub(in crate::dns) use tcp_multiplex::ResidentDnsTcpMultiplexHandle;
use tcp_udp::forward_dns_tcp_udp_async;
use tls_https::{forward_dns_https_async, forward_dns_tls_async};
#[cfg(test)]
pub(super) use wire::parse_doh_http_response;

type ResidentDnsUpstreamExchangeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, ResidentDnsTransportError>> + Send + 'a>>;

pub(super) fn forward_dns_to_upstream_async<'a>(
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
