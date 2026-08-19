#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::PathBuf;
#[cfg(test)]
use std::pin::Pin;
use std::sync::{Arc, Mutex, atomic::Ordering};
#[cfg(test)]
use std::task::{Context, Poll};
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;

#[cfg(test)]
use bytes::Bytes;
#[cfg(test)]
use dae_core_types::OutboundIndex;
#[cfg(test)]
use dae_datapath::TcpDialMode;
#[cfg(test)]
use dae_datapath::{OUTBOUND_BLOCK, OUTBOUND_CONTROL_PLANE_ROUTING, OUTBOUND_DIRECT};
#[cfg(test)]
use dae_ebpf_support::BpfRoutingResult;
#[cfg(test)]
use dae_outbound::shadowsocks::{
    ShadowsocksRStreamDecoder, ShadowsocksRStreamEncoder, shadowsocksr_http_simple_origin_request,
};
#[cfg(test)]
use dae_outbound::shared_transport::{
    GRPC_ACCEPT_ENCODING_HEADER, GRPC_CONTENT_TYPE_APPLICATION, GRPC_ENCODING_HEADER,
    GRPC_IDENTITY_ENCODING, GRPC_TE_HEADER, GRPC_TE_TRAILERS,
};
use dae_resident_tcp::{
    ResidentTcpDnsFuture, ResidentTcpDnsResolver, SharedResidentTcpDnsResolver,
};
#[cfg(test)]
use dae_routing::RoutingMatcher;
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
#[cfg(test)]
use tokio::io::AsyncWriteExt;
#[cfg(test)]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time;

use super::ResidentDnsResolver;
use super::events::append_event;
use super::execution::tcp_execution_descriptor;
#[cfg(test)]
use super::plan::{
    ResidentProxyGroupPlan, SharedResidentProxyGroupMap, share_resident_proxy_groups,
};
#[cfg(test)]
use super::probe::{resident_tcp_probe_http_request, resident_tcp_probe_status_ok};
use super::{
    ResidentDataplaneMetrics, ResidentTaskSetShutdown, SharedResidentStopSignal,
    record_resident_task_completion, resident_normalized_socket_addr, resident_socket_addr_display,
    run_until_resident_stop, shutdown_resident_task_set,
};

pub(crate) use dae_resident_tcp::*;

#[derive(Clone)]
pub(crate) struct ResidentTcpDnsResolverPort {
    resolver: ResidentDnsResolver,
}

impl ResidentTcpDnsResolverPort {
    pub(crate) fn shared(resolver: ResidentDnsResolver) -> SharedResidentTcpDnsResolver {
        Arc::new(Self { resolver })
    }
}

impl ResidentTcpDnsResolver for ResidentTcpDnsResolverPort {
    fn resolve_domain_has_ip_for_dial<'a>(
        &'a self,
        domain: &'a str,
        ip: IpAddr,
    ) -> ResidentTcpDnsFuture<'a, bool> {
        Box::pin(async move {
            self.resolver
                .resolve_domain_has_ip_for_dial(domain, ip)
                .await
        })
    }

    fn query_tcp<'a>(
        &'a self,
        original_dst: SocketAddr,
        request: &'a [u8],
    ) -> ResidentTcpDnsFuture<'a, Result<Vec<u8>, String>> {
        Box::pin(async move { self.resolver.query_tcp(original_dst, request).await })
    }

    fn server_failure_response(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        ResidentDnsResolver::server_failure_response(request)
    }
}

#[cfg(test)]
fn resident_tcp_router_for_test(
    proxies: BTreeMap<u8, ResidentProxyGroupPlan>,
    routing_matcher: RoutingMatcher,
    dial_mode: TcpDialMode,
    sniffing_timeout: Duration,
    so_mark_from_dae: u32,
    mptcp: bool,
) -> Result<ResidentTcpRouter, String> {
    resident_tcp_router_for_test_shared(
        share_resident_proxy_groups(proxies),
        routing_matcher,
        dial_mode,
        sniffing_timeout,
        so_mark_from_dae,
        mptcp,
    )
}

#[cfg(test)]
fn resident_tcp_router_for_test_shared(
    proxies: SharedResidentProxyGroupMap,
    routing_matcher: RoutingMatcher,
    dial_mode: TcpDialMode,
    sniffing_timeout: Duration,
    so_mark_from_dae: u32,
    mptcp: bool,
) -> Result<ResidentTcpRouter, String> {
    ResidentTcpRouter::new_for_test(
        super::plan::ResidentTcpProxyGroupSelector::shared(proxies),
        ResidentTcpDnsResolverPort::shared(ResidentDnsResolver::asis(so_mark_from_dae)),
        routing_matcher,
        dial_mode,
        sniffing_timeout,
        so_mark_from_dae,
        mptcp,
    )
}

mod accept_loop;
pub(super) use self::accept_loop::*;
mod admission;
pub(crate) use self::admission::ResidentTcpAdmission;

#[cfg(test)]
mod tests;
