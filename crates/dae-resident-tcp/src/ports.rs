use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use dae_outbound_core::NetworkType;
use dae_resident_plan::ResidentProxyBinding;

mod router;

pub use router::{
    ResidentTcpRouter, TCP_SNIFF_BUFFER_LIMIT, TcpBlockSelection, TcpDirectSelection,
    TcpProxySelection, TcpRouteSelection, TcpRoutingLogMetadata, TcpSelection, TcpSniffReport,
};

pub type ResidentTcpDnsFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait ResidentTcpDnsResolver: Send + Sync {
    fn resolve_domain_has_ip_for_dial<'a>(
        &'a self,
        domain: &'a str,
        ip: IpAddr,
    ) -> ResidentTcpDnsFuture<'a, bool>;

    fn query_tcp<'a>(
        &'a self,
        original_dst: SocketAddr,
        request: &'a [u8],
    ) -> ResidentTcpDnsFuture<'a, Result<Vec<u8>, String>>;

    fn server_failure_response(&self, request: &[u8]) -> Result<Vec<u8>, String>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidentTcpProxySelectionError {
    pub message: String,
    pub no_alive: bool,
}

pub trait ResidentTcpProxySelector: Send + Sync {
    fn proxy_count(&self) -> usize;

    fn select_proxy(
        &self,
        outbound: u8,
        network_type: NetworkType,
        strict_ip_version: bool,
    ) -> Result<ResidentProxyBinding, ResidentTcpProxySelectionError>;
}

pub fn resident_tcp_network_type(ip: IpAddr) -> NetworkType {
    match ip {
        IpAddr::V4(_) => NetworkType::TCP4,
        IpAddr::V6(_) => NetworkType::TCP6,
    }
}

pub type SharedResidentTcpDnsResolver = Arc<dyn ResidentTcpDnsResolver>;
pub type SharedResidentTcpProxySelector = Arc<dyn ResidentTcpProxySelector>;
