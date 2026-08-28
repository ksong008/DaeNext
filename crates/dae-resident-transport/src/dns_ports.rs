use std::future::Future;
use std::pin::Pin;

use dae_resident_model::ResidentProxyBinding;
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::{ProxyDnsRequestContext, ProxyDnsRequestError};

pub type ResidentTransportFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub struct ResidentDnsProxyTcpOpenRequest {
    pub binding: ResidentProxyBinding,
    pub target: String,
    pub dial_ip: bool,
    pub sniff_payload: Vec<u8>,
    pub sniff_domain: String,
    pub context: ProxyDnsRequestContext,
}

pub trait ResidentDnsProxyTcpSession: Send {
    fn take_stream(&mut self) -> Option<TcpStream>;

    fn finish(
        self: Box<Self>,
        deadline: Instant,
        exchange_failed: bool,
    ) -> ResidentTransportFuture<'static, Result<String, String>>;
}

pub trait ResidentDnsProxyTcpTransport: Send + Sync {
    fn open(
        &self,
        request: ResidentDnsProxyTcpOpenRequest,
    ) -> ResidentTransportFuture<
        '_,
        Result<Box<dyn ResidentDnsProxyTcpSession>, ProxyDnsRequestError>,
    >;
}
