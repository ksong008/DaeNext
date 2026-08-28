use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

pub type ResidentDnsUdpFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;

pub trait ResidentDnsUdpResolver: Send + Sync {
    fn query_udp<'a>(
        &'a self,
        original_dst: SocketAddr,
        request: &'a [u8],
    ) -> ResidentDnsUdpFuture<'a>;
}
