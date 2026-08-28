use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use dae_outbound::NetworkType;
use dae_resident_core::{ResidentDataplaneMetrics, ResidentOwnedTaskShutdownCompletion};
use dae_resident_plan::ResidentProxyBinding;
use dae_resident_transport::{
    ObservedQuicEndpoint, ProxyDnsRequestContext, ProxyDnsRequestError, ProxyDnsRequestFailure,
    ProxyDnsRequestStage, QuicEndpointOpenContext,
};
pub use dae_resident_transport::{
    ResidentDnsProxyTcpOpenRequest, ResidentDnsProxyTcpSession, ResidentDnsProxyTcpTransport,
};
use tokio::net::TcpStream;
use tokio::time::Instant;

pub struct ResidentDnsTransportOwnerObservation {
    metrics: Arc<ResidentDataplaneMetrics>,
    charged_bytes: usize,
    evicted: AtomicBool,
    released: AtomicBool,
}

impl ResidentDnsTransportOwnerObservation {
    pub fn new(metrics: Arc<ResidentDataplaneMetrics>, charged_bytes: usize) -> Arc<Self> {
        metrics.dns_transport_owner_opened(charged_bytes);
        Arc::new(Self {
            metrics,
            charged_bytes,
            evicted: AtomicBool::new(false),
            released: AtomicBool::new(false),
        })
    }

    pub fn mark_evicted(&self) {
        if !self.evicted.swap(true, Ordering::AcqRel) {
            self.metrics.dns_transport_owner_evicted();
        }
    }

    pub fn release(&self) {
        if !self.released.swap(true, Ordering::AcqRel) {
            self.metrics.dns_transport_owner_released(
                self.charged_bytes,
                self.evicted.load(Ordering::Acquire),
            );
        }
    }
}

impl Drop for ResidentDnsTransportOwnerObservation {
    fn drop(&mut self) {
        self.release();
    }
}

pub type ResidentDnsProxyFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug)]
pub struct ResidentDnsProxySelection {
    pub binding: ResidentProxyBinding,
    pub network_type: NetworkType,
    pub latency_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidentDnsProxySelectionError {
    pub message: String,
    pub no_alive: bool,
}

pub trait ResidentDnsProxySelector: std::fmt::Debug + Send + Sync {
    fn select(
        &self,
        outbound: u8,
        network_type: NetworkType,
    ) -> Result<ResidentDnsProxySelection, ResidentDnsProxySelectionError>;
}

pub trait ResidentDnsQuicEndpointTransport: Send + Sync {
    fn open_marked_endpoint(
        &self,
        mark: u32,
        remote: SocketAddr,
        context: QuicEndpointOpenContext,
        deadline: dae_runtime_control::AbsoluteDeadline,
        cancellation: &dae_runtime_control::OwnerCancellationSignal,
    ) -> Result<ObservedQuicEndpoint, String>;
}

pub trait ResidentDnsProxyUdpForwarder: Send + Sync {
    fn exchange<'a>(
        &'a self,
        payload: &'a [u8],
        context: ProxyDnsRequestContext,
    ) -> ResidentDnsProxyFuture<'a, Result<Vec<u8>, ProxyDnsRequestError>>;

    fn shutdown(&self, deadline: Instant) -> ResidentDnsProxyFuture<'_, serde_json::Value>;

    fn owner_observation(&self) -> Arc<ResidentDnsTransportOwnerObservation>;

    fn actor_count(&self) -> usize;
}

pub trait ResidentDnsProxyUdpBridge: Send {
    fn local_addr(&self) -> SocketAddr;

    fn last_error(&self) -> Option<String>;

    fn shutdown_and_join_until(
        self: Box<Self>,
        deadline: Instant,
    ) -> ResidentDnsProxyFuture<'static, Result<ResidentOwnedTaskShutdownCompletion, String>>;
}

pub trait ResidentDnsProxyUdpTransport: Send + Sync {
    fn open_forwarder(
        &self,
        binding: ResidentProxyBinding,
        original_dst: SocketAddr,
    ) -> Result<Arc<dyn ResidentDnsProxyUdpForwarder>, String>;

    fn open_bridge(
        &self,
        binding: ResidentProxyBinding,
        original_dst: SocketAddr,
        owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
    ) -> ResidentDnsProxyFuture<'_, Result<Box<dyn ResidentDnsProxyUdpBridge>, String>>;
}

#[derive(Clone)]
pub struct ResidentDnsTransportPorts {
    proxy_tcp: Arc<dyn ResidentDnsProxyTcpTransport>,
    proxy_udp: Arc<dyn ResidentDnsProxyUdpTransport>,
    quic_endpoint: Arc<dyn ResidentDnsQuicEndpointTransport>,
}

impl ResidentDnsTransportPorts {
    pub fn new(
        proxy_tcp: Arc<dyn ResidentDnsProxyTcpTransport>,
        proxy_udp: Arc<dyn ResidentDnsProxyUdpTransport>,
        quic_endpoint: Arc<dyn ResidentDnsQuicEndpointTransport>,
    ) -> Self {
        Self {
            proxy_tcp,
            proxy_udp,
            quic_endpoint,
        }
    }

    pub fn unavailable() -> Self {
        Self::new(
            Arc::new(UnavailableDnsProxyTcpTransport),
            Arc::new(UnavailableDnsProxyUdpTransport),
            Arc::new(UnavailableDnsQuicEndpointTransport),
        )
    }

    pub fn proxy_tcp(&self) -> Arc<dyn ResidentDnsProxyTcpTransport> {
        Arc::clone(&self.proxy_tcp)
    }

    pub fn proxy_udp(&self) -> Arc<dyn ResidentDnsProxyUdpTransport> {
        Arc::clone(&self.proxy_udp)
    }

    pub fn quic_endpoint(&self) -> Arc<dyn ResidentDnsQuicEndpointTransport> {
        Arc::clone(&self.quic_endpoint)
    }
}

struct UnavailableDnsProxyTcpTransport;

impl ResidentDnsProxyTcpTransport for UnavailableDnsProxyTcpTransport {
    fn open(
        &self,
        _request: ResidentDnsProxyTcpOpenRequest,
    ) -> ResidentDnsProxyFuture<'_, Result<Box<dyn ResidentDnsProxyTcpSession>, ProxyDnsRequestError>>
    {
        Box::pin(async {
            Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::OwnerAcquire,
                ProxyDnsRequestFailure::Network,
                "resident DNS proxy TCP transport is not configured",
            ))
        })
    }
}

struct UnavailableDnsProxyUdpTransport;

impl ResidentDnsProxyUdpTransport for UnavailableDnsProxyUdpTransport {
    fn open_forwarder(
        &self,
        _binding: ResidentProxyBinding,
        _original_dst: SocketAddr,
    ) -> Result<Arc<dyn ResidentDnsProxyUdpForwarder>, String> {
        Err("resident DNS proxy UDP transport is not configured".to_owned())
    }

    fn open_bridge(
        &self,
        _binding: ResidentProxyBinding,
        _original_dst: SocketAddr,
        _owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
    ) -> ResidentDnsProxyFuture<'_, Result<Box<dyn ResidentDnsProxyUdpBridge>, String>> {
        Box::pin(async { Err("resident DNS proxy UDP transport is not configured".to_owned()) })
    }
}

struct UnavailableDnsQuicEndpointTransport;

impl ResidentDnsQuicEndpointTransport for UnavailableDnsQuicEndpointTransport {
    fn open_marked_endpoint(
        &self,
        _mark: u32,
        _remote: SocketAddr,
        _context: QuicEndpointOpenContext,
        _deadline: dae_runtime_control::AbsoluteDeadline,
        _cancellation: &dae_runtime_control::OwnerCancellationSignal,
    ) -> Result<ObservedQuicEndpoint, String> {
        Err("resident DNS QUIC endpoint transport is not configured".to_owned())
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn exchange_resident_proxy_dns_tcp_stream<F, Fut>(
    transport: &dyn ResidentDnsProxyTcpTransport,
    binding: ResidentProxyBinding,
    target: String,
    dial_ip: bool,
    sniff_payload: Vec<u8>,
    sniff_domain: String,
    context: ProxyDnsRequestContext,
    exchange: F,
) -> Result<Vec<u8>, ProxyDnsRequestError>
where
    F: FnOnce(TcpStream) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, ProxyDnsRequestError>>,
{
    let mut session = transport
        .open(ResidentDnsProxyTcpOpenRequest {
            binding,
            target,
            dial_ip,
            sniff_payload,
            sniff_domain,
            context,
        })
        .await?;
    let stream = session.take_stream().ok_or_else(|| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::OwnerAcquire,
            ProxyDnsRequestFailure::Network,
            "proxy DNS TCP transport returned a session without a stream",
        )
    })?;
    let response_result = exchange(stream).await;
    let cleanup_result = session
        .finish(context.deadline(), response_result.is_err())
        .await;
    match response_result {
        Ok(response) => match cleanup_result {
            Ok(_) => Ok(response),
            Err(error) => Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Cleanup,
                ProxyDnsRequestFailure::Network,
                error,
            )),
        },
        Err(response_error) => {
            let cleanup_detail = match cleanup_result {
                Ok(event) => format!("handler_event={event}"),
                Err(error) => format!("handler_error={error}"),
            };
            Err(ProxyDnsRequestError::new(
                response_error.stage(),
                response_error.failure(),
                format!("{response_error}; {cleanup_detail}"),
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_resident_proxy_dns_tcp_connection<F, Fut>(
    transport: &dyn ResidentDnsProxyTcpTransport,
    binding: ResidentProxyBinding,
    target: String,
    dial_ip: bool,
    sniff_payload: Vec<u8>,
    sniff_domain: String,
    context: ProxyDnsRequestContext,
    cleanup_deadline: Instant,
    run: F,
) -> Result<(), ProxyDnsRequestError>
where
    F: FnOnce(TcpStream) -> Fut,
    Fut: Future<Output = Result<(), ProxyDnsRequestError>>,
{
    let mut session = transport
        .open(ResidentDnsProxyTcpOpenRequest {
            binding,
            target,
            dial_ip,
            sniff_payload,
            sniff_domain,
            context,
        })
        .await?;
    let stream = session.take_stream().ok_or_else(|| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::OwnerAcquire,
            ProxyDnsRequestFailure::Network,
            "proxy DNS TCP transport returned a session without a stream",
        )
    })?;
    let run_result = run(stream).await;
    let cleanup_result = session.finish(cleanup_deadline, run_result.is_err()).await;
    match run_result {
        Ok(()) => cleanup_result.map(|_| ()).map_err(|error| {
            ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Cleanup,
                ProxyDnsRequestFailure::Network,
                error,
            )
        }),
        Err(run_error) => {
            let cleanup_detail = match cleanup_result {
                Ok(event) => format!("handler_event={event}"),
                Err(error) => format!("handler_error={error}"),
            };
            Err(ProxyDnsRequestError::new(
                run_error.stage(),
                run_error.failure(),
                format!("{run_error}; {cleanup_detail}"),
            ))
        }
    }
}
