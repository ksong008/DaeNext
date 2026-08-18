use std::future::Future;
use std::pin::Pin;

use dae_resident_plan::ResidentProxyBinding;
use dae_resident_transport::{
    ProxyDnsRequestContext, ProxyDnsRequestError, ProxyDnsRequestFailure, ProxyDnsRequestStage,
};
use tokio::net::TcpStream;
use tokio::time::Instant;

pub type ResidentDnsProxyFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

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
    ) -> ResidentDnsProxyFuture<'static, Result<String, String>>;
}

pub trait ResidentDnsProxyTcpTransport: Send + Sync {
    fn open(
        &self,
        request: ResidentDnsProxyTcpOpenRequest,
    ) -> ResidentDnsProxyFuture<'_, Result<Box<dyn ResidentDnsProxyTcpSession>, ProxyDnsRequestError>>;
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
