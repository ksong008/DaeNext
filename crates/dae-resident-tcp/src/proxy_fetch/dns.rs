use super::*;
use crate::{
    ProxyDnsRequestContext, ProxyDnsRequestError, ProxyDnsRequestFailure, ProxyDnsRequestStage,
};
use dae_resident_dns::{
    ResidentDnsProxyFuture, ResidentDnsProxyTcpOpenRequest, ResidentDnsProxyTcpSession,
    ResidentDnsProxyTcpTransport,
};

pub fn resident_dns_proxy_tcp_transport(
    owners: ResidentTransportOwnerRegistries,
) -> Arc<dyn ResidentDnsProxyTcpTransport> {
    Arc::new(ResidentDataplaneDnsProxyTcpTransport { owners })
}

struct ResidentDataplaneDnsProxyTcpTransport {
    owners: ResidentTransportOwnerRegistries,
}

struct ResidentDataplaneDnsProxyTcpSession {
    stream: Option<TokioTcpStream>,
    handler: Option<ResidentProxyTcpHandlerGuard>,
}

impl ResidentDnsProxyTcpTransport for ResidentDataplaneDnsProxyTcpTransport {
    fn open(
        &self,
        request: ResidentDnsProxyTcpOpenRequest,
    ) -> ResidentDnsProxyFuture<'_, Result<Box<dyn ResidentDnsProxyTcpSession>, ProxyDnsRequestError>>
    {
        let owners = self.owners.clone();
        Box::pin(async move {
            let (stream, handler) = open_resident_proxy_dns_tcp_stream_async(
                request.binding,
                &request.target,
                request.dial_ip,
                request.sniff_payload,
                request.sniff_domain,
                request.context,
                owners,
            )
            .await?;
            Ok(Box::new(ResidentDataplaneDnsProxyTcpSession {
                stream: Some(stream),
                handler: Some(handler),
            }) as Box<dyn ResidentDnsProxyTcpSession>)
        })
    }
}

impl ResidentDnsProxyTcpSession for ResidentDataplaneDnsProxyTcpSession {
    fn take_stream(&mut self) -> Option<TokioTcpStream> {
        self.stream.take()
    }

    fn finish(
        mut self: Box<Self>,
        deadline: time::Instant,
        exchange_failed: bool,
    ) -> ResidentDnsProxyFuture<'static, Result<String, String>> {
        let Some(mut handler) = self.handler.take() else {
            return Box::pin(async {
                Err("proxy DNS TCP session handler is unavailable".to_owned())
            });
        };
        handler.stop();
        Box::pin(async move {
            join_proxy_dns_handler(handler.handle_mut(), deadline, exchange_failed)
                .await
                .map(sanitize_probe_event)
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn open_resident_proxy_dns_tcp_stream_async(
    binding: ResidentProxyBinding,
    target: &str,
    dial_ip: bool,
    sniff_payload: Vec<u8>,
    sniff_domain: String,
    context: ProxyDnsRequestContext,
    owners: ResidentTransportOwnerRegistries,
) -> Result<(TokioTcpStream, ResidentProxyTcpHandlerGuard), ProxyDnsRequestError> {
    let listener = bind_proxy_dns_loopback_listener(context).await?;
    context.ensure(ProxyDnsRequestStage::OwnerAcquire)?;
    let listen_addr = listener.local_addr().map_err(|error| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::OwnerAcquire,
            ProxyDnsRequestFailure::Network,
            format!("read resident proxy TCP listener address: {error}"),
        )
    })?;
    let client = context
        .run(
            ProxyDnsRequestStage::OwnerAcquire,
            ProxyDnsRequestFailure::Network,
            TokioTcpStream::connect(listen_addr),
        )
        .await?;
    let (accepted, peer) = context
        .run(
            ProxyDnsRequestStage::OwnerAcquire,
            ProxyDnsRequestFailure::Network,
            listener.accept(),
        )
        .await?;
    context.ensure(ProxyDnsRequestStage::OwnerAcquire)?;
    let handler = start_resident_proxy_tcp_handler(
        binding,
        target,
        dial_ip,
        sniff_payload,
        sniff_domain,
        accepted,
        peer,
        listen_addr,
        owners.hysteria2(),
        owners.tuic(),
        owners.juicity(),
        owners.anytls(),
        Some(dae_runtime_control::AbsoluteDeadline::at(
            context.deadline().into_std(),
        )),
    );
    Ok((client, handler))
}

async fn bind_proxy_dns_loopback_listener(
    context: ProxyDnsRequestContext,
) -> Result<TokioTcpListener, ProxyDnsRequestError> {
    let ipv6_addr = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 0);
    match context
        .run(
            ProxyDnsRequestStage::OwnerAcquire,
            ProxyDnsRequestFailure::Network,
            TokioTcpListener::bind(ipv6_addr),
        )
        .await
    {
        Ok(listener) => Ok(listener),
        Err(error) if error.failure() == ProxyDnsRequestFailure::Network => {
            let ipv4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
            context
                .run(
                    ProxyDnsRequestStage::OwnerAcquire,
                    ProxyDnsRequestFailure::Network,
                    TokioTcpListener::bind(ipv4_addr),
                )
                .await
                .map_err(|ipv4_error| {
                    ProxyDnsRequestError::new(
                        ipv4_error.stage(),
                        ipv4_error.failure(),
                        format!(
                            "bind resident proxy DNS loopback listener: ipv6={error}; ipv4={ipv4_error}"
                        ),
                    )
                })
        }
        Err(error) => Err(error),
    }
}

async fn join_proxy_dns_handler(
    handle: &mut tokio::task::JoinHandle<Result<Value, String>>,
    deadline: time::Instant,
    response_failed: bool,
) -> Result<Value, String> {
    let deadline = if response_failed {
        std::cmp::min(
            deadline,
            time::Instant::now() + RESIDENT_TCP_FAILED_HANDLER_JOIN_GRACE,
        )
    } else {
        deadline
    };
    match time::timeout_at(deadline, &mut *handle).await {
        Ok(joined) => joined.map_err(|error| format!("join resident TCP handler: {error}"))?,
        Err(_) => {
            handle.abort();
            let _ = (&mut *handle).await;
            Err("join resident TCP handler: absolute deadline expired".to_owned())
        }
    }
}
