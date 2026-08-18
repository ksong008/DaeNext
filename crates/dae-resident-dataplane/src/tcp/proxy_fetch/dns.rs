use super::*;
use crate::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
use crate::{
    ProxyDnsRequestContext, ProxyDnsRequestError, ProxyDnsRequestFailure, ProxyDnsRequestStage,
};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn exchange_resident_proxy_dns_tcp_stream_async<F, Fut>(
    binding: ResidentProxyBinding,
    target: &str,
    dial_ip: bool,
    sniff_payload: Vec<u8>,
    sniff_domain: String,
    context: ProxyDnsRequestContext,
    owners: ResidentTransportOwnerRegistries,
    exchange: F,
) -> Result<Vec<u8>, ProxyDnsRequestError>
where
    F: FnOnce(TokioTcpStream) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, ProxyDnsRequestError>>,
{
    let (client, mut handler) = open_resident_proxy_dns_tcp_stream_async(
        binding,
        target,
        dial_ip,
        sniff_payload,
        sniff_domain,
        context,
        owners,
    )
    .await?;

    let response_result = exchange(client).await;
    handler.stop();
    let handler_result = join_proxy_dns_handler(
        handler.handle_mut(),
        context.deadline(),
        response_result.is_err(),
    )
    .await;
    match response_result {
        Ok(response) => match handler_result {
            Ok(_) => Ok(response),
            Err(error) => Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Cleanup,
                ProxyDnsRequestFailure::Network,
                error,
            )),
        },
        Err(response_error) => {
            let handler_detail = match handler_result {
                Ok(event) => format!("handler_event={}", sanitize_probe_event(event)),
                Err(error) => format!("handler_error={error}"),
            };
            Err(ProxyDnsRequestError::new(
                response_error.stage(),
                response_error.failure(),
                format!("{response_error}; {handler_detail}"),
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_resident_proxy_dns_tcp_connection_async<F, Fut>(
    binding: ResidentProxyBinding,
    target: &str,
    dial_ip: bool,
    sniff_payload: Vec<u8>,
    sniff_domain: String,
    context: ProxyDnsRequestContext,
    owners: ResidentTransportOwnerRegistries,
    run: F,
) -> Result<(), ProxyDnsRequestError>
where
    F: FnOnce(TokioTcpStream) -> Fut,
    Fut: std::future::Future<Output = Result<(), ProxyDnsRequestError>>,
{
    let (client, mut handler) = open_resident_proxy_dns_tcp_stream_async(
        binding,
        target,
        dial_ip,
        sniff_payload,
        sniff_domain,
        context,
        owners,
    )
    .await?;
    let run_result = run(client).await;
    handler.stop();
    let cleanup_deadline = time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    let handler_result =
        join_proxy_dns_handler(handler.handle_mut(), cleanup_deadline, run_result.is_err()).await;
    match run_result {
        Ok(()) => handler_result.map(|_| ()).map_err(|error| {
            ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Cleanup,
                ProxyDnsRequestFailure::Network,
                error,
            )
        }),
        Err(run_error) => {
            let handler_detail = match handler_result {
                Ok(event) => format!("handler_event={}", sanitize_probe_event(event)),
                Err(error) => format!("handler_error={error}"),
            };
            Err(ProxyDnsRequestError::new(
                run_error.stage(),
                run_error.failure(),
                format!("{run_error}; {handler_detail}"),
            ))
        }
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
