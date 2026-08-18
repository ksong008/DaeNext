use super::*;

pub(super) async fn forward_dns_tls_to_proxy_async(
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    payload: &[u8],
    binding: ResidentProxyBinding,
    transport: Arc<dyn ResidentDnsProxyTcpTransport>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ProxyDnsRequestError> {
    let target = target.to_string();
    exchange_resident_proxy_dns_tcp_stream(
        transport.as_ref(),
        binding,
        target.clone(),
        true,
        Vec::new(),
        upstream.target.host.clone(),
        context,
        |stream| async move {
            let mut tls = open_proxy_dns_tls_stream(upstream, stream, &[], context).await?;
            exchange_proxy_dns_framed_stream(&mut tls, payload, DNS_TCP_MESSAGE_READ_LIMIT, context)
                .await
        },
    )
    .await
    .map_err(|error| {
        error.with_context(format_args!(
            "forward DNS over proxied TLS to upstream {} {} via {}",
            upstream.tag, upstream.target.authority, target
        ))
    })
}

pub(super) async fn forward_dns_https_to_proxy_async(
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    payload: &[u8],
    binding: ResidentProxyBinding,
    transport: Arc<dyn ResidentDnsProxyTcpTransport>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ProxyDnsRequestError> {
    let target = target.to_string();
    exchange_resident_proxy_dns_tcp_stream(
        transport.as_ref(),
        binding,
        target.clone(),
        true,
        Vec::new(),
        upstream.target.host.clone(),
        context,
        |stream| async move { forward_proxy_dns_https(upstream, stream, payload, context).await },
    )
    .await
    .map_err(|error| {
        error.with_context(format_args!(
            "forward DNS over proxied HTTPS to upstream {} {} via {}",
            upstream.tag, upstream.target.authority, target
        ))
    })
}

async fn forward_proxy_dns_https(
    upstream: &ResidentDnsUpstream,
    stream: TokioTcpStream,
    payload: &[u8],
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ProxyDnsRequestError> {
    let mut tls = open_proxy_dns_tls_stream(upstream, stream, &["http/1.1"], context).await?;
    match tls.alpn_protocol().as_deref() {
        None | Some(b"http/1.1") => {}
        Some(_) => {
            return Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Authenticate,
                ProxyDnsRequestFailure::Protocol,
                "proxied DNS HTTPS negotiated an unsupported application protocol",
            ));
        }
    }
    let doh = build_doh_request(
        &upstream.target.authority,
        &upstream.target.authority,
        &upstream.path,
        payload,
    )
    .map_err(|error| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Send,
            ProxyDnsRequestFailure::Protocol,
            format!("build proxied DoH request: {error}"),
        )
    })?;
    let request_target = doh_request_target(&upstream.path, doh.dns_query.as_deref());
    let request = http1_doh_request_bytes(&doh, &request_target);
    context
        .run(
            ProxyDnsRequestStage::Send,
            ProxyDnsRequestFailure::Network,
            async {
                tls.write_all(&request).await?;
                tls.flush().await
            },
        )
        .await?;
    let raw = context
        .run(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Network,
            read_to_end_capped_async(&mut tls, DNS_DOH_RESPONSE_READ_LIMIT),
        )
        .await?;
    parse_doh_http_response(payload, &raw).map_err(|error| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Protocol,
            error,
        )
    })
}

async fn open_proxy_dns_tls_stream(
    upstream: &ResidentDnsUpstream,
    stream: TokioTcpStream,
    alpn: &[&str],
    context: ProxyDnsRequestContext,
) -> Result<ResidentDnsTlsStream, ProxyDnsRequestError> {
    context
        .run(
            ProxyDnsRequestStage::Authenticate,
            ProxyDnsRequestFailure::Network,
            super::open_dns_boring_tls_stream_async(upstream, stream, alpn, context),
        )
        .await
}
