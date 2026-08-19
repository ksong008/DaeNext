use super::*;

pub async fn forward_proxied_dns_h3_request(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    client: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ProxyDnsRequestError> {
    context.ensure(ProxyDnsRequestStage::Send)?;
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
            format!("build proxied DoH3 request: {error}"),
        )
    })?;
    let uri = if let Some(query) = doh.dns_query.as_deref() {
        format!(
            "https://{}{}",
            upstream.target.authority,
            doh_request_target(&upstream.path, Some(query))
        )
    } else {
        format!("https://{}{}", upstream.target.authority, upstream.path)
    };
    let mut builder = Request::builder()
        .method(doh.method.as_str())
        .uri(uri)
        .header(http::header::ACCEPT, DOH_MEDIA_TYPE);
    if !doh.content_type.is_empty() {
        builder = builder.header(http::header::CONTENT_TYPE, doh.content_type.as_str());
    }
    let request = builder.body(()).map_err(|error| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Send,
            ProxyDnsRequestFailure::Protocol,
            format!("build proxied DoH3 HTTP request: {error}"),
        )
    })?;
    let mut stream = context
        .run(
            ProxyDnsRequestStage::Send,
            ProxyDnsRequestFailure::Network,
            async {
                client
                    .send_request(request)
                    .await
                    .map_err(|error| format!("send proxied DoH3 request: {error:?}"))
            },
        )
        .await?;
    context
        .run(
            ProxyDnsRequestStage::Send,
            ProxyDnsRequestFailure::Network,
            async {
                if !doh.body.is_empty() {
                    stream
                        .send_data(Bytes::copy_from_slice(&doh.body))
                        .await
                        .map_err(|error| format!("send proxied DoH3 body: {error:?}"))?;
                }
                stream
                    .finish()
                    .await
                    .map_err(|error| format!("finish proxied DoH3 request: {error:?}"))
            },
        )
        .await?;
    let (response, body) = context
        .run_typed(ProxyDnsRequestStage::Read, async {
            let response = stream.recv_response().await.map_err(|error| {
                ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::Read,
                    ProxyDnsRequestFailure::Network,
                    format!("receive proxied DoH3 response: {error:?}"),
                )
            })?;
            let mut body = Vec::new();
            loop {
                let chunk = stream.recv_data().await.map_err(|error| {
                    ProxyDnsRequestError::new(
                        ProxyDnsRequestStage::Read,
                        ProxyDnsRequestFailure::Network,
                        format!("receive proxied DoH3 body: {error:?}"),
                    )
                })?;
                let Some(mut chunk) = chunk else {
                    break;
                };
                let remaining = chunk.remaining();
                if body.len().saturating_add(remaining) > DNS_DOH_RESPONSE_READ_LIMIT {
                    return Err(ProxyDnsRequestError::new(
                        ProxyDnsRequestStage::Read,
                        ProxyDnsRequestFailure::Capacity,
                        format!(
                            "proxied DoH3 response exceeds read limit {DNS_DOH_RESPONSE_READ_LIMIT}"
                        ),
                    ));
                }
                body.extend_from_slice(&chunk.copy_to_bytes(remaining));
            }
            Ok((response, body))
        })
        .await?;
    let content_type = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .map(|value| value.as_bytes().to_vec())
        .unwrap_or_default();
    let status = response.status();
    validate_doh_response(status.as_u16(), status.as_str(), &content_type).map_err(|error| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Protocol,
            error.to_string(),
        )
    })?;
    restore_dns_response_id(payload, &body).map_err(|error| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Protocol,
            error,
        )
    })
}
