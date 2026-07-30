use super::super::*;
use super::ResidentDnsTransportError;
use super::plain::{dns_transport_route_name, open_dns_tcp_stream_with_context_async};
use super::route::{
    ResidentDnsUpstreamRoutedTarget, race_dns_upstream_targets, resolved_upstream_targets,
    select_dns_upstream_targets,
};
use super::wire::{
    doh_request_target, forward_dns_framed_stream_async, http1_doh_keep_alive_request_bytes,
    http1_doh_request_bytes, parse_doh_http_response, read_http1_response_message_capped_async,
    read_to_end_capped_async, resident_dns_tls_client_config, restore_dns_response_id,
};

mod proxy;

use self::proxy::{forward_dns_https_to_proxy_async, forward_dns_tls_to_proxy_async};

const DNS_HTTPS_H2_RETRY_COOLDOWN: std::time::Duration = RESIDENT_UDP_RESPONSE_TIMEOUT;

pub(super) async fn forward_dns_tls_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let resolved = resolved_upstream_targets(upstream)
        .await
        .map_err(ResidentDnsTransportError::message)?;
    let (targets, failures) =
        select_dns_upstream_targets(plan, upstream, resolved.to_vec(), L4Proto::Tcp)
            .map_err(ResidentDnsTransportError::message)?;
    race_dns_upstream_targets(
        upstream,
        &resolved,
        "forward DNS TLS to",
        targets,
        failures,
        forwarders.resources.upstream_candidate_race_width(),
        |target| async move {
            forward_dns_tls_to_routed_target_async(upstream, target, payload, forwarders, context)
                .await
        },
    )
    .await
}

async fn forward_dns_tls_to_routed_target_async(
    upstream: &ResidentDnsUpstream,
    target: ResidentDnsUpstreamRoutedTarget,
    payload: &[u8],
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let started_at = std::time::Instant::now();
    let remote = target.target;
    let route = dns_transport_route_name(&target.selection);
    let result = match &target.selection {
        ResidentDnsUpstreamSelection::Direct { mark } => {
            let forwarder = forwarders
                .tls_forwarder(upstream, remote, *mark, &target.selection)
                .map_err(ResidentDnsTransportError::message)?;
            forwarder.exchange(payload, context).await
        }
        ResidentDnsUpstreamSelection::Proxy { binding } => forward_dns_tls_to_proxy_async(
            upstream,
            remote,
            payload,
            binding.clone(),
            ResidentTransportOwnerRegistries::new(
                forwarders.hysteria2_owner_registry.clone(),
                forwarders.tuic_owner_registry.clone(),
                forwarders.juicity_owner_registry.clone(),
            )
            .with_anytls(forwarders.anytls_owner_registry.clone()),
            context,
        )
        .await
        .map_err(|error| ResidentDnsTransportError::proxy(error.with_context(remote))),
    };
    record_dns_transport_trace(ResidentDnsTransportTraceInput {
        upstream: upstream.tag.clone(),
        scheme: upstream.scheme.as_str(),
        target: remote,
        l4proto: L4Proto::Tcp,
        route,
        started_at,
        error: result.as_ref().err().map(ToString::to_string),
    });
    result
}

impl ResidentDnsTlsForwarder {
    async fn exchange(
        &self,
        payload: &[u8],
        context: ProxyDnsRequestContext,
    ) -> Result<Vec<u8>, ResidentDnsTransportError> {
        match self.exchange_once(payload, true, context).await {
            Ok(response) => Ok(response),
            Err(first_err) => {
                self.exchange_once(payload, false, context)
                    .await
                    .map_err(|retry_err| {
                        ResidentDnsTransportError::combined_attempts(
                            "DNS TLS pooled forwarder retry",
                            first_err,
                            retry_err,
                        )
                    })
            }
        }
    }

    async fn exchange_once(
        &self,
        payload: &[u8],
        use_idle: bool,
        context: ProxyDnsRequestContext,
    ) -> Result<Vec<u8>, ResidentDnsTransportError> {
        let _permit = acquire_dns_permit(&self.permits, "DNS TLS stream pool", context)
            .await
            .map_err(ResidentDnsTransportError::message)?;
        let mut stream = if use_idle {
            match self.idle.lock().await.pop() {
                Some(stream) => stream,
                None => {
                    let stream = open_dns_tcp_stream_with_context_async(
                        &self.upstream,
                        self.target,
                        self.mark,
                        context,
                    )
                    .await
                    .map_err(ResidentDnsTransportError::proxy)?;
                    open_dns_tls_stream_async(&self.upstream, stream, context)
                        .await
                        .map_err(ResidentDnsTransportError::message)?
                }
            }
        } else {
            let stream = open_dns_tcp_stream_with_context_async(
                &self.upstream,
                self.target,
                self.mark,
                context,
            )
            .await
            .map_err(ResidentDnsTransportError::proxy)?;
            open_dns_tls_stream_async(&self.upstream, stream, context)
                .await
                .map_err(ResidentDnsTransportError::message)?
        };
        let result = time::timeout_at(
            context.deadline(),
            forward_dns_framed_stream_async(&mut stream, payload),
        )
        .await
        .map_err(|_| ResidentDnsTransportError::message("DNS TLS exchange timeout"))?
        .map_err(|err| {
            ResidentDnsTransportError::message(format!(
                "forward DNS over TLS to upstream {} {}: {err}",
                self.upstream.tag, self.upstream.target.authority
            ))
        });
        if result.is_ok() {
            return_tls_stream_to_pool(&self.idle, stream).await;
        }
        result
    }
}

async fn return_tls_stream_to_pool(
    pool: &AsyncMutex<Vec<tokio_rustls::client::TlsStream<TokioTcpStream>>>,
    stream: tokio_rustls::client::TlsStream<TokioTcpStream>,
) {
    let mut idle = pool.lock().await;
    if idle.len() < DNS_STREAM_POOL_MAX_IDLE {
        idle.push(stream);
    }
}

async fn open_dns_tls_stream_async(
    upstream: &ResidentDnsUpstream,
    stream: TokioTcpStream,
    context: ProxyDnsRequestContext,
) -> Result<tokio_rustls::client::TlsStream<TokioTcpStream>, String> {
    let config = resident_dns_tls_client_config(&[])?;
    let server_name = ServerName::try_from(upstream.target.host.clone()).map_err(|err| {
        format!(
            "invalid DNS TLS server name {}: {err}",
            upstream.target.host
        )
    })?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let tls = time::timeout_at(context.deadline(), connector.connect(server_name, stream))
        .await
        .map_err(|_| "DNS TLS handshake timeout".to_owned())?
        .map_err(|err| {
            format!(
                "connect DNS TLS upstream {} {}: {err}",
                upstream.tag, upstream.target.authority
            )
        })?;
    Ok(tls)
}

pub(super) async fn forward_dns_https_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let resolved = resolved_upstream_targets(upstream)
        .await
        .map_err(ResidentDnsTransportError::message)?;
    let (targets, failures) =
        select_dns_upstream_targets(plan, upstream, resolved.to_vec(), L4Proto::Tcp)
            .map_err(ResidentDnsTransportError::message)?;
    race_dns_upstream_targets(
        upstream,
        &resolved,
        "forward DNS HTTPS to",
        targets,
        failures,
        forwarders.resources.upstream_candidate_race_width(),
        |target| async move {
            forward_dns_https_to_routed_target_async(upstream, target, payload, forwarders, context)
                .await
        },
    )
    .await
}

async fn forward_dns_https_to_routed_target_async(
    upstream: &ResidentDnsUpstream,
    target: ResidentDnsUpstreamRoutedTarget,
    payload: &[u8],
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let started_at = std::time::Instant::now();
    let remote = target.target;
    let route = dns_transport_route_name(&target.selection);
    let result = match &target.selection {
        ResidentDnsUpstreamSelection::Direct { mark } => {
            let forwarder = forwarders
                .https_forwarder(upstream, remote, *mark, &target.selection)
                .map_err(ResidentDnsTransportError::message)?;
            forwarder.exchange(payload, context).await
        }
        ResidentDnsUpstreamSelection::Proxy { binding } => forward_dns_https_to_proxy_async(
            upstream,
            remote,
            payload,
            binding.clone(),
            ResidentTransportOwnerRegistries::new(
                forwarders.hysteria2_owner_registry.clone(),
                forwarders.tuic_owner_registry.clone(),
                forwarders.juicity_owner_registry.clone(),
            )
            .with_anytls(forwarders.anytls_owner_registry.clone()),
            context,
        )
        .await
        .map_err(|error| ResidentDnsTransportError::proxy(error.with_context(remote))),
    };
    record_dns_transport_trace(ResidentDnsTransportTraceInput {
        upstream: upstream.tag.clone(),
        scheme: upstream.scheme.as_str(),
        target: remote,
        l4proto: L4Proto::Tcp,
        route,
        started_at,
        error: result.as_ref().err().map(ToString::to_string),
    });
    result
}

impl ResidentDnsHttpsForwarder {
    async fn exchange(
        &self,
        payload: &[u8],
        context: ProxyDnsRequestContext,
    ) -> Result<Vec<u8>, ResidentDnsTransportError> {
        let mut h2_error = None;
        if self.h2_retry_ready() {
            match self.exchange_h2(payload, context).await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    h2_error = Some(err);
                }
            }
        }
        self.exchange_http1(payload, context)
            .await
            .map_err(|http1_err| match h2_error {
                Some(h2_err) => ResidentDnsTransportError::combined_attempts(
                    "DNS HTTPS HTTP/2 and HTTP/1.1 fallback",
                    h2_err,
                    http1_err,
                ),
                None => http1_err,
            })
    }

    async fn exchange_http1(
        &self,
        payload: &[u8],
        context: ProxyDnsRequestContext,
    ) -> Result<Vec<u8>, ResidentDnsTransportError> {
        match self.exchange_http1_once(payload, true, context).await {
            Ok(response) => Ok(response),
            Err(first_err) => self
                .exchange_http1_once(payload, false, context)
                .await
                .map_err(|retry_err| {
                    ResidentDnsTransportError::combined_attempts(
                        "DNS HTTPS HTTP/1.1 pooled forwarder retry",
                        first_err,
                        retry_err,
                    )
                }),
        }
    }

    async fn exchange_http1_once(
        &self,
        payload: &[u8],
        use_idle: bool,
        context: ProxyDnsRequestContext,
    ) -> Result<Vec<u8>, ResidentDnsTransportError> {
        let _permit = acquire_dns_permit(
            &self.http1_permits,
            "DNS HTTPS HTTP/1.1 stream pool",
            context,
        )
        .await
        .map_err(ResidentDnsTransportError::message)?;
        let mut stream = if use_idle {
            match self.http1_idle.lock().await.pop() {
                Some(stream) => stream,
                None => {
                    let stream = open_dns_tcp_stream_with_context_async(
                        &self.upstream,
                        self.target,
                        self.mark,
                        context,
                    )
                    .await
                    .map_err(ResidentDnsTransportError::proxy)?;
                    open_dns_https_tls_stream_async(&self.upstream, stream, context)
                        .await
                        .map_err(ResidentDnsTransportError::message)?
                }
            }
        } else {
            let stream = open_dns_tcp_stream_with_context_async(
                &self.upstream,
                self.target,
                self.mark,
                context,
            )
            .await
            .map_err(ResidentDnsTransportError::proxy)?;
            open_dns_https_tls_stream_async(&self.upstream, stream, context)
                .await
                .map_err(ResidentDnsTransportError::message)?
        };
        let result = time::timeout_at(
            context.deadline(),
            forward_dns_https_over_reusable_stream_async(&self.upstream, &mut stream, payload),
        )
        .await
        .map_err(|_| {
            ResidentDnsTransportError::message("DNS HTTPS HTTP/1.1 absolute deadline expired")
        })?
        .map_err(ResidentDnsTransportError::message);
        if result.is_ok() {
            return_tls_stream_to_pool(&self.http1_idle, stream).await;
        }
        result
    }

    async fn exchange_h2(
        &self,
        payload: &[u8],
        context: ProxyDnsRequestContext,
    ) -> Result<Vec<u8>, ResidentDnsTransportError> {
        let _permit = acquire_dns_permit(&self.h2_permits, "DNS HTTPS HTTP/2 stream pool", context)
            .await
            .map_err(ResidentDnsTransportError::message)?;
        let mut sender = self.h2_sender(context).await?;
        let result = forward_dns_https_over_h2_async(&self.upstream, payload, &mut sender, context)
            .await
            .map_err(ResidentDnsTransportError::message);
        if result.is_err() {
            self.invalidate_h2().await;
        }
        result
    }

    async fn h2_sender(
        &self,
        context: ProxyDnsRequestContext,
    ) -> Result<h2::client::SendRequest<Bytes>, ResidentDnsTransportError> {
        {
            let h2 = self.h2.lock().await;
            if let Some(forwarder) = h2.as_ref() {
                return Ok(forwarder.sender.clone());
            }
        }
        if !self.h2_retry_ready() {
            return Err(ResidentDnsTransportError::message(
                "DNS HTTPS HTTP/2 retry cooldown is active",
            ));
        }
        let _open_guard = time::timeout_at(context.deadline(), self.h2_open_lock.lock())
            .await
            .map_err(|_| {
                ResidentDnsTransportError::message(
                    "DNS HTTPS HTTP/2 open lock absolute deadline expired",
                )
            })?;
        {
            let h2 = self.h2.lock().await;
            if let Some(forwarder) = h2.as_ref() {
                return Ok(forwarder.sender.clone());
            }
        }
        if !self.h2_retry_ready() {
            return Err(ResidentDnsTransportError::message(
                "DNS HTTPS HTTP/2 retry cooldown is active",
            ));
        }
        match open_dns_https_h2_forwarder_async(&self.upstream, self.target, self.mark, context)
            .await
        {
            Ok(forwarder) => {
                let sender = forwarder.sender.clone();
                self.record_h2_success();
                let mut h2 = self.h2.lock().await;
                *h2 = Some(forwarder);
                Ok(sender)
            }
            Err(err) => {
                self.record_h2_failure();
                Err(err)
            }
        }
    }

    async fn invalidate_h2(&self) {
        let _open_guard = self.h2_open_lock.lock().await;
        let mut h2 = self.h2.lock().await;
        *h2 = None;
        drop(h2);
        self.record_h2_failure();
    }

    fn h2_retry_ready(&self) -> bool {
        self.h2_recovery
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .should_attempt(std::time::Instant::now())
    }

    fn record_h2_failure(&self) {
        self.h2_recovery
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_failure(std::time::Instant::now(), DNS_HTTPS_H2_RETRY_COOLDOWN);
    }

    fn record_h2_success(&self) {
        self.h2_recovery
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_success();
    }
}

async fn open_dns_https_tls_stream_async(
    upstream: &ResidentDnsUpstream,
    stream: TokioTcpStream,
    context: ProxyDnsRequestContext,
) -> Result<tokio_rustls::client::TlsStream<TokioTcpStream>, String> {
    let config = resident_dns_tls_client_config(&["http/1.1"])?;
    let server_name = ServerName::try_from(upstream.target.host.clone()).map_err(|err| {
        format!(
            "invalid DNS HTTPS server name {}: {err}",
            upstream.target.host
        )
    })?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let tls = time::timeout_at(context.deadline(), connector.connect(server_name, stream))
        .await
        .map_err(|_| "DNS HTTPS TLS handshake timeout".to_owned())?
        .map_err(|err| {
            format!(
                "connect DNS HTTPS upstream {} {}: {err}",
                upstream.tag, upstream.target.authority
            )
        })?;
    Ok(tls)
}

async fn open_dns_https_h2_forwarder_async(
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    mark: u32,
    context: ProxyDnsRequestContext,
) -> Result<ResidentDnsH2Forwarder, ResidentDnsTransportError> {
    let stream = open_dns_tcp_stream_with_context_async(upstream, target, mark, context)
        .await
        .map_err(ResidentDnsTransportError::proxy)?;
    let tls = open_dns_https_h2_tls_stream_async(upstream, stream, context)
        .await
        .map_err(ResidentDnsTransportError::message)?;
    let (sender, connection) = time::timeout_at(context.deadline(), h2::client::handshake(tls))
        .await
        .map_err(|_| ResidentDnsTransportError::message("DNS HTTPS HTTP/2 handshake timeout"))?
        .map_err(|err| {
            ResidentDnsTransportError::message(format!(
                "create DNS HTTPS HTTP/2 client for upstream {} {}: {err}",
                upstream.tag, upstream.target.authority
            ))
        })?;
    let driver_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(ResidentDnsH2Forwarder {
        sender,
        driver_task,
    })
}

async fn open_dns_https_h2_tls_stream_async(
    upstream: &ResidentDnsUpstream,
    stream: TokioTcpStream,
    context: ProxyDnsRequestContext,
) -> Result<tokio_rustls::client::TlsStream<TokioTcpStream>, String> {
    let config = resident_dns_tls_client_config(&["h2"])?;
    let server_name = ServerName::try_from(upstream.target.host.clone()).map_err(|err| {
        format!(
            "invalid DNS HTTPS HTTP/2 server name {}: {err}",
            upstream.target.host
        )
    })?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let tls = time::timeout_at(context.deadline(), connector.connect(server_name, stream))
        .await
        .map_err(|_| "DNS HTTPS HTTP/2 TLS handshake timeout".to_owned())?
        .map_err(|err| {
            format!(
                "connect DNS HTTPS HTTP/2 upstream {} {}: {err}",
                upstream.tag, upstream.target.authority
            )
        })?;
    let negotiated = tls.get_ref().1.alpn_protocol();
    if negotiated != Some(b"h2".as_slice()) {
        return Err(format!(
            "DNS HTTPS upstream {} {} did not negotiate HTTP/2",
            upstream.tag, upstream.target.authority
        ));
    }
    Ok(tls)
}

async fn forward_dns_https_over_h2_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    sender: &mut h2::client::SendRequest<Bytes>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, String> {
    let doh = build_doh_request(
        &upstream.target.authority,
        &upstream.target.authority,
        &upstream.path,
        payload,
    )
    .map_err(|err| format!("build DoH HTTP/2 request: {err}"))?;
    let uri = if let Some(query) = doh.dns_query.as_deref() {
        format!(
            "https://{}{}",
            upstream.target.authority,
            doh_request_target(&upstream.path, Some(query))
        )
    } else {
        format!("https://{}{}", upstream.target.authority, upstream.path)
    };
    let mut request = Request::builder()
        .version(http::Version::HTTP_2)
        .method(doh.method.as_str())
        .uri(uri)
        .header(http::header::ACCEPT, DOH_MEDIA_TYPE);
    if !doh.content_type.is_empty() {
        request = request.header(http::header::CONTENT_TYPE, doh.content_type.as_str());
    }
    let request = request
        .body(())
        .map_err(|err| format!("build DoH HTTP/2 request: {err}"))?;
    time::timeout_at(context.deadline(), async {
        let mut sender = sender
            .clone()
            .ready()
            .await
            .map_err(|err| format!("wait for DoH HTTP/2 stream capacity: {err}"))?;
        let (response, mut body_sender) = sender
            .send_request(request, doh.body.is_empty())
            .map_err(|err| format!("send DoH HTTP/2 request headers: {err}"))?;
        if !doh.body.is_empty() {
            body_sender
                .send_data(Bytes::copy_from_slice(&doh.body), true)
                .map_err(|err| format!("send DoH HTTP/2 body: {err}"))?;
        }
        let response = response
            .await
            .map_err(|err| format!("receive DoH HTTP/2 response headers: {err}"))?;
        let status = response.status();
        let content_type = response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .map(|value| value.as_bytes().to_vec())
            .unwrap_or_default();
        validate_doh_response(status.as_u16(), status.as_str(), &content_type)
            .map_err(|err| err.to_string())?;
        let mut body = response.into_body();
        let mut out = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(|err| format!("receive DoH HTTP/2 response body: {err}"))?;
            if out.len().saturating_add(chunk.len()) > DNS_DOH_RESPONSE_READ_LIMIT {
                return Err(format!(
                    "DoH HTTP/2 response exceeds read limit {DNS_DOH_RESPONSE_READ_LIMIT}"
                ));
            }
            out.extend_from_slice(&chunk);
        }
        restore_dns_response_id(payload, &out)
    })
    .await
    .map_err(|_| "DNS HTTPS HTTP/2 exchange timeout".to_owned())?
    .map_err(|err| {
        format!(
            "forward DNS over HTTP/2 to upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })
}

async fn forward_dns_https_over_reusable_stream_async(
    upstream: &ResidentDnsUpstream,
    tls: &mut tokio_rustls::client::TlsStream<TokioTcpStream>,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let doh = build_doh_request(
        &upstream.target.authority,
        &upstream.target.authority,
        &upstream.path,
        payload,
    )
    .map_err(|err| format!("build DoH request: {err}"))?;
    let request_target = doh_request_target(&upstream.path, doh.dns_query.as_deref());
    let request = http1_doh_keep_alive_request_bytes(&doh, &request_target);
    time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, async {
        tls.write_all(&request)
            .await
            .map_err(|err| format!("write DoH request: {err}"))?;
        tls.flush()
            .await
            .map_err(|err| format!("flush DoH request: {err}"))?;
        let raw =
            read_http1_response_message_capped_async(tls, DNS_DOH_RESPONSE_READ_LIMIT).await?;
        parse_doh_http_response(payload, &raw)
    })
    .await
    .map_err(|_| "DNS HTTPS exchange timeout".to_owned())?
    .map_err(|err| {
        format!(
            "forward DNS over HTTPS to upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const H2_DOH_TEST_AUTHORITY: &str = "doh-fixture.invalid";
    const H2_DOH_TEST_PATH: &str = "/dns-query";

    #[tokio::test]
    async fn doh_h2_forwarder_handles_concurrent_streams() {
        let (client_io, server_io) = tokio::io::duplex(DNS_DOH_RESPONSE_READ_LIMIT);
        let (sender, connection) = h2::client::handshake(client_io).await.unwrap();
        let client_driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let first_query = build_dns_query_packet(0x1111, "first.example", DNS_QTYPE_A).unwrap();
        let second_query = build_dns_query_packet(0x2222, "second.example", DNS_QTYPE_A).unwrap();
        let server_first = first_query.clone();
        let server_second = second_query.clone();
        let server = tokio::spawn(async move {
            let mut server = h2::server::handshake(server_io).await.unwrap();
            let first = server.accept().await.unwrap().unwrap();
            let second = server.accept().await.unwrap().unwrap();
            send_h2_doh_response(second.1, &server_second, [192, 0, 2, 2]);
            send_h2_doh_response(first.1, &server_first, [192, 0, 2, 1]);
            let _ = time::timeout(RESIDENT_IDLE_SLEEP, server.accept()).await;
        });
        let upstream = h2_test_upstream();
        let mut first_sender = sender.clone();
        let mut second_sender = sender;
        let context = ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(1));
        let (first, second) = tokio::join!(
            forward_dns_https_over_h2_async(&upstream, &first_query, &mut first_sender, context,),
            forward_dns_https_over_h2_async(&upstream, &second_query, &mut second_sender, context,),
        );

        assert_eq!(&first.unwrap()[0..2], &0x1111_u16.to_be_bytes());
        assert_eq!(&second.unwrap()[0..2], &0x2222_u16.to_be_bytes());
        server.await.unwrap();
        client_driver.abort();
    }

    fn send_h2_doh_response(
        mut respond: h2::server::SendResponse<Bytes>,
        query: &[u8],
        address: [u8; 4],
    ) {
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CONTENT_TYPE, DOH_MEDIA_TYPE)
            .body(())
            .unwrap();
        let mut stream = respond.send_response(response, false).unwrap();
        let response = dns_a_response_for_query(&dns_data_with_zero_id(query), address);
        stream.send_data(Bytes::from(response), true).unwrap();
    }

    fn h2_test_upstream() -> ResidentDnsUpstream {
        ResidentDnsUpstream {
            index: 0,
            tag: "h2-fixture".to_owned(),
            target: ResidentDnsUpstreamTarget {
                authority: H2_DOH_TEST_AUTHORITY.to_owned(),
                host: H2_DOH_TEST_AUTHORITY.to_owned(),
                port: DNS_HTTPS_DEFAULT_PORT,
                literal_addr: None,
                fallback_resolver: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    DNS_DEFAULT_PORT,
                ),
                resolver_mark: 0,
                resolved_addrs: Arc::default(),
            },
            scheme: ResidentDnsUpstreamScheme::Https,
            path: H2_DOH_TEST_PATH.to_owned(),
        }
    }

    fn dns_a_response_for_query(query: &[u8], address: [u8; 4]) -> Vec<u8> {
        let view = DnsPacketView::parse(query).unwrap();
        let mut response = Vec::new();
        response.extend_from_slice(&query[0..2]);
        response.extend_from_slice(&0x8180_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&query[12..view.answer_offset()]);
        response.extend_from_slice(&0xc00c_u16.to_be_bytes());
        response.extend_from_slice(&DNS_QTYPE_A.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&address);
        response
    }
}
