use super::*;

const DNS_UDP_FORWARD_ATTEMPTS: usize = 3;

pub(super) async fn forward_dns_to_upstream_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    mark: u32,
    forwarders: &Arc<ResidentDnsForwarderCache>,
) -> Result<Vec<u8>, String> {
    match upstream.scheme {
        ResidentDnsUpstreamScheme::Udp => {
            forward_dns_udp_upstream_async(upstream, payload, mark).await
        }
        ResidentDnsUpstreamScheme::Tcp => forward_dns_tcp_async(upstream, payload, mark).await,
        ResidentDnsUpstreamScheme::TcpUdp => {
            forward_dns_tcp_udp_async(upstream, payload, mark).await
        }
        ResidentDnsUpstreamScheme::Tls => forward_dns_tls_async(upstream, payload, mark).await,
        ResidentDnsUpstreamScheme::Https => forward_dns_https_async(upstream, payload, mark).await,
        ResidentDnsUpstreamScheme::Quic => {
            let forwarder = forwarders.quic_forwarder(upstream, mark)?;
            forward_dns_quic_cached(forwarder, payload).await
        }
        ResidentDnsUpstreamScheme::Http3 => forward_dns_h3_async(upstream, payload, mark).await,
    }
}

async fn resolved_upstream_targets(
    upstream: &ResidentDnsUpstream,
) -> Result<Vec<SocketAddr>, String> {
    upstream.target.resolve_addrs().await
}

fn dns_upstream_targets_failed(
    upstream: &ResidentDnsUpstream,
    operation: &str,
    failures: Vec<String>,
) -> String {
    let detail = if failures.is_empty() {
        "no target attempted".to_owned()
    } else {
        failures.join("; ")
    };
    format!(
        "{operation} upstream {} {} failed for all resolved targets: {detail}",
        upstream.tag, upstream.target.authority
    )
}

async fn forward_dns_udp_upstream_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let mut failures = Vec::new();
    for target in resolved_upstream_targets(upstream).await? {
        match forward_dns_udp_async(target, payload, mark).await {
            Ok(response) => return Ok(response),
            Err(err) => failures.push(format!("{target}: {err}")),
        }
    }
    Err(dns_upstream_targets_failed(
        upstream,
        "forward DNS UDP to",
        failures,
    ))
}

async fn forward_dns_tcp_udp_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let mut failures = Vec::new();
    for target in resolved_upstream_targets(upstream).await? {
        match forward_dns_udp_async(target, payload, mark).await {
            Ok(response) if !dns_response_truncated(&response) => return Ok(response),
            Ok(_) => match forward_dns_tcp_to_target_async(upstream, target, payload, mark).await {
                Ok(response) => return Ok(response),
                Err(err) => failures.push(format!("{target} TCP after truncated UDP: {err}")),
            },
            Err(err) => failures.push(format!("{target} UDP: {err}")),
        }
    }
    Err(dns_upstream_targets_failed(
        upstream,
        "forward DNS tcp+udp to",
        failures,
    ))
}

impl ResidentDnsForwarderCache {
    pub(super) fn quic_forwarder(
        &self,
        upstream: &ResidentDnsUpstream,
        mark: u32,
    ) -> Result<Arc<AsyncMutex<ResidentDnsQuicForwarder>>, String> {
        let key = ResidentDnsForwarderKey {
            scheme: upstream.scheme,
            authority: upstream.target.authority.clone(),
            path: upstream.path.clone(),
            mark,
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS forwarder cache lock poisoned".to_owned())?;
        state.next_tick = state.next_tick.wrapping_add(1);
        let last_used = state.next_tick;
        if let Some(entry) = state.entries.get_mut(&key) {
            entry.last_used = last_used;
            return Ok(Arc::clone(&entry.quic));
        }
        if state.entries.len() >= DNS_FORWARDER_CACHE_MAX_ENTRIES {
            evict_oldest_dns_forwarder(&mut state);
        }
        let forwarder = Arc::new(AsyncMutex::new(ResidentDnsQuicForwarder {
            upstream: upstream.clone(),
            mark,
            endpoint: None,
            connection: None,
        }));
        state.entries.insert(
            key,
            ResidentDnsForwarderEntry {
                last_used,
                quic: Arc::clone(&forwarder),
            },
        );
        Ok(forwarder)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.entries.len())
            .unwrap_or_default()
    }
}

fn evict_oldest_dns_forwarder(state: &mut ResidentDnsForwarderCacheState) {
    let Some(oldest_key) = state
        .entries
        .iter()
        .min_by_key(|(_, entry)| entry.last_used)
        .map(|(key, _)| key.clone())
    else {
        return;
    };
    state.entries.remove(&oldest_key);
}

async fn forward_dns_quic_cached(
    forwarder: Arc<AsyncMutex<ResidentDnsQuicForwarder>>,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let (connection, upstream) = {
        let mut forwarder = forwarder.lock().await;
        (forwarder.connection().await?, forwarder.upstream.clone())
    };
    match forward_dns_over_quic_connection(&upstream, &connection, payload).await {
        Ok(response) => Ok(response),
        Err(first_err) => {
            let (connection, upstream) = {
                let mut forwarder = forwarder.lock().await;
                forwarder.close_connection();
                (forwarder.connection().await?, forwarder.upstream.clone())
            };
            forward_dns_over_quic_connection(&upstream, &connection, payload)
                .await
                .map_err(|retry_err| {
                    format!("DNS QUIC cached forwarder retry failed after {first_err}: {retry_err}")
                })
        }
    }
}

impl ResidentDnsQuicForwarder {
    async fn connection(&mut self) -> Result<quinn::Connection, String> {
        if let Some(connection) = self.connection.as_ref() {
            return Ok(connection.clone());
        }
        let mut failures = Vec::new();
        for remote in resolved_upstream_targets(&self.upstream).await? {
            match self.connect_remote(remote).await {
                Ok(connection) => return Ok(connection),
                Err(err) => failures.push(format!("{remote}: {err}")),
            }
        }
        Err(dns_upstream_targets_failed(
            &self.upstream,
            "connect DNS QUIC to",
            failures,
        ))
    }

    async fn connect_remote(&mut self, remote: SocketAddr) -> Result<quinn::Connection, String> {
        let mut endpoint = open_marked_quic_endpoint_for_remote(self.mark, remote)?;
        endpoint.set_default_client_config(resident_dns_quic_client_config(DNS_DOQ_ALPN)?);
        let connection = time::timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            endpoint
                .connect(remote, &self.upstream.target.host)
                .map_err(|err| format!("connect DoQ endpoint: {err}"))?,
        )
        .await
        .map_err(|_| "DNS QUIC handshake timeout".to_owned())?
        .map_err(|err| {
            format!(
                "connect DNS QUIC upstream {} {}: {err}",
                self.upstream.tag, self.upstream.target.authority
            )
        })?;
        self.endpoint = Some(endpoint);
        self.connection = Some(connection.clone());
        Ok(connection)
    }

    fn close_connection(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), b"dns-query failed");
        }
    }
}

async fn forward_dns_over_quic_connection(
    upstream: &ResidentDnsUpstream,
    connection: &quinn::Connection,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let (mut send, mut recv) = time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, connection.open_bi())
        .await
        .map_err(|_| "DNS QUIC stream open timeout".to_owned())?
        .map_err(|err| format!("open DNS QUIC stream: {err}"))?;
    let query = dns_data_with_zero_id(payload);
    time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, async {
        write_dns_tcp_message_async(&mut send, &query).await?;
        send.finish()
            .map_err(|err| format!("finish DNS QUIC request stream: {err}"))?;
        let response = read_dns_tcp_message_async(&mut recv).await?;
        restore_dns_response_id(payload, &response)
    })
    .await
    .map_err(|_| "DNS QUIC exchange timeout".to_owned())?
    .map_err(|err| {
        format!(
            "forward DNS over QUIC to upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })
}

pub(super) async fn forward_dns_udp_async(
    target: SocketAddr,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    forward_dns_udp_with_attempts_async(
        target,
        payload,
        mark,
        DNS_UDP_FORWARD_ATTEMPTS,
        dns_udp_forward_attempt_timeout(),
    )
    .await
}

async fn forward_dns_udp_with_attempts_async(
    target: SocketAddr,
    payload: &[u8],
    mark: u32,
    attempts: usize,
    attempt_timeout: std::time::Duration,
) -> Result<Vec<u8>, String> {
    let attempts = attempts.max(1);
    let bind = match target {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket =
        std::net::UdpSocket::bind(bind).map_err(|err| format!("bind DNS UDP socket: {err}"))?;
    if mark != 0 {
        set_socket_mark(socket.as_raw_fd(), mark)
            .map_err(|err| format!("set DNS UDP SO_MARK {mark}: {err}"))?;
    }
    socket
        .set_nonblocking(true)
        .map_err(|err| format!("set DNS UDP nonblocking: {err}"))?;
    let socket = tokio::net::UdpSocket::from_std(socket)
        .map_err(|err| format!("adopt async DNS UDP socket: {err}"))?;
    for attempt in 0..attempts {
        socket
            .send_to(payload, target)
            .await
            .map_err(|err| format!("send DNS UDP packet: {err}"))?;
        let mut response = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
        match time::timeout(attempt_timeout, socket.recv_from(&mut response)).await {
            Ok(Ok((read, _))) => {
                response.truncate(read);
                return Ok(response);
            }
            Ok(Err(err)) => return Err(format!("receive DNS UDP response: {err}")),
            Err(_) if attempt + 1 < attempts => continue,
            Err(_) => {
                return Err(format!(
                    "receive DNS UDP response timeout after {attempts} attempts"
                ));
            }
        }
    }
    Err("receive DNS UDP response timeout".to_owned())
}

fn dns_udp_forward_attempt_timeout() -> std::time::Duration {
    let divisor = (DNS_UDP_FORWARD_ATTEMPTS as u128).saturating_add(1);
    let millis = RESIDENT_UDP_RESPONSE_TIMEOUT
        .as_millis()
        .saturating_div(divisor)
        .max(1);
    std::time::Duration::from_millis(millis.min(u64::MAX as u128) as u64)
}

async fn forward_dns_tcp_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let mut failures = Vec::new();
    for target in resolved_upstream_targets(upstream).await? {
        match forward_dns_tcp_to_target_async(upstream, target, payload, mark).await {
            Ok(response) => return Ok(response),
            Err(err) => failures.push(format!("{target}: {err}")),
        }
    }
    Err(dns_upstream_targets_failed(
        upstream,
        "forward DNS TCP to",
        failures,
    ))
}

async fn forward_dns_tcp_to_target_async(
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let mut stream = open_dns_tcp_stream_async(upstream, target, mark).await?;
    time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        forward_dns_framed_stream_async(&mut stream, payload),
    )
    .await
    .map_err(|_| "DNS TCP exchange timeout".to_owned())?
    .map_err(|err| {
        format!(
            "forward DNS over TCP to upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })
}

async fn forward_dns_tls_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let mut failures = Vec::new();
    for target in resolved_upstream_targets(upstream).await? {
        match forward_dns_tls_to_target_async(upstream, target, payload, mark).await {
            Ok(response) => return Ok(response),
            Err(err) => failures.push(format!("{target}: {err}")),
        }
    }
    Err(dns_upstream_targets_failed(
        upstream,
        "forward DNS TLS to",
        failures,
    ))
}

async fn forward_dns_tls_to_target_async(
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let stream = open_dns_tcp_stream_async(upstream, target, mark).await?;
    let config = resident_dns_tls_client_config(&[])?;
    let server_name = ServerName::try_from(upstream.target.host.clone()).map_err(|err| {
        format!(
            "invalid DNS TLS server name {}: {err}",
            upstream.target.host
        )
    })?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let mut tls = time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| "DNS TLS handshake timeout".to_owned())?
    .map_err(|err| {
        format!(
            "connect DNS TLS upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })?;
    time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        forward_dns_framed_stream_async(&mut tls, payload),
    )
    .await
    .map_err(|_| "DNS TLS exchange timeout".to_owned())?
    .map_err(|err| {
        format!(
            "forward DNS over TLS to upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })
}

async fn forward_dns_https_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let mut failures = Vec::new();
    for target in resolved_upstream_targets(upstream).await? {
        match forward_dns_https_to_target_async(upstream, target, payload, mark).await {
            Ok(response) => return Ok(response),
            Err(err) => failures.push(format!("{target}: {err}")),
        }
    }
    Err(dns_upstream_targets_failed(
        upstream,
        "forward DNS HTTPS to",
        failures,
    ))
}

async fn forward_dns_https_to_target_async(
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let stream = open_dns_tcp_stream_async(upstream, target, mark).await?;
    let config = resident_dns_tls_client_config(&["http/1.1"])?;
    let server_name = ServerName::try_from(upstream.target.host.clone()).map_err(|err| {
        format!(
            "invalid DNS HTTPS server name {}: {err}",
            upstream.target.host
        )
    })?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let mut tls = time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| "DNS HTTPS TLS handshake timeout".to_owned())?
    .map_err(|err| {
        format!(
            "connect DNS HTTPS upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })?;
    let doh = build_doh_request(
        &upstream.target.authority,
        &upstream.target.authority,
        &upstream.path,
        payload,
    )
    .map_err(|err| format!("build DoH request: {err}"))?;
    let request_target = doh_request_target(&upstream.path, doh.dns_query.as_deref());
    let request = http1_doh_request_bytes(&doh, &request_target);
    time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, async {
        tls.write_all(&request)
            .await
            .map_err(|err| format!("write DoH request: {err}"))?;
        tls.flush()
            .await
            .map_err(|err| format!("flush DoH request: {err}"))?;
        let raw = read_to_end_capped_async(&mut tls, DNS_DOH_RESPONSE_READ_LIMIT).await?;
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

async fn forward_dns_h3_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let mut failures = Vec::new();
    for remote in resolved_upstream_targets(upstream).await? {
        match forward_dns_h3_to_target_async(upstream, remote, payload, mark).await {
            Ok(response) => return Ok(response),
            Err(err) => failures.push(format!("{remote}: {err}")),
        }
    }
    Err(dns_upstream_targets_failed(
        upstream,
        "forward DNS H3 to",
        failures,
    ))
}

async fn forward_dns_h3_to_target_async(
    upstream: &ResidentDnsUpstream,
    remote: SocketAddr,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let mut endpoint = open_marked_quic_endpoint_for_remote(mark, remote)?;
    endpoint.set_default_client_config(resident_dns_quic_client_config(DNS_DOH3_ALPN)?);
    let connection = time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        endpoint
            .connect(remote, &upstream.target.host)
            .map_err(|err| format!("connect DoH3 endpoint: {err}"))?,
    )
    .await
    .map_err(|_| "DNS H3 handshake timeout".to_owned())?
    .map_err(|err| {
        format!(
            "connect DNS H3 upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })?;
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut driver, mut client) = h3::client::new(h3_connection)
        .await
        .map_err(|err| format!("create DNS H3 client: {err:?}"))?;
    let driver_task = tokio::spawn(async move { poll_fn(|cx| driver.poll_close(cx)).await });

    let response = time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, async {
        let doh = build_doh_request(
            &upstream.target.authority,
            &upstream.target.authority,
            &upstream.path,
            payload,
        )
        .map_err(|err| format!("build DoH3 request: {err}"))?;
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
        let request = builder
            .body(())
            .map_err(|err| format!("build DoH3 HTTP request: {err}"))?;
        let mut stream = client
            .send_request(request)
            .await
            .map_err(|err| format!("send DoH3 request: {err:?}"))?;
        if !doh.body.is_empty() {
            stream
                .send_data(Bytes::copy_from_slice(&doh.body))
                .await
                .map_err(|err| format!("send DoH3 body: {err:?}"))?;
        }
        stream
            .finish()
            .await
            .map_err(|err| format!("finish DoH3 request: {err:?}"))?;
        let response = stream
            .recv_response()
            .await
            .map_err(|err| format!("recv DoH3 response: {err:?}"))?;
        let content_type = response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .map(|value| value.as_bytes().to_vec())
            .unwrap_or_default();
        let status = response.status();
        let mut body = Vec::new();
        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|err| format!("recv DoH3 response body: {err:?}"))?
        {
            let remaining = chunk.remaining();
            if body.len().saturating_add(remaining) > DNS_DOH_RESPONSE_READ_LIMIT {
                return Err(format!(
                    "DoH3 response exceeds read limit {DNS_DOH_RESPONSE_READ_LIMIT}"
                ));
            }
            body.extend_from_slice(&chunk.copy_to_bytes(remaining));
        }
        validate_doh_response(status.as_u16(), status.as_str(), &content_type)
            .map_err(|err| err.to_string())?;
        restore_dns_response_id(payload, &body)
    })
    .await
    .map_err(|_| "DNS H3 exchange timeout".to_owned())?
    .map_err(|err| {
        format!(
            "forward DNS over HTTP/3 to upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })?;
    drop(client);
    connection.close(0_u32.into(), b"dns-query done");
    endpoint.wait_idle().await;
    let _ = driver_task.await;
    Ok(response)
}

async fn open_dns_tcp_stream_async(
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    mark: u32,
) -> Result<TokioTcpStream, String> {
    let connected = open_direct_tcp_connection_async(target.to_string(), mark, false)
        .await
        .map_err(|err| {
            format!(
                "connect DNS upstream {} {}: {err}",
                upstream.tag, upstream.target.authority
            )
        })?;
    TokioTcpStream::from_std(connected.stream).map_err(|err| format!("adopt DNS TCP stream: {err}"))
}

async fn forward_dns_framed_stream_async<S>(
    stream: &mut S,
    payload: &[u8],
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_dns_tcp_message_async(stream, payload).await?;
    stream
        .flush()
        .await
        .map_err(|err| format!("flush DNS framed request: {err}"))?;
    read_dns_tcp_message_async(stream).await
}

async fn write_dns_tcp_message_async<S>(stream: &mut S, payload: &[u8]) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    let len = u16::try_from(payload.len())
        .map_err(|_| format!("DNS request exceeds TCP frame limit: {}", payload.len()))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|err| format!("write DNS TCP frame length: {err}"))?;
    stream
        .write_all(payload)
        .await
        .map_err(|err| format!("write DNS TCP frame payload: {err}"))
}

async fn read_dns_tcp_message_async<S>(stream: &mut S) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut len = [0_u8; 2];
    stream
        .read_exact(&mut len)
        .await
        .map_err(|err| format!("read DNS TCP response length: {err}"))?;
    let len = u16::from_be_bytes(len) as usize;
    if len > DNS_TCP_MESSAGE_READ_LIMIT {
        return Err(format!("DNS TCP response length {len} exceeds read limit"));
    }
    let mut response = vec![0_u8; len];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|err| format!("read DNS TCP response payload: {err}"))?;
    Ok(response)
}

fn resident_dns_tls_client_config(alpn: &[&str]) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    Ok(Arc::new(config))
}

fn resident_dns_quic_client_config(alpn: &str) -> Result<quinn::ClientConfig, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut crypto = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![alpn.as_bytes().to_vec()];
    Ok(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)
            .map_err(|err| format!("build DNS QUIC client TLS config: {err}"))?,
    )))
}

fn http1_doh_request_bytes(doh: &dae_dns::DohRequest, target: &str) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(doh.method.as_bytes());
    request.extend_from_slice(b" ");
    request.extend_from_slice(target.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    request.extend_from_slice(doh.host.as_bytes());
    request.extend_from_slice(b"\r\nAccept: ");
    request.extend_from_slice(doh.accept.as_bytes());
    request.extend_from_slice(b"\r\nConnection: close\r\n");
    if !doh.content_type.is_empty() {
        request.extend_from_slice(b"Content-Type: ");
        request.extend_from_slice(doh.content_type.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    if !doh.body.is_empty() {
        request.extend_from_slice(b"Content-Length: ");
        request.extend_from_slice(doh.body.len().to_string().as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(&doh.body);
    request
}

fn doh_request_target(path: &str, dns_query: Option<&str>) -> String {
    match dns_query {
        Some(query) if path.contains('?') => format!("{path}&dns={query}"),
        Some(query) => format!("{path}?dns={query}"),
        None => path.to_owned(),
    }
}

async fn read_to_end_capped_async<S>(stream: &mut S, limit: usize) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut buf = [0_u8; 8192];
    loop {
        let read = stream
            .read(&mut buf)
            .await
            .map_err(|err| format!("read HTTP response: {err}"))?;
        if read == 0 {
            return Ok(out);
        }
        if out.len().saturating_add(read) > limit {
            return Err(format!("HTTP response exceeds read limit {limit}"));
        }
        out.extend_from_slice(&buf[..read]);
    }
}

pub(super) fn parse_doh_http_response(request: &[u8], raw: &[u8]) -> Result<Vec<u8>, String> {
    let header_end = find_http_header_end(raw).ok_or("DoH response has no header end")?;
    let headers = &raw[..header_end];
    let mut body = raw[header_end + 4..].to_vec();
    let header_text = std::str::from_utf8(headers)
        .map_err(|err| format!("DoH response headers are not UTF-8: {err}"))?;
    let mut lines = header_text.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| "DoH response has no status line".to_owned())?;
    let status_code = status
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("DoH response status line is malformed: {status}"))?
        .parse::<u16>()
        .map_err(|err| format!("parse DoH response status code: {err}"))?;
    let mut content_type = Vec::new();
    let mut chunked = false;
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-type" => content_type = value.as_bytes().to_vec(),
            "content-length" => {
                content_length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|err| format!("parse DoH content-length: {err}"))?,
                );
            }
            "transfer-encoding" if value.to_ascii_lowercase().contains("chunked") => chunked = true,
            _ => {}
        }
    }
    validate_doh_response(status_code, status, &content_type).map_err(|err| err.to_string())?;
    if chunked {
        body = decode_http_chunked_body(&body)?;
    } else if let Some(len) = content_length {
        if body.len() < len {
            return Err(format!(
                "DoH response body shorter than content-length: {} < {len}",
                body.len()
            ));
        }
        body.truncate(len);
    }
    restore_dns_response_id(request, &body)
}

fn find_http_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

fn decode_http_chunked_body(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut offset = 0_usize;
    let mut out = Vec::new();
    loop {
        let line_end = raw[offset..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|index| offset + index)
            .ok_or_else(|| "chunked DoH body has no chunk-size line end".to_owned())?;
        let line = std::str::from_utf8(&raw[offset..line_end])
            .map_err(|err| format!("chunked DoH size line is not UTF-8: {err}"))?;
        let size_hex = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|err| format!("parse chunked DoH size {size_hex:?}: {err}"))?;
        offset = line_end + 2;
        if size == 0 {
            return Ok(out);
        }
        let end = offset
            .checked_add(size)
            .ok_or_else(|| "chunked DoH body size overflow".to_owned())?;
        if raw.len() < end + 2 {
            return Err("chunked DoH body is truncated".to_owned());
        }
        out.extend_from_slice(&raw[offset..end]);
        if &raw[end..end + 2] != b"\r\n" {
            return Err("chunked DoH chunk missing trailing CRLF".to_owned());
        }
        offset = end + 2;
    }
}

fn restore_dns_response_id(request: &[u8], response: &[u8]) -> Result<Vec<u8>, String> {
    if request.len() < 2 {
        return Err("DNS request is too short to restore response id".to_owned());
    }
    let request_id = u16::from_be_bytes([request[0], request[1]]);
    restore_packed_response_request_id(response, request_id)
        .ok_or_else(|| "DNS response is too short to restore request id".to_owned())
}

fn dns_response_truncated(response: &[u8]) -> bool {
    response
        .get(2..4)
        .map(|flags| u16::from_be_bytes([flags[0], flags[1]]) & 0x0200 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn forward_dns_udp_retries_after_timeout() {
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = upstream.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buf = [0_u8; 64];
            let _ = upstream.recv_from(&mut buf).await.unwrap();
            let (read, peer) = upstream.recv_from(&mut buf).await.unwrap();
            upstream.send_to(&buf[..read], peer).await.unwrap();
        });

        let response = forward_dns_udp_with_attempts_async(
            target,
            b"fixture-query",
            0,
            2,
            std::time::Duration::from_millis(20),
        )
        .await
        .unwrap();

        assert_eq!(response, b"fixture-query");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn forward_dns_udp_reports_attempt_count_after_timeouts() {
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = upstream.local_addr().unwrap();
        let _server = tokio::spawn(async move {
            let mut buf = [0_u8; 64];
            while upstream.recv_from(&mut buf).await.is_ok() {}
        });

        let err = forward_dns_udp_with_attempts_async(
            target,
            b"fixture-query",
            0,
            2,
            std::time::Duration::from_millis(5),
        )
        .await
        .unwrap_err();

        assert!(err.contains("after 2 attempts"));
    }

    #[tokio::test]
    async fn forward_dns_tcp_tries_next_resolved_target_after_connect_failure() {
        let closed = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let server_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = server_listener.accept().await.unwrap();
            let mut len = [0_u8; 2];
            stream.read_exact(&mut len).await.unwrap();
            let len = u16::from_be_bytes(len) as usize;
            let mut payload = vec![0_u8; len];
            stream.read_exact(&mut payload).await.unwrap();
            stream
                .write_all(&(payload.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&payload).await.unwrap();
        });

        let resolved_addrs = Arc::new(OnceCell::new());
        resolved_addrs.set(vec![closed, server_addr]).unwrap();
        let upstream = ResidentDnsUpstream {
            index: 0,
            tag: "test".to_owned(),
            target: ResidentDnsUpstreamTarget {
                authority: "test.example:53".to_owned(),
                host: "test.example".to_owned(),
                port: 53,
                literal_addr: None,
                fallback_resolver: "127.0.0.1:53".parse().unwrap(),
                resolver_mark: 0,
                resolved_addrs,
            },
            scheme: ResidentDnsUpstreamScheme::Tcp,
            path: String::new(),
        };

        let response = forward_dns_tcp_async(&upstream, b"fixture-query", 0)
            .await
            .unwrap();

        assert_eq!(response, b"fixture-query");
        server.await.unwrap();
    }
}
