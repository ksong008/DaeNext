use super::*;

pub(crate) async fn open_async_resident_tls_client_with_binding(
    binding: &ResidentProxyBinding,
    mptcp: bool,
) -> Result<AsyncResidentTlsClient, String> {
    let tcp = open_proxy_tcp_stream_with_binding(binding, mptcp).await?;
    open_async_resident_tls_client_over_stream(binding.plan(), tcp).await
}

pub(crate) async fn open_async_vless_tls_client_with_flow_at_candidates(
    proxy: &ResidentProxyPlan,
    candidates: &[SocketAddr],
    mark: u32,
    mptcp: bool,
) -> Result<AsyncVlessTlsClient, String> {
    if proxy.chain_parent.is_some() {
        return Err(
            "xHTTP shared transport parent chains are rejected by the typed chain contract"
                .to_owned(),
        );
    }
    let tcp = open_proxy_tcp_stream_at_candidates(proxy, candidates, mark, mptcp).await?;
    open_async_resident_tls_client_over_stream(proxy, tcp).await
}

async fn open_async_resident_tls_client_over_stream(
    proxy: &ResidentProxyPlan,
    tcp: TokioTcpStream,
) -> Result<AsyncResidentTlsClient, String> {
    match ResidentTlsProvider::from_proxy(proxy)? {
        ResidentTlsProvider::FingerprintAwareBoring => {
            open_async_boring_resident_tls_client(proxy, tcp).await
        }
        ResidentTlsProvider::RealityRustls => {
            open_async_reality_rustls_resident_tls_client(proxy, tcp).await
        }
        ResidentTlsProvider::RealityFingerprintBoring => {
            open_async_reality_boring_resident_tls_client(proxy, tcp).await
        }
        ResidentTlsProvider::StandardRustls => {
            open_async_rustls_resident_tls_client(proxy, tcp).await
        }
    }
}

pub(super) fn async_resident_tcp_stream_for_proxy(
    proxy: &ResidentProxyPlan,
    tcp: TokioTcpStream,
) -> AsyncResidentTcpStream {
    // The record-bounded transport gate is needed by the legacy Vision path:
    // after Xray's DIRECT command, that path hands the connection itself to
    // raw TCP.  VLESS Encryption + Vision is different.  Its DIRECT command
    // only hands off the *inner VLESS record wrapper*; the outer TLS session
    // must continue to consume subsequent TLS records.  Putting a bounded
    // reader underneath rustls would leave it parked at the first record
    // boundary and make the post-DIRECT response look like a stalled socket.
    let vision_encryption = proxy.vless_encryption().ok().flatten().is_some();
    if proxy.execution_plan().protocol == ResidentProtocolShape::VlessVision && !vision_encryption {
        AsyncResidentTcpStream::new_vision(tcp, proxy.tls_fragment.clone())
    } else {
        AsyncResidentTcpStream::new(tcp, proxy.tls_fragment.clone())
    }
}

pub(crate) async fn open_async_xhttp_endpoint_tls_client(
    endpoint: &ResidentXhttpEndpointPlan,
    mark: u32,
    mptcp: bool,
) -> Result<AsyncResidentTlsClient, String> {
    let tcp = open_xhttp_endpoint_tcp_stream_async(endpoint, mark, mptcp).await?;
    open_async_xhttp_endpoint_tls_client_over_stream(endpoint, tcp).await
}

pub(crate) async fn open_async_xhttp_endpoint_tls_client_at_candidates(
    endpoint: &ResidentXhttpEndpointPlan,
    candidates: &[SocketAddr],
    mark: u32,
    mptcp: bool,
) -> Result<AsyncResidentTlsClient, String> {
    let tcp =
        open_xhttp_endpoint_tcp_stream_at_candidates(endpoint, candidates, mark, mptcp).await?;
    open_async_xhttp_endpoint_tls_client_over_stream(endpoint, tcp).await
}

async fn open_async_xhttp_endpoint_tls_client_over_stream(
    endpoint: &ResidentXhttpEndpointPlan,
    tcp: TokioTcpStream,
) -> Result<AsyncResidentTlsClient, String> {
    let config = rustls_xhttp_endpoint_client_config(endpoint)?;
    let server_name = ServerName::try_from(endpoint.server_name.clone()).map_err(|err| {
        format!(
            "invalid xHTTP TLS server name {}: {err}",
            endpoint.server_name
        )
    })?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let tcp = AsyncResidentTcpStream::new(tcp, endpoint.tls_fragment.clone());
    let tls = time::timeout(
        RESIDENT_CONNECT_TIMEOUT,
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_| "xHTTP tokio-rustls handshake timeout".to_owned())?
    .map_err(|err| format!("connect xHTTP tokio-rustls client: {err}"))?;
    Ok(AsyncVlessTlsClient {
        engine: AsyncVlessTlsEngine::Rustls { tls },
    })
}

#[cfg(test)]
pub(crate) async fn open_proxy_tcp_stream_async(
    proxy: &ResidentProxyPlan,
) -> Result<TokioTcpStream, String> {
    open_proxy_tcp_stream_async_with_flow(proxy, proxy.mark, proxy.mptcp).await
}

#[cfg(test)]
pub(crate) async fn open_proxy_tcp_stream_async_with_flow(
    proxy: &ResidentProxyPlan,
    mark: u32,
    mptcp: bool,
) -> Result<TokioTcpStream, String> {
    if let Some(parent) = proxy.chain_parent.as_deref() {
        return open_proxy_tcp_stream_through_configured_parent_async(proxy, parent).await;
    }
    let protocol = &proxy.protocol;
    let target = authority_from_host_port(proxy.server_host.as_str(), proxy.server_port);
    let connected = open_direct_tcp_connection_async(target.clone(), mark, mptcp)
        .await
        .map_err(|err| format!("connect {protocol} server {target}: {err}"))?;
    connected
        .stream
        .set_read_timeout(None)
        .map_err(|err| format!("clear {protocol} TCP read timeout: {err}"))?;
    connected
        .stream
        .set_write_timeout(None)
        .map_err(|err| format!("clear {protocol} TCP write timeout: {err}"))?;
    TokioTcpStream::from_std(connected.stream)
        .map_err(|err| format!("adopt async proxy TCP stream: {err}"))
}

pub(crate) async fn open_proxy_tcp_stream_with_binding(
    binding: &ResidentProxyBinding,
    mptcp: bool,
) -> Result<TokioTcpStream, String> {
    let proxy = binding.plan();
    if proxy.chain_parent.is_some() {
        return open_proxy_tcp_stream_through_parent_async(binding).await;
    }
    let protocol = &proxy.protocol;
    let target = authority_from_host_port(proxy.server_host.as_str(), proxy.server_port);
    let connected =
        open_direct_tcp_connection_async(target.clone(), binding.effective_socket_mark(), mptcp)
            .await
            .map_err(|err| format!("connect {protocol} server {target}: {err}"))?;
    connected
        .stream
        .set_read_timeout(None)
        .map_err(|err| format!("clear {protocol} TCP read timeout: {err}"))?;
    connected
        .stream
        .set_write_timeout(None)
        .map_err(|err| format!("clear {protocol} TCP write timeout: {err}"))?;
    TokioTcpStream::from_std(connected.stream)
        .map_err(|err| format!("adopt async proxy TCP stream: {err}"))
}

pub(crate) async fn open_xhttp_endpoint_tcp_stream_async(
    endpoint: &ResidentXhttpEndpointPlan,
    mark: u32,
    mptcp: bool,
) -> Result<TokioTcpStream, String> {
    let target = format!("{}:{}", endpoint.server_host, endpoint.server_port);
    let connected = open_direct_tcp_connection_async(target.clone(), mark, mptcp)
        .await
        .map_err(|err| format!("connect xHTTP endpoint {target}: {err}"))?;
    connected
        .stream
        .set_read_timeout(None)
        .map_err(|err| format!("clear xHTTP endpoint TCP read timeout: {err}"))?;
    connected
        .stream
        .set_write_timeout(None)
        .map_err(|err| format!("clear xHTTP endpoint TCP write timeout: {err}"))?;
    TokioTcpStream::from_std(connected.stream)
        .map_err(|err| format!("adopt async xHTTP endpoint TCP stream: {err}"))
}

async fn open_proxy_tcp_stream_at_candidates(
    proxy: &ResidentProxyPlan,
    candidates: &[SocketAddr],
    mark: u32,
    mptcp: bool,
) -> Result<TokioTcpStream, String> {
    let protocol = proxy.protocol;
    let connected = open_direct_tcp_connection_at_candidates(
        candidates,
        mark,
        mptcp,
        &format!("connect resolved {protocol} server"),
    )
    .await?;
    adopt_direct_tcp_connection(
        connected,
        &format!("clear {protocol} TCP read timeout"),
        &format!("clear {protocol} TCP write timeout"),
        "adopt async proxy TCP stream",
    )
}

async fn open_xhttp_endpoint_tcp_stream_at_candidates(
    _endpoint: &ResidentXhttpEndpointPlan,
    candidates: &[SocketAddr],
    mark: u32,
    mptcp: bool,
) -> Result<TokioTcpStream, String> {
    let connected = open_direct_tcp_connection_at_candidates(
        candidates,
        mark,
        mptcp,
        "connect resolved xHTTP endpoint",
    )
    .await?;
    adopt_direct_tcp_connection(
        connected,
        "clear xHTTP endpoint TCP read timeout",
        "clear xHTTP endpoint TCP write timeout",
        "adopt async xHTTP endpoint TCP stream",
    )
}

async fn open_direct_tcp_connection_at_candidates(
    candidates: &[SocketAddr],
    mark: u32,
    mptcp: bool,
    context: &str,
) -> Result<DirectTcpConnection, String> {
    let (_, connected) = try_tcp_socket_addr_candidates(
        candidates,
        context,
        TcpCandidateRacePolicy::new(
            RESIDENT_TCP_CANDIDATE_ATTEMPT_DELAY,
            RESIDENT_CONNECT_TIMEOUT,
            RESIDENT_TCP_CANDIDATE_MAX_IN_FLIGHT,
        ),
        |candidate| open_direct_tcp_connection_async(candidate.to_string(), mark, mptcp),
    )
    .await
    .map_err(|err| err.to_string())?;
    Ok(connected)
}

fn adopt_direct_tcp_connection(
    connected: DirectTcpConnection,
    read_context: &str,
    write_context: &str,
    adopt_context: &str,
) -> Result<TokioTcpStream, String> {
    connected
        .stream
        .set_read_timeout(None)
        .map_err(|err| format!("{read_context}: {err}"))?;
    connected
        .stream
        .set_write_timeout(None)
        .map_err(|err| format!("{write_context}: {err}"))?;
    TokioTcpStream::from_std(connected.stream).map_err(|err| format!("{adopt_context}: {err}"))
}

pub(crate) async fn open_async_rustls_resident_tls_client(
    proxy: &ResidentProxyPlan,
    tcp: TokioTcpStream,
) -> Result<AsyncVlessTlsClient, String> {
    let config = rustls_vless_client_config(proxy)?;
    let server_name = ServerName::try_from(proxy.server_name.clone())
        .map_err(|err| format!("invalid VLESS TLS server name {}: {err}", proxy.server_name))?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let tcp = async_resident_tcp_stream_for_proxy(proxy, tcp);
    let tls = time::timeout(
        RESIDENT_CONNECT_TIMEOUT,
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_| "VLESS tokio-rustls handshake timeout".to_owned())?
    .map_err(|err| format!("connect VLESS tokio-rustls client: {err}"))?;
    Ok(AsyncVlessTlsClient {
        engine: AsyncVlessTlsEngine::Rustls { tls },
    })
}

pub(crate) async fn open_async_reality_rustls_resident_tls_client(
    proxy: &ResidentProxyPlan,
    tcp: TokioTcpStream,
) -> Result<AsyncVlessTlsClient, String> {
    let config = rustls_vless_client_config(proxy)?;
    let server_name = ServerName::try_from(proxy.server_name.clone()).map_err(|err| {
        format!(
            "invalid VLESS Reality server name {}: {err}",
            proxy.server_name
        )
    })?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let tcp = async_resident_tcp_stream_for_proxy(proxy, tcp);
    let tls = time::timeout(
        RESIDENT_CONNECT_TIMEOUT,
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_| "VLESS Reality tokio-rustls handshake timeout".to_owned())?
    .map_err(|err| format!("connect VLESS Reality tokio-rustls client: {err}"))?;
    Ok(AsyncVlessTlsClient {
        engine: AsyncVlessTlsEngine::RealityRustls { tls },
    })
}

pub(crate) async fn open_async_boring_resident_tls_client(
    proxy: &ResidentProxyPlan,
    tcp: TokioTcpStream,
) -> Result<AsyncVlessTlsClient, String> {
    let connector = boring_vless_connector(proxy)?;
    let mut config = connector
        .configure()
        .map_err(|err| format!("configure VLESS BoringSSL client: {err}"))?;
    configure_utls_template_boring_ssl(&mut config, proxy)?;
    let tcp = async_resident_tcp_stream_for_proxy(proxy, tcp);
    let tls = time::timeout(
        RESIDENT_CONNECT_TIMEOUT,
        tokio_boring::connect(config, &proxy.server_name, tcp),
    )
    .await
    .map_err(|_| "VLESS tokio-boring handshake timeout".to_owned())?
    .map_err(|err| format!("connect VLESS tokio-boring client: {err}"))?;
    Ok(AsyncVlessTlsClient {
        engine: AsyncVlessTlsEngine::Boring { tls },
    })
}
