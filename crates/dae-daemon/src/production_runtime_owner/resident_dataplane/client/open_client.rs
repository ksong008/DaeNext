use super::*;

pub(crate) async fn open_async_vless_tls_client_with_flow(
    proxy: &ResidentProxyPlan,
    mark: u32,
    mptcp: bool,
) -> Result<AsyncVlessTlsClient, String> {
    open_async_resident_tls_client_with_flow(proxy, mark, mptcp).await
}

pub(crate) async fn open_async_resident_tls_client(
    proxy: &ResidentProxyPlan,
) -> Result<AsyncResidentTlsClient, String> {
    open_async_resident_tls_client_with_flow(proxy, proxy.mark, proxy.mptcp).await
}

pub(crate) async fn open_async_resident_tls_client_with_flow(
    proxy: &ResidentProxyPlan,
    mark: u32,
    mptcp: bool,
) -> Result<AsyncResidentTlsClient, String> {
    let tcp = open_proxy_tcp_stream_async_with_flow(proxy, mark, mptcp).await?;
    match ResidentTlsProvider::from_proxy(proxy)? {
        ResidentTlsProvider::FingerprintAwareBoring => {
            open_async_boring_resident_tls_client(proxy, tcp).await
        }
        ResidentTlsProvider::RealityRustls => {
            open_async_reality_rustls_resident_tls_client(proxy, tcp).await
        }
        ResidentTlsProvider::StandardRustls => {
            open_async_rustls_resident_tls_client(proxy, tcp).await
        }
    }
}

pub(crate) async fn open_async_xhttp_endpoint_tls_client(
    endpoint: &ResidentXhttpEndpointPlan,
    mark: u32,
    mptcp: bool,
) -> Result<AsyncResidentTlsClient, String> {
    let tcp = open_xhttp_endpoint_tcp_stream_async(endpoint, mark, mptcp).await?;
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

pub(crate) async fn open_proxy_tcp_stream_async(
    proxy: &ResidentProxyPlan,
) -> Result<TokioTcpStream, String> {
    open_proxy_tcp_stream_async_with_flow(proxy, proxy.mark, proxy.mptcp).await
}

pub(crate) async fn open_proxy_tcp_stream_async_with_flow(
    proxy: &ResidentProxyPlan,
    mark: u32,
    mptcp: bool,
) -> Result<TokioTcpStream, String> {
    let protocol = &proxy.protocol;
    let target = format!("{}:{}", proxy.server_host, proxy.server_port);
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

pub(crate) async fn open_async_rustls_resident_tls_client(
    proxy: &ResidentProxyPlan,
    tcp: TokioTcpStream,
) -> Result<AsyncVlessTlsClient, String> {
    let config = rustls_vless_client_config(proxy)?;
    let server_name = ServerName::try_from(proxy.server_name.clone())
        .map_err(|err| format!("invalid VLESS TLS server name {}: {err}", proxy.server_name))?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let tcp = AsyncResidentTcpStream::new(tcp, proxy.tls_fragment.clone());
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
    let tcp = AsyncResidentTcpStream::new(tcp, proxy.tls_fragment.clone());
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
    let config = connector
        .configure()
        .map_err(|err| format!("configure VLESS BoringSSL client: {err}"))?;
    let tcp = AsyncResidentTcpStream::new(tcp, proxy.tls_fragment.clone());
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
