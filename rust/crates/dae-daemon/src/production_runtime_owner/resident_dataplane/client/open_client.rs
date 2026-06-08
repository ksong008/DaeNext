use super::*;
pub(crate) fn open_vless_tls_client(proxy: &ResidentProxyPlan) -> Result<VlessTlsClient, String> {
    open_resident_tls_client(proxy)
}

pub(crate) fn open_resident_tls_client(
    proxy: &ResidentProxyPlan,
) -> Result<VlessTlsClient, String> {
    let target = resolve_proxy_addr(proxy)?;
    let connected = magic_tcp_connect(
        target,
        &TcpDirectDialOptions {
            mark: proxy.mark,
            mptcp: proxy.mptcp,
            timeout: RESIDENT_CONNECT_TIMEOUT,
        },
    )
    .map_err(|err| format!("connect VLESS server {target}: {err}"))?;
    connected
        .stream
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set VLESS TCP read timeout: {err}"))?;
    connected
        .stream
        .set_write_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set VLESS TCP write timeout: {err}"))?;
    connected
        .stream
        .set_nodelay(true)
        .map_err(|err| format!("set VLESS TCP_NODELAY: {err}"))?;
    match ResidentTlsProvider::from_proxy(proxy)? {
        ResidentTlsProvider::FingerprintAwareBoring => {
            open_boring_resident_tls_client(proxy, connected.stream)
        }
        ResidentTlsProvider::StandardRustls => {
            open_rustls_resident_tls_client(proxy, connected.stream)
        }
    }
}

pub(crate) async fn open_async_vless_tls_client(
    proxy: &ResidentProxyPlan,
) -> Result<AsyncVlessTlsClient, String> {
    open_async_resident_tls_client(proxy).await
}

pub(crate) async fn open_async_resident_tls_client(
    proxy: &ResidentProxyPlan,
) -> Result<AsyncResidentTlsClient, String> {
    let tcp = open_proxy_tcp_stream_async(proxy.clone()).await?;
    match ResidentTlsProvider::from_proxy(proxy)? {
        ResidentTlsProvider::FingerprintAwareBoring => {
            open_async_boring_resident_tls_client(proxy, tcp).await
        }
        ResidentTlsProvider::StandardRustls => {
            open_async_rustls_resident_tls_client(proxy, tcp).await
        }
    }
}

pub(crate) async fn open_proxy_tcp_stream_async(
    proxy: ResidentProxyPlan,
) -> Result<TokioTcpStream, String> {
    let stream = task::spawn_blocking(move || {
        let target = resolve_proxy_addr(&proxy)?;
        let protocol = proxy.protocol.clone();
        let connected = magic_tcp_connect(
            target,
            &TcpDirectDialOptions {
                mark: proxy.mark,
                mptcp: proxy.mptcp,
                timeout: RESIDENT_CONNECT_TIMEOUT,
            },
        )
        .map_err(|err| format!("connect {protocol} server {target}: {err}"))?;
        connected
            .stream
            .set_read_timeout(None)
            .map_err(|err| format!("clear {protocol} TCP read timeout: {err}"))?;
        connected
            .stream
            .set_write_timeout(None)
            .map_err(|err| format!("clear {protocol} TCP write timeout: {err}"))?;
        connected
            .stream
            .set_nonblocking(true)
            .map_err(|err| format!("set {protocol} TCP nonblocking: {err}"))?;
        connected
            .stream
            .set_nodelay(true)
            .map_err(|err| format!("set {protocol} TCP_NODELAY: {err}"))?;
        Ok::<TcpStream, String>(connected.stream)
    })
    .await
    .map_err(|err| format!("join proxy TCP connect task: {err}"))??;
    TokioTcpStream::from_std(stream).map_err(|err| format!("adopt async proxy TCP stream: {err}"))
}

pub(crate) async fn open_async_rustls_resident_tls_client(
    proxy: &ResidentProxyPlan,
    tcp: TokioTcpStream,
) -> Result<AsyncVlessTlsClient, String> {
    let config = rustls_vless_client_config(proxy)?;
    let server_name = ServerName::try_from(proxy.server_name.clone())
        .map_err(|err| format!("invalid VLESS TLS server name {}: {err}", proxy.server_name))?;
    let connector = tokio_rustls::TlsConnector::from(config);
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

pub(crate) async fn open_async_boring_resident_tls_client(
    proxy: &ResidentProxyPlan,
    tcp: TokioTcpStream,
) -> Result<AsyncVlessTlsClient, String> {
    let connector = boring_vless_connector(proxy)?;
    let config = connector
        .configure()
        .map_err(|err| format!("configure VLESS BoringSSL client: {err}"))?;
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

pub(crate) fn open_rustls_resident_tls_client(
    proxy: &ResidentProxyPlan,
    tcp: TcpStream,
) -> Result<VlessTlsClient, String> {
    let config = rustls_vless_client_config(proxy)?;
    let server_name = ServerName::try_from(proxy.server_name.clone())
        .map_err(|err| format!("invalid VLESS TLS server name {}: {err}", proxy.server_name))?;
    let conn = ClientConnection::new(config, server_name)
        .map_err(|err| format!("create VLESS rustls client: {err}"))?;
    let mut client = VlessTlsClient {
        engine: VlessTlsEngine::Rustls {
            tcp,
            conn,
            tls_records: TlsRecordReader::default(),
        },
    };
    drive_tls_io_blocking(&mut client)?;
    Ok(client)
}

pub(crate) fn open_boring_resident_tls_client(
    proxy: &ResidentProxyPlan,
    tcp: TcpStream,
) -> Result<VlessTlsClient, String> {
    let connector = boring_vless_connector(proxy)?;
    let tls = connector
        .connect(&proxy.server_name, tcp)
        .map_err(|err| format!("connect VLESS BoringSSL client: {err}"))?;
    Ok(VlessTlsClient {
        engine: VlessTlsEngine::Boring {
            tls,
            pending_plaintext: Vec::new(),
        },
    })
}
