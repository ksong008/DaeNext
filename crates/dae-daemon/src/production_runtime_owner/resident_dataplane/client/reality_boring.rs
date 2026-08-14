use super::*;

pub(crate) async fn open_async_reality_boring_resident_tls_client(
    proxy: &ResidentProxyPlan,
    tcp: TokioTcpStream,
) -> Result<AsyncVlessTlsClient, String> {
    let reality = proxy
        .reality
        .as_ref()
        .ok_or_else(|| "VLESS Reality BoringSSL underlay missing reality settings".to_owned())?;
    let connector = boring_vless_connector(proxy)?;
    let mut config = connector
        .configure()
        .map_err(|err| format!("configure VLESS Reality BoringSSL client: {err}"))?;
    configure_utls_template_boring_ssl(&mut config, proxy)?;
    config.set_verify_hostname(false);
    let mldsa65_verify = reality.mldsa65_verify.clone();
    config.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
        verify_reality_boring_server_cert(ssl, mldsa65_verify.as_ref())
    });
    configure_reality_boring_ssl(&mut config, reality)?;

    let tcp = async_resident_tcp_stream_for_proxy(proxy, tcp);
    let tls = time::timeout(
        RESIDENT_CONNECT_TIMEOUT,
        tokio_boring::connect(config, &proxy.server_name, tcp),
    )
    .await
    .map_err(|_| "VLESS Reality tokio-boring handshake timeout".to_owned())?
    .map_err(|err| format!("connect VLESS Reality tokio-boring client: {err}"))?;
    Ok(AsyncVlessTlsClient {
        engine: AsyncVlessTlsEngine::RealityBoring { tls },
    })
}

pub(crate) async fn open_async_reality_boring_xhttp_endpoint_client(
    endpoint: &ResidentXhttpEndpointPlan,
    tcp: TokioTcpStream,
) -> Result<AsyncResidentTlsClient, String> {
    let reality = endpoint
        .reality
        .as_ref()
        .ok_or_else(|| "xHTTP Reality BoringSSL underlay missing reality settings".to_owned())?;
    let connector = boring_xhttp_endpoint_connector(endpoint)?;
    let mut config = connector
        .configure()
        .map_err(|err| format!("configure xHTTP Reality BoringSSL client: {err}"))?;
    configure_utls_template_boring_ssl_for_xhttp_endpoint(&mut config, endpoint)?;
    config.set_verify_hostname(false);
    let mldsa65_verify = reality.mldsa65_verify.clone();
    config.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
        verify_reality_boring_server_cert(ssl, mldsa65_verify.as_ref())
    });
    configure_reality_boring_ssl(&mut config, reality)?;

    let tcp = AsyncResidentTcpStream::new(tcp, endpoint.tls_fragment.clone());
    let tls = time::timeout(
        RESIDENT_CONNECT_TIMEOUT,
        tokio_boring::connect(config, &endpoint.server_name, tcp),
    )
    .await
    .map_err(|_| "xHTTP Reality tokio-boring handshake timeout".to_owned())?
    .map_err(|err| format!("connect xHTTP Reality tokio-boring client: {err}"))?;
    Ok(AsyncVlessTlsClient {
        engine: AsyncVlessTlsEngine::RealityBoring { tls },
    })
}
