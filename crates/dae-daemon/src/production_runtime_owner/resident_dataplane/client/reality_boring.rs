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
    config.set_verify_hostname(false);
    config.set_custom_verify_callback(SslVerifyMode::PEER, verify_reality_boring_server_cert);
    configure_reality_boring_ssl(&mut config, reality)?;

    let tcp = AsyncResidentTcpStream::new(tcp, proxy.tls_fragment.clone());
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
