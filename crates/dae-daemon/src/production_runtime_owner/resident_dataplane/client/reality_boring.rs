use super::*;

pub(crate) async fn open_async_reality_boring_resident_tls_client(
    proxy: &ResidentProxyPlan,
    policy: &ResidentTlsPolicy,
    tcp: TokioTcpStream,
) -> Result<AsyncVlessTlsClient, String> {
    let connector = boring_vless_connector(proxy, policy)?;
    let mut config = connector
        .configure()
        .map_err(|err| format!("configure VLESS Reality BoringSSL client: {err}"))?;
    configure_utls_template_boring_ssl(&mut config, proxy)?;
    config.set_verify_hostname(false);
    let mldsa65_verify = proxy
        .reality
        .as_ref()
        .and_then(|reality| reality.mldsa65_verify.clone());
    config.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
        verify_reality_boring_server_cert(ssl, mldsa65_verify.as_ref())
    });
    configure_reality_boring_ssl(&mut config, &policy.verification)?;

    let tcp = async_boring_resident_tcp_stream_for_proxy(proxy, tcp);
    let session_key = ResidentBoringTlsSessionKey::new(&policy.server_name);
    let tls = time::timeout(
        RESIDENT_CONNECT_TIMEOUT,
        connector.connect(config, session_key, &policy.server_name, tcp),
    )
    .await
    .map_err(|_| "VLESS Reality tokio-boring handshake timeout".to_owned())?
    .map_err(|err| format!("connect VLESS Reality tokio-boring client: {err}"))?;
    Ok(AsyncVlessTlsClient {
        engine: AsyncVlessTlsEngine::RealityBoring { tls },
    })
}
