use super::*;

pub(crate) async fn open_async_resident_tls_client_with_binding(
    binding: &ResidentProxyBinding,
    mptcp: bool,
) -> Result<AsyncResidentTlsClient, String> {
    let tcp = open_proxy_tcp_stream_with_binding(binding, mptcp).await?;
    if binding.plan().ech.is_some() {
        return open_async_boring_ech_resident_tls_client_with_binding(binding, mptcp, tcp).await;
    }
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
    if proxy.ech.is_some() {
        return open_async_boring_ech_resident_tls_client_at_candidates(
            proxy, candidates, mark, mptcp, tcp,
        )
        .await;
    }
    open_async_resident_tls_client_over_stream(proxy, tcp).await
}

async fn open_async_resident_tls_client_over_stream(
    proxy: &ResidentProxyPlan,
    tcp: TokioTcpStream,
) -> Result<AsyncResidentTlsClient, String> {
    let selection = ResidentTlsFactorySelection::from_proxy(proxy)?;
    let policy = &selection.policy;
    match selection.provider {
        ResidentTlsProvider::FingerprintAwareBoring => {
            open_async_boring_resident_tls_client(proxy, policy, tcp).await
        }
        ResidentTlsProvider::RealityFingerprintBoring => {
            open_async_reality_boring_resident_tls_client(proxy, policy, tcp).await
        }
    }
}

pub(super) fn async_boring_resident_tcp_stream_for_proxy(
    proxy: &ResidentProxyPlan,
    tcp: TokioTcpStream,
) -> AsyncResidentTcpStream {
    let vision_encryption = proxy.vless_encryption().ok().flatten().is_some();
    if proxy.execution_plan().protocol == ResidentProtocolShape::VlessVision && !vision_encryption {
        AsyncResidentTcpStream::new_vision(tcp, proxy.tls_fragment.clone())
    } else {
        AsyncResidentTcpStream::new_boring(tcp, proxy.tls_fragment.clone())
    }
}

pub(crate) async fn open_async_xhttp_endpoint_tls_client(
    endpoint: &ResidentXhttpEndpointPlan,
    mark: u32,
    mptcp: bool,
) -> Result<AsyncResidentTlsClient, String> {
    let tcp = open_xhttp_endpoint_tcp_stream_async(endpoint, mark, mptcp).await?;
    if endpoint.ech.is_some() {
        return open_async_boring_ech_xhttp_client(endpoint, mark, mptcp, tcp).await;
    }
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
    if endpoint.ech.is_some() {
        return open_async_boring_ech_xhttp_client_at_candidates(
            endpoint, candidates, mark, mptcp, tcp,
        )
        .await;
    }
    open_async_xhttp_endpoint_tls_client_over_stream(endpoint, tcp).await
}

async fn open_async_xhttp_endpoint_tls_client_over_stream(
    endpoint: &ResidentXhttpEndpointPlan,
    tcp: TokioTcpStream,
) -> Result<AsyncResidentTlsClient, String> {
    let selection = ResidentTlsFactorySelection::from_xhttp_endpoint(endpoint)?;
    match selection.provider {
        ResidentTlsProvider::FingerprintAwareBoring
        | ResidentTlsProvider::RealityFingerprintBoring => {
            open_async_boring_xhttp_endpoint_tls_client_over_stream(
                endpoint,
                &selection.policy,
                tcp,
            )
            .await
        }
    }
}

async fn open_async_boring_xhttp_endpoint_tls_client_over_stream(
    endpoint: &ResidentXhttpEndpointPlan,
    policy: &ResidentTlsPolicy,
    tcp: TokioTcpStream,
) -> Result<AsyncResidentTlsClient, String> {
    let connector = boring_xhttp_endpoint_connector(endpoint)?;
    let mut config = connector
        .configure()
        .map_err(|err| format!("configure xHTTP BoringSSL client: {err}"))?;
    configure_utls_template_boring_ssl_for_xhttp_endpoint(&mut config, endpoint)?;
    let reality = policy.verification.reality_material().is_some();
    if reality {
        config.set_verify_hostname(false);
        let mldsa65_verify = endpoint
            .reality
            .as_ref()
            .and_then(|reality| reality.mldsa65_verify.clone());
        config.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            verify_reality_boring_server_cert(ssl, mldsa65_verify.as_ref())
        });
        configure_reality_boring_ssl(&mut config, &policy.verification)?;
    }
    let tcp = AsyncResidentTcpStream::new_boring(tcp, endpoint.tls_fragment.clone());
    let session_key = ResidentBoringTlsSessionKey::new(&policy.server_name);
    let tls = time::timeout(
        RESIDENT_CONNECT_TIMEOUT,
        connector.connect(config, session_key, &policy.server_name, tcp),
    )
    .await
    .map_err(|_| "xHTTP tokio-boring handshake timeout".to_owned())?
    .map_err(|err| format!("connect xHTTP tokio-boring client: {err}"))?;
    Ok(AsyncVlessTlsClient {
        engine: if reality {
            AsyncVlessTlsEngine::RealityBoring { tls }
        } else {
            AsyncVlessTlsEngine::Boring { tls }
        },
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

pub(crate) async fn open_async_boring_resident_tls_client(
    proxy: &ResidentProxyPlan,
    policy: &ResidentTlsPolicy,
    tcp: TokioTcpStream,
) -> Result<AsyncVlessTlsClient, String> {
    let connector = boring_vless_connector(proxy, policy)?;
    let mut config = connector
        .configure()
        .map_err(|err| format!("configure VLESS BoringSSL client: {err}"))?;
    configure_utls_template_boring_ssl(&mut config, proxy)?;
    let tcp = async_boring_resident_tcp_stream_for_proxy(proxy, tcp);
    let session_key = ResidentBoringTlsSessionKey::new(&policy.server_name);
    let tls = time::timeout(
        RESIDENT_CONNECT_TIMEOUT,
        connector.connect(config, session_key, &policy.server_name, tcp),
    )
    .await
    .map_err(|_| "VLESS tokio-boring handshake timeout".to_owned())?
    .map_err(|err| format!("connect VLESS tokio-boring client: {err}"))?;
    Ok(AsyncVlessTlsClient {
        engine: AsyncVlessTlsEngine::Boring { tls },
    })
}

#[derive(Debug)]
enum ResidentEchHandshakeError {
    Rejected(Vec<u8>),
    Failed(String),
}

async fn open_async_boring_ech_resident_tls_client_with_binding(
    binding: &ResidentProxyBinding,
    mptcp: bool,
    initial_tcp: TokioTcpStream,
) -> Result<AsyncResidentTlsClient, String> {
    let proxy = binding.plan();
    let initial = proxy
        .ech
        .as_ref()
        .ok_or_else(|| "resident ECH plan missing config list".to_owned())?;
    match open_async_boring_ech_resident_tls_attempt(
        proxy,
        initial_tcp,
        initial.config_list_bytes(),
    )
    .await
    {
        Ok(client) => Ok(client),
        Err(ResidentEchHandshakeError::Rejected(retry)) => {
            let retry = validated_ech_retry_config(retry)?;
            let tcp = open_proxy_tcp_stream_with_binding(binding, mptcp).await?;
            finish_boring_ech_resident_retry(proxy, tcp, &retry).await
        }
        Err(ResidentEchHandshakeError::Failed(error)) => Err(error),
    }
}

async fn open_async_boring_ech_resident_tls_client_at_candidates(
    proxy: &ResidentProxyPlan,
    candidates: &[SocketAddr],
    mark: u32,
    mptcp: bool,
    initial_tcp: TokioTcpStream,
) -> Result<AsyncResidentTlsClient, String> {
    let initial = proxy
        .ech
        .as_ref()
        .ok_or_else(|| "resident ECH plan missing config list".to_owned())?;
    match open_async_boring_ech_resident_tls_attempt(
        proxy,
        initial_tcp,
        initial.config_list_bytes(),
    )
    .await
    {
        Ok(client) => Ok(client),
        Err(ResidentEchHandshakeError::Rejected(retry)) => {
            let retry = validated_ech_retry_config(retry)?;
            let tcp = open_proxy_tcp_stream_at_candidates(proxy, candidates, mark, mptcp).await?;
            finish_boring_ech_resident_retry(proxy, tcp, &retry).await
        }
        Err(ResidentEchHandshakeError::Failed(error)) => Err(error),
    }
}

async fn finish_boring_ech_resident_retry(
    proxy: &ResidentProxyPlan,
    tcp: TokioTcpStream,
    retry: &EchConfigList,
) -> Result<AsyncResidentTlsClient, String> {
    finish_boring_ech_retry_result(
        open_async_boring_ech_resident_tls_attempt(proxy, tcp, retry.bytes()).await,
        "VLESS",
    )
}

async fn open_async_boring_ech_resident_tls_attempt(
    proxy: &ResidentProxyPlan,
    tcp: TokioTcpStream,
    ech_config_list: &[u8],
) -> Result<AsyncResidentTlsClient, ResidentEchHandshakeError> {
    let policy = ResidentTlsPolicy::from_proxy(proxy);
    let connector =
        boring_vless_connector(proxy, &policy).map_err(ResidentEchHandshakeError::Failed)?;
    let mut config = connector.configure().map_err(|err| {
        ResidentEchHandshakeError::Failed(format!("configure VLESS ECH BoringSSL client: {err}"))
    })?;
    configure_utls_template_boring_ssl(&mut config, proxy)
        .map_err(ResidentEchHandshakeError::Failed)?;
    config.set_ech_config_list(ech_config_list).map_err(|err| {
        ResidentEchHandshakeError::Failed(format!("set VLESS BoringSSL ECHConfigList: {err}"))
    })?;
    let tcp = async_boring_resident_tcp_stream_for_proxy(proxy, tcp);
    let session_key =
        ResidentBoringTlsSessionKey::with_ech_config_list(&proxy.server_name, ech_config_list);
    let result = time::timeout(
        RESIDENT_CONNECT_TIMEOUT,
        connector.connect(config, session_key, &proxy.server_name, tcp),
    )
    .await
    .map_err(|_| {
        ResidentEchHandshakeError::Failed("VLESS BoringSSL ECH handshake timeout".to_owned())
    })?;
    match result {
        Ok(tls) if tls.ssl().ech_accepted() => Ok(AsyncVlessTlsClient {
            engine: AsyncVlessTlsEngine::Boring { tls },
        }),
        Ok(_) => Err(ResidentEchHandshakeError::Failed(
            "VLESS BoringSSL handshake completed without accepting required ECH".to_owned(),
        )),
        Err(error) => Err(classify_boring_ech_handshake_error(
            error,
            proxy.allow_insecure,
            "VLESS",
        )),
    }
}

async fn open_async_boring_ech_xhttp_client(
    endpoint: &ResidentXhttpEndpointPlan,
    mark: u32,
    mptcp: bool,
    initial_tcp: TokioTcpStream,
) -> Result<AsyncResidentTlsClient, String> {
    let initial = endpoint
        .ech
        .as_ref()
        .ok_or_else(|| "xHTTP ECH plan missing config list".to_owned())?;
    match open_async_boring_ech_xhttp_attempt(endpoint, initial_tcp, initial.config_list_bytes())
        .await
    {
        Ok(client) => Ok(client),
        Err(ResidentEchHandshakeError::Rejected(retry)) => {
            let retry = validated_ech_retry_config(retry)?;
            let tcp = open_xhttp_endpoint_tcp_stream_async(endpoint, mark, mptcp).await?;
            finish_boring_ech_xhttp_retry(endpoint, tcp, &retry).await
        }
        Err(ResidentEchHandshakeError::Failed(error)) => Err(error),
    }
}

async fn open_async_boring_ech_xhttp_client_at_candidates(
    endpoint: &ResidentXhttpEndpointPlan,
    candidates: &[SocketAddr],
    mark: u32,
    mptcp: bool,
    initial_tcp: TokioTcpStream,
) -> Result<AsyncResidentTlsClient, String> {
    let initial = endpoint
        .ech
        .as_ref()
        .ok_or_else(|| "xHTTP ECH plan missing config list".to_owned())?;
    match open_async_boring_ech_xhttp_attempt(endpoint, initial_tcp, initial.config_list_bytes())
        .await
    {
        Ok(client) => Ok(client),
        Err(ResidentEchHandshakeError::Rejected(retry)) => {
            let retry = validated_ech_retry_config(retry)?;
            let tcp =
                open_xhttp_endpoint_tcp_stream_at_candidates(endpoint, candidates, mark, mptcp)
                    .await?;
            finish_boring_ech_xhttp_retry(endpoint, tcp, &retry).await
        }
        Err(ResidentEchHandshakeError::Failed(error)) => Err(error),
    }
}

async fn finish_boring_ech_xhttp_retry(
    endpoint: &ResidentXhttpEndpointPlan,
    tcp: TokioTcpStream,
    retry: &EchConfigList,
) -> Result<AsyncResidentTlsClient, String> {
    finish_boring_ech_retry_result(
        open_async_boring_ech_xhttp_attempt(endpoint, tcp, retry.bytes()).await,
        "xHTTP",
    )
}

fn finish_boring_ech_retry_result<T>(
    result: Result<T, ResidentEchHandshakeError>,
    label: &str,
) -> Result<T, String> {
    match result {
        Ok(client) => Ok(client),
        Err(ResidentEchHandshakeError::Rejected(_)) => Err(format!(
            "{label} BoringSSL ECH rejected after one authenticated retry"
        )),
        Err(ResidentEchHandshakeError::Failed(error)) => Err(error),
    }
}

async fn open_async_boring_ech_xhttp_attempt(
    endpoint: &ResidentXhttpEndpointPlan,
    tcp: TokioTcpStream,
    ech_config_list: &[u8],
) -> Result<AsyncResidentTlsClient, ResidentEchHandshakeError> {
    let connector =
        boring_xhttp_endpoint_connector(endpoint).map_err(ResidentEchHandshakeError::Failed)?;
    let mut config = connector.configure().map_err(|err| {
        ResidentEchHandshakeError::Failed(format!("configure xHTTP ECH BoringSSL client: {err}"))
    })?;
    configure_utls_template_boring_ssl_for_xhttp_endpoint(&mut config, endpoint)
        .map_err(ResidentEchHandshakeError::Failed)?;
    config.set_ech_config_list(ech_config_list).map_err(|err| {
        ResidentEchHandshakeError::Failed(format!("set xHTTP BoringSSL ECHConfigList: {err}"))
    })?;
    let tcp = AsyncResidentTcpStream::new_boring(tcp, endpoint.tls_fragment.clone());
    let session_key =
        ResidentBoringTlsSessionKey::with_ech_config_list(&endpoint.server_name, ech_config_list);
    let result = time::timeout(
        RESIDENT_CONNECT_TIMEOUT,
        connector.connect(config, session_key, &endpoint.server_name, tcp),
    )
    .await
    .map_err(|_| {
        ResidentEchHandshakeError::Failed("xHTTP BoringSSL ECH handshake timeout".to_owned())
    })?;
    match result {
        Ok(tls) if tls.ssl().ech_accepted() => Ok(AsyncVlessTlsClient {
            engine: AsyncVlessTlsEngine::Boring { tls },
        }),
        Ok(_) => Err(ResidentEchHandshakeError::Failed(
            "xHTTP BoringSSL handshake completed without accepting required ECH".to_owned(),
        )),
        Err(error) => Err(classify_boring_ech_handshake_error(
            error,
            endpoint.allow_insecure,
            "xHTTP",
        )),
    }
}

fn classify_boring_ech_handshake_error(
    error: ResidentBoringTlsConnectError<AsyncResidentTcpStream>,
    allow_insecure: bool,
    label: &str,
) -> ResidentEchHandshakeError {
    let retry = error
        .handshake_error()
        .and_then(tokio_boring::HandshakeError::ssl)
        .and_then(SslRef::get_ech_retry_configs)
        .map(ToOwned::to_owned);
    if let Some(retry) = retry {
        if allow_insecure {
            return ResidentEchHandshakeError::Failed(format!(
                "{label} BoringSSL ECH rejection supplied unauthenticated retry configs while allowInsecure is enabled"
            ));
        }
        return ResidentEchHandshakeError::Rejected(retry);
    }
    ResidentEchHandshakeError::Failed(format!("connect {label} BoringSSL ECH client: {error}"))
}

fn validated_ech_retry_config(bytes: Vec<u8>) -> Result<EchConfigList, String> {
    EchConfigList::from_bytes(bytes)
        .map_err(|err| format!("server returned invalid ECH retry config list: {err}"))
}

#[cfg(test)]
#[path = "open_client/ech_tests.rs"]
mod ech_tests;
