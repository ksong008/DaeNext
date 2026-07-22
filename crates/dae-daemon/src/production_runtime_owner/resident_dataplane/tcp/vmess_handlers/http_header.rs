use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::production_runtime_owner::resident_dataplane::tcp) async fn handle_vmess_http_header_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
    body_security: dae_outbound::vmess::VMessBodySecurity,
) -> Result<Value, String> {
    let proxy = open_plain_proxy_tcp_stream_async(&selection).await?;
    let proxy = open_vmess_http_header_stream(
        proxy,
        &selection.proxy.stream_host,
        &selection.proxy.stream_path,
    )
    .await?;
    relay_vmess_http_header_connection_async(
        inbound,
        peer,
        original_dst,
        selection,
        stop,
        sniff,
        metrics,
        id,
        body_security,
        proxy,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(in crate::production_runtime_owner::resident_dataplane::tcp) async fn handle_vmess_http_header_tls_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
    body_security: dae_outbound::vmess::VMessBodySecurity,
) -> Result<Value, String> {
    let client =
        open_async_resident_tls_client_with_binding(&selection.proxy, selection.mptcp).await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let client = open_vmess_http_header_stream(
        client,
        &selection.proxy.stream_host,
        &selection.proxy.stream_path,
    )
    .await?;
    relay_vmess_http_header_connection_async(
        inbound,
        peer,
        original_dst,
        selection,
        stop,
        sniff,
        metrics,
        id,
        body_security,
        client,
        Some(tls_underlay),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn relay_vmess_http_header_connection_async<S>(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
    body_security: dae_outbound::vmess::VMessBodySecurity,
    mut proxy: VmessHttpHeaderStream<S>,
    tls_underlay: Option<&'static str>,
) -> Result<Value, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut session, initial_payload_len) = take_vmess_tcp_session(
        id,
        body_security,
        &selection.route.dial_target,
        sniff,
        "build VMess TCP HTTP header session",
    )?;
    proxy
        .write_all(&session.first_write)
        .await
        .map_err(|error| format!("write VMess TCP HTTP header initial request: {error}"))?;
    discard_vmess_first_write(&mut session);
    let mut initial_stats = DirectTcpRelayStats::default();
    if initial_payload_len != 0 {
        initial_stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
    }
    let result =
        relay_tcp_over_vmess_aead_async(inbound, &mut proxy, stop, session, initial_stats, metrics)
            .await;
    let event = match result {
        Ok(stats) => generic_proxy_tcp_finished_event(
            peer,
            original_dst,
            &selection,
            sniff,
            "vmess",
            &stats,
            "tcp-http-header-aead",
        ),
        Err(error) => generic_proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            "vmess",
            &error,
            "tcp-http-header-aead",
        ),
    };
    let mut event = event;
    event["stream_wrapper"] = json!("tcp-http-header");
    if let Some(tls_underlay) = tls_underlay {
        event["tls_underlay"] = json!(tls_underlay);
    }
    append_proxy_tcp_execution_fields(
        &mut event,
        "tcp-http-header-aead",
        "vmess",
        tls_underlay,
        None,
    );
    Ok(event)
}
