// Trojan proxy handlers keep protocol credentials, stream state, and event context explicit.
#![allow(clippy::too_many_arguments)]

use super::*;
pub async fn handle_trojan_websocket_tls_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    password: &str,
) -> Result<Value, String> {
    let mut client =
        open_async_resident_tls_client_with_binding(&selection.proxy, selection.mptcp).await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    let ws_leftover = websocket_handshake_over_resident_tls_async(&mut client, &options).await?;
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    let request = trojan_packet::tcp_request_header(
        password,
        "tcp",
        &selection.route.dial_target,
        &initial_payload,
    )
    .map_err(|err| format!("build Trojan WebSocket TCP request: {err}"))?;
    write_websocket_binary_frame_over_resident_tls_async(
        &mut client,
        &request,
        "write Trojan websocket request",
    )
    .await?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if initial_payload_len != 0 {
        initial_stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
    }
    drop((request, initial_payload));

    match relay_tcp_over_trojan_websocket_tls_async(
        inbound,
        &mut client,
        stop,
        metrics,
        ws_leftover,
    )
    .await
    {
        Ok(mut stats) => {
            stats.client_to_direct += initial_stats.client_to_direct;
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "trojan",
                &stats,
                "async-proxy-websocket-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("websocket");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-websocket-tls",
                "trojan",
                Some(tls_underlay),
                None,
            );
            Ok(event)
        }
        Err(err) => {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "trojan",
                &err,
                "async-proxy-websocket-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("websocket");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-websocket-tls",
                "trojan",
                Some(tls_underlay),
                None,
            );
            Ok(event)
        }
    }
}
pub async fn handle_trojan_websocket_inner_shadowsocks_tls_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    password: &str,
    inner_cipher: &str,
    inner_password: &str,
) -> Result<Value, String> {
    let mut client =
        open_async_resident_tls_client_with_binding(&selection.proxy, selection.mptcp).await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    let ws_leftover = websocket_handshake_over_resident_tls_async(&mut client, &options).await?;
    let initial_payload = sniff.take_payload();
    let stats = relay_tcp_over_trojan_websocket_inner_shadowsocks_tls(
        inbound,
        &mut client,
        stop,
        &selection.route.dial_target,
        password,
        inner_cipher,
        inner_password,
        initial_payload,
        metrics,
        ws_leftover,
    )
    .await;
    stats
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "trojan",
                &stats,
                "inner-encryption-websocket-aead",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("websocket");
            event["inner_encryption"] = json!("shadowsocks");
            append_proxy_tcp_execution_fields(
                &mut event,
                "inner-encryption-websocket-aead",
                "trojan",
                Some(tls_underlay),
                None,
            );
            event
        })
        .or_else(|err| {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "trojan",
                &err,
                "inner-encryption-websocket-aead",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("websocket");
            event["inner_encryption"] = json!("shadowsocks");
            append_proxy_tcp_execution_fields(
                &mut event,
                "inner-encryption-websocket-aead",
                "trojan",
                Some(tls_underlay),
                None,
            );
            Ok::<Value, String>(event)
        })
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_trojan_httpupgrade_tls_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    password: &str,
) -> Result<Value, String> {
    let mut client =
        open_async_resident_tls_client_with_binding(&selection.proxy, selection.mptcp).await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    let httpupgrade_leftover =
        httpupgrade_handshake_over_resident_tls_async(&mut client, &options).await?;
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    let request = trojan_packet::tcp_request_header(
        password,
        "tcp",
        &selection.route.dial_target,
        &initial_payload,
    )
    .map_err(|err| format!("build Trojan HTTP Upgrade TCP request: {err}"))?;
    client
        .write_plain_all(&request, "write Trojan HTTP Upgrade TCP request")
        .await?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if initial_payload_len != 0 {
        initial_stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
    }
    drop((request, initial_payload));

    match relay_tcp_over_resident_tls_plain_async(
        inbound,
        &mut client,
        stop,
        metrics,
        httpupgrade_leftover,
    )
    .await
    {
        Ok(mut stats) => {
            stats.client_to_direct += initial_stats.client_to_direct;
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "trojan",
                &stats,
                "async-proxy-httpupgrade-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("httpupgrade");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-httpupgrade-tls",
                "trojan",
                Some(tls_underlay),
                None,
            );
            Ok(event)
        }
        Err(err) => {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "trojan",
                &err,
                "async-proxy-httpupgrade-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("httpupgrade");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-httpupgrade-tls",
                "trojan",
                Some(tls_underlay),
                None,
            );
            Ok(event)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_trojan_grpc_tls_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    password: &str,
) -> Result<Value, String> {
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    let request = trojan_packet::tcp_request_header(
        password,
        "tcp",
        &selection.route.dial_target,
        &initial_payload,
    )
    .map_err(|err| format!("build Trojan gRPC TCP request: {err}"))?;
    let (mut h2_send, mut h2_recv, carrier_lease) =
        open_grpc_h2_stream(&selection.proxy, &request).await?;
    drop((request, initial_payload));
    let tls_underlay = carrier_lease.tls_underlay();
    let mut initial_stats = DirectTcpRelayStats::default();
    if initial_payload_len != 0 {
        initial_stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
    }

    let result = relay_tcp_over_grpc_h2(
        inbound,
        &mut h2_send,
        &mut h2_recv,
        stop,
        initial_stats,
        metrics,
        false,
    )
    .await;
    match result {
        Ok(stats) => {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "trojan",
                &stats,
                "async-proxy-grpc-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("grpc");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-grpc-tls",
                "trojan",
                Some(tls_underlay),
                None,
            );
            Ok(event)
        }
        Err(err) => {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "trojan",
                &err,
                "async-proxy-grpc-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("grpc");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-grpc-tls",
                "trojan",
                Some(tls_underlay),
                None,
            );
            Ok(event)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_trojan_tls_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    password: &str,
) -> Result<Value, String> {
    let mut client =
        open_async_resident_tls_client_with_binding(&selection.proxy, selection.mptcp).await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    let request = trojan_packet::tcp_request_header(
        password,
        "tcp",
        &selection.route.dial_target,
        &initial_payload,
    )
    .map_err(|err| format!("build Trojan TCP request: {err}"))?;
    client
        .write_plain_all(&request, "write Trojan TCP request")
        .await?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if initial_payload_len != 0 {
        initial_stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
    }
    drop((request, initial_payload));
    match relay_tcp_over_resident_tls_plain_async(inbound, &mut client, stop, metrics, Vec::new())
        .await
    {
        Ok(mut stats) => {
            stats.client_to_direct += initial_stats.client_to_direct;
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "trojan",
                &stats,
                "async-proxy-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-tls",
                "trojan",
                Some(tls_underlay),
                None,
            );
            Ok(event)
        }
        Err(err) => {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "trojan",
                &err,
                "async-proxy-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-tls",
                "trojan",
                Some(tls_underlay),
                None,
            );
            Ok(event)
        }
    }
}
