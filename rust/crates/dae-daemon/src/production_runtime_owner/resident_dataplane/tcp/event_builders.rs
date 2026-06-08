fn append_tcp_execution_fields(event: &mut Value, execution: &str) {
    append_runtime_execution_descriptor(event, tcp_execution_descriptor(execution));
}

fn append_proxy_tcp_execution_fields(
    event: &mut Value,
    execution: &str,
    handler: &str,
    tls_underlay: Option<&str>,
    quic_underlay: Option<&str>,
) {
    let mut descriptor = tcp_execution_descriptor(execution).with_protocol_framing(handler);
    let graph_id = event
        .get("graphId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(graph_id) = graph_id.as_deref() {
        descriptor = descriptor.with_graph_id(graph_id);
    }
    if let Some(tls_underlay) = tls_underlay {
        descriptor = descriptor.with_security_underlay(tls_underlay);
    }
    if let Some(quic_underlay) = quic_underlay {
        descriptor = descriptor.with_transport_underlay(quic_underlay);
    }
    append_runtime_execution_descriptor(event, descriptor);
}

fn proxy_tcp_finished_event(
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    sniff: &TcpSniffReport,
    tls_underlay: &'static str,
    stats: &RelayStats,
    execution: &'static str,
) -> Value {
    let mut event = proxy_tcp_base_event(
        "tcp_connection_finished",
        peer,
        original_dst,
        selection,
        sniff,
    );
    event["tls_underlay"] = json!(tls_underlay);
    event["resident_protocol_handler"] = json!("vless");
    append_proxy_tcp_execution_fields(&mut event, execution, "vless", Some(tls_underlay), None);
    append_proxy_relay_stats(&mut event, stats);
    event
}

fn proxy_tcp_failed_event(
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    sniff: &TcpSniffReport,
    tls_underlay: &'static str,
    err: &RelayError,
    execution: &'static str,
) -> Value {
    let mut event = proxy_tcp_base_event(
        "tcp_connection_failed",
        peer,
        original_dst,
        selection,
        sniff,
    );
    event["error"] = json!(&err.message);
    event["tls_underlay"] = json!(tls_underlay);
    event["resident_protocol_handler"] = json!("vless");
    append_proxy_tcp_execution_fields(&mut event, execution, "vless", Some(tls_underlay), None);
    append_proxy_relay_stats(&mut event, &err.stats);
    event
}

fn generic_proxy_tcp_finished_event(
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    sniff: &TcpSniffReport,
    handler: &'static str,
    stats: &DirectTcpRelayStats,
    execution: &'static str,
) -> Value {
    let mut event = proxy_tcp_base_event(
        "tcp_connection_finished",
        peer,
        original_dst,
        selection,
        sniff,
    );
    event["resident_protocol_handler"] = json!(handler);
    append_proxy_tcp_execution_fields(&mut event, execution, handler, None, None);
    append_generic_proxy_relay_stats(&mut event, stats);
    event
}

fn generic_proxy_tcp_failed_event(
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    sniff: &TcpSniffReport,
    handler: &'static str,
    err: &str,
    execution: &'static str,
) -> Value {
    let mut event = proxy_tcp_base_event(
        "tcp_connection_failed",
        peer,
        original_dst,
        selection,
        sniff,
    );
    event["resident_protocol_handler"] = json!(handler);
    append_proxy_tcp_execution_fields(&mut event, execution, handler, None, None);
    event["error"] = json!(err);
    event
}

fn proxy_tcp_base_event(
    event_name: &str,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    sniff: &TcpSniffReport,
) -> Value {
    let mut event = json!({
        "event": event_name,
        "outbound_kind": "proxy",
        "peer": peer.to_string(),
        "original_dst": original_dst.to_string(),
        "dial_target": &selection.route.dial_target,
        "dial_ip": selection.route.dial_ip,
        "initial_outbound": selection.route.initial_outbound,
        "final_outbound": selection.route.final_outbound,
        "final_mark": selection.route.final_mark,
        "userspace_route_executed": selection.route.userspace_route_executed,
        "userspace_route_must": selection.route.userspace_route_must,
        "sniffed_domain": &sniff.domain,
        "sniff_error": &sniff.error,
        "proxy_group": &selection.proxy.group_name,
        "group_policy": &selection.proxy.group_policy,
        "node_tag": &selection.proxy.node_tag,
        "graphId": &selection.proxy.graph_id,
    });
    append_tcp_route_log_fields(
        &mut event,
        &selection.route,
        &selection.proxy.group_name,
        &selection.proxy.group_policy,
        &selection.proxy.node_tag,
    );
    event
}

fn append_proxy_relay_stats(event: &mut Value, stats: &RelayStats) {
    event["bytes_client_to_proxy"] = json!(stats.client_to_proxy);
    event["bytes_proxy_to_client"] = json!(stats.proxy_to_client);
    event["response_header_stripped"] = json!(stats.response_header_stripped);
    event["vision_unpadding_blocks"] = json!(stats.vision_unpadding_blocks);
    event["vision_direct_command_seen"] = json!(stats.vision_direct_command_seen);
    event["vision_raw_direct_recovered"] = json!(stats.vision_raw_direct_recovered);
    event["vision_downlink_direct_active"] = json!(stats.vision_downlink_direct_active);
}

fn append_generic_proxy_relay_stats(event: &mut Value, stats: &DirectTcpRelayStats) {
    event["bytes_client_to_proxy"] = json!(stats.client_to_direct);
    event["bytes_proxy_to_client"] = json!(stats.direct_to_client);
    event["response_header_stripped"] = json!(false);
    event["vision_unpadding_blocks"] = json!(0);
    event["vision_direct_command_seen"] = json!(false);
    event["vision_raw_direct_recovered"] = json!(false);
    event["vision_downlink_direct_active"] = json!(false);
}
