use super::*;
pub(super) fn append_tcp_execution_fields(event: &mut Value, execution: &str) {
    append_runtime_execution_descriptor(event, tcp_execution_descriptor(execution));
}

pub(super) fn append_proxy_tcp_execution_fields(
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

pub(super) fn proxy_tcp_finished_event(
    peer: SocketAddr,
    original_dst: SocketAddr,
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

pub(super) fn proxy_tcp_failed_event(
    peer: SocketAddr,
    original_dst: SocketAddr,
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

pub(super) fn generic_proxy_tcp_finished_event(
    peer: SocketAddr,
    original_dst: SocketAddr,
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

pub(super) fn generic_proxy_tcp_failed_event(
    peer: SocketAddr,
    original_dst: SocketAddr,
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

pub(super) fn proxy_tcp_base_event(
    event_name: &str,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: &TcpProxySelection,
    sniff: &TcpSniffReport,
) -> Value {
    let mut map = serde_json::Map::with_capacity(18);
    map.insert("event".to_owned(), Value::String(event_name.to_owned()));
    map.insert(
        "outbound_kind".to_owned(),
        Value::String("proxy".to_owned()),
    );
    map.insert(
        "peer".to_owned(),
        Value::String(resident_socket_addr_display(peer)),
    );
    map.insert(
        "original_dst".to_owned(),
        Value::String(resident_socket_addr_display(original_dst)),
    );
    map.insert(
        "dial_target".to_owned(),
        Value::String(selection.route.dial_target.clone()),
    );
    map.insert("dial_ip".to_owned(), Value::Bool(selection.route.dial_ip));
    map.insert(
        "initial_outbound".to_owned(),
        Value::from(selection.route.initial_outbound),
    );
    map.insert(
        "final_outbound".to_owned(),
        Value::from(selection.route.final_outbound),
    );
    map.insert(
        "final_mark".to_owned(),
        Value::from(selection.route.final_mark),
    );
    map.insert(
        "userspace_route_executed".to_owned(),
        Value::Bool(selection.route.userspace_route_executed),
    );
    map.insert(
        "userspace_route_must".to_owned(),
        Value::Bool(selection.route.userspace_route_must),
    );
    map.insert(
        "sniffed_domain".to_owned(),
        Value::String(sniff.domain.clone()),
    );
    map.insert(
        "sniff_error".to_owned(),
        sniff
            .error
            .as_ref()
            .map_or(Value::Null, |err| Value::String(err.clone())),
    );
    map.insert(
        "proxy_group".to_owned(),
        Value::String(selection.proxy.group_name.clone()),
    );
    map.insert(
        "group_policy".to_owned(),
        Value::String(selection.proxy.group_policy.clone()),
    );
    map.insert(
        "node_tag".to_owned(),
        Value::String(selection.proxy.node_tag.clone()),
    );
    map.insert(
        "graphId".to_owned(),
        Value::String(selection.proxy.graph_id.clone()),
    );
    let mut event = Value::Object(map);
    append_tcp_route_log_fields(
        &mut event,
        &selection.route,
        &selection.proxy.group_name,
        &selection.proxy.group_policy,
        &selection.proxy.node_tag,
    );
    event
}

pub(super) fn tcp_route_chosen_event(
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: &TcpSelection,
    sniff: &TcpSniffReport,
    dial_mode: &str,
) -> Value {
    let (route, outbound_kind, outbound, policy, dialer, mptcp) = match selection {
        TcpSelection::Direct(selection) => (
            &selection.route,
            "direct",
            "direct",
            "fixed",
            "direct",
            selection.mptcp,
        ),
        TcpSelection::Block(selection) => {
            (&selection.route, "block", "block", "fixed", "block", false)
        }
        TcpSelection::Proxy(selection) => (
            &selection.route,
            "proxy",
            selection.proxy.group_name.as_str(),
            selection.proxy.group_policy.as_str(),
            selection.proxy.node_tag.as_str(),
            selection.mptcp,
        ),
    };
    let mut event = json!({
        "event": "tcp_route_chosen",
        "outbound_kind": outbound_kind,
        "peer": resident_socket_addr_display(peer),
        "original_dst": resident_socket_addr_display(original_dst),
        "dial_target": &route.dial_target,
        "dial_ip": route.dial_ip,
        "dial_mode": dial_mode,
        "initial_outbound": route.initial_outbound,
        "final_outbound": route.final_outbound,
        "final_mark": route.final_mark,
        "userspace_route_executed": route.userspace_route_executed,
        "userspace_route_must": route.userspace_route_must,
        "sniffed_domain": &sniff.domain,
        "sniff_error": &sniff.error,
        "mptcp": mptcp,
    });
    append_tcp_route_log_fields(&mut event, route, outbound, policy, dialer);
    event
}

pub(super) fn append_proxy_relay_stats(event: &mut Value, stats: &RelayStats) {
    if let Some(map) = event.as_object_mut() {
        map.insert(
            "bytes_client_to_proxy".to_owned(),
            Value::from(stats.client_to_proxy),
        );
        map.insert(
            "bytes_proxy_to_client".to_owned(),
            Value::from(stats.proxy_to_client),
        );
        map.insert(
            "response_header_stripped".to_owned(),
            Value::Bool(stats.response_header_stripped),
        );
        map.insert(
            "vision_unpadding_blocks".to_owned(),
            Value::from(stats.vision_unpadding_blocks),
        );
        map.insert(
            "vision_direct_command_seen".to_owned(),
            Value::Bool(stats.vision_direct_command_seen),
        );
        map.insert(
            "vision_raw_direct_recovered".to_owned(),
            Value::Bool(stats.vision_raw_direct_recovered),
        );
        map.insert(
            "vision_downlink_direct_active".to_owned(),
            Value::Bool(stats.vision_downlink_direct_active),
        );
    }
}

pub(super) fn append_generic_proxy_relay_stats(event: &mut Value, stats: &DirectTcpRelayStats) {
    if let Some(map) = event.as_object_mut() {
        map.insert(
            "bytes_client_to_proxy".to_owned(),
            Value::from(stats.client_to_direct),
        );
        map.insert(
            "bytes_proxy_to_client".to_owned(),
            Value::from(stats.direct_to_client),
        );
        map.insert("response_header_stripped".to_owned(), Value::Bool(false));
        map.insert("vision_unpadding_blocks".to_owned(), Value::from(0));
        map.insert("vision_direct_command_seen".to_owned(), Value::Bool(false));
        map.insert("vision_raw_direct_recovered".to_owned(), Value::Bool(false));
        map.insert(
            "vision_downlink_direct_active".to_owned(),
            Value::Bool(false),
        );
    }
}
