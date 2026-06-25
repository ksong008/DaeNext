use std::net::{IpAddr, SocketAddr};

use super::*;
pub(crate) fn append_resident_event_product_log(
    config_dir: &Path,
    state: &Path,
    event: &Value,
) -> io::Result<()> {
    let Some(event_name) = event.get("event").and_then(Value::as_str) else {
        return Ok(());
    };
    if resident_event_hidden_from_product_log(event_name) {
        return Ok(());
    }
    let level = resident_event_product_log_level(event_name, event);
    let fields = resident_event_product_log_fields(event_name, event);
    append_log_fields_for_config(
        config_dir,
        state,
        level,
        &resident_event_product_log_message(event_name, event),
        fields,
    )
}

pub(crate) fn resident_event_hidden_from_product_log(event_name: &str) -> bool {
    matches!(
        event_name,
        "tcp_worker_started"
            | "tcp_worker_stopped"
            | "udp_session_manager_started"
            | "udp_session_manager_stopped"
            | "resident_health_checker_started"
    )
}

pub(crate) fn resident_event_product_log_level(event_name: &str, event: &Value) -> &'static str {
    if event_name.contains("panic") {
        return "panic";
    }
    if event_name.contains("fatal") {
        return "fatal";
    }
    match event_name {
        "tcp_listener_nonblocking_failed"
        | "tcp_async_runtime_build_failed"
        | "tcp_async_listener_adopt_failed"
        | "udp_socket_nonblocking_failed"
        | "udp_session_manager_start_failed"
        | "udp_session_manager_async_fd_failed" => return "error",
        "tcp_accept_failed"
        | "tcp_connection_failed"
        | "udp_receive_failed"
        | "udp_packet_skipped"
        | "udp_packet_dropped"
        | "udp_reply_failed"
        | "udp_exchange_failed"
        | "dns_bind_listener_start_failed"
        | "dns_bind_receive_failed"
        | "dns_bind_response_send_failed"
        | "dns_bind_query_failed"
        | "dns_bind_accept_failed"
        | "resident_health_checker_runtime_failed" => return "warn",
        "dns_bind_listener_started" | "dns_bind_listener_stopped" => return "info",
        "tcp_connection_finished" | "tcp_connection_blocked"
            if resident_event_has_route_log_context(event) =>
        {
            return "info";
        }
        "tcp_connection_finished"
        | "tcp_connection_blocked"
        | "udp_packet_finished"
        | "udp_dns_packet_finished"
        | "dns_bind_query_finished"
        | "udp_session_started"
        | "udp_session_stopped" => return "debug",
        _ => {}
    }
    if event_name.contains("failed") || event_name.contains("error") {
        return "warn";
    }
    "debug"
}

pub(crate) fn resident_event_has_route_log_context(event: &Value) -> bool {
    [
        "network",
        "outbound",
        "proxy_group",
        "outbound_kind",
        "original_dst",
    ]
    .iter()
    .any(|key| event.get(key).is_some_and(|value| !value.is_null()))
}

pub(crate) fn resident_event_is_flow_diagnostic(event_name: &str) -> bool {
    matches!(
        event_name,
        "tcp_connection_finished"
            | "tcp_connection_failed"
            | "tcp_connection_blocked"
            | "udp_packet_finished"
            | "udp_dns_packet_finished"
            | "udp_packet_skipped"
            | "udp_reply_failed"
            | "udp_exchange_failed"
    )
}

pub(crate) fn resident_event_product_log_message(event_name: &str, event: &Value) -> String {
    if resident_event_is_flow_diagnostic(event_name)
        && let Some(message) = resident_flow_event_product_log_message(event_name, event)
    {
        return message;
    }
    format!("resident dataplane {}", event_name.replace('_', " "))
}

pub(crate) fn resident_event_product_log_fields(
    event_name: &str,
    event: &Value,
) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    if resident_event_is_flow_diagnostic(event_name) {
        append_resident_flow_event_product_log_fields(&mut fields, event);
        return fields;
    }
    fields.insert("event".to_owned(), event_name.to_owned());
    if let Some(object) = event.as_object() {
        for (key, value) in object {
            if key == "event" || resident_product_log_field_hidden(key) {
                continue;
            }
            fields.insert(key.to_owned(), product_log_field_value(value));
        }
    }
    fields
}

pub(crate) fn resident_flow_event_product_log_message(
    event_name: &str,
    event: &Value,
) -> Option<String> {
    let peer = resident_event_socket_field_value(event, "peer")
        .unwrap_or_else(|| "unknown-peer".to_owned());
    let target = resident_event_first_socket_field_value(
        event,
        &[
            "dial_target",
            "direct_target",
            "original_dst",
            "direct_peer_addr",
        ],
    )
    .unwrap_or_else(|| "unknown-target".to_owned());
    let suffix = if event_name.contains("failed")
        || event_name.contains("error")
        || event_name.ends_with("_skipped")
    {
        " failed"
    } else {
        ""
    };
    Some(format!("{peer} <-> {target}{suffix}"))
}

pub(crate) fn append_resident_flow_event_product_log_fields(
    fields: &mut BTreeMap<String, String>,
    event: &Value,
) {
    append_resident_flow_network_field(fields, event);
    append_resident_event_first_field_if_present(
        fields,
        event,
        "outbound",
        &["outbound", "proxy_group", "outbound_kind"],
    );
    append_resident_event_first_field_if_present(
        fields,
        event,
        "policy",
        &["policy", "group_policy"],
    );
    append_resident_event_first_field_if_present(
        fields,
        event,
        "dialer",
        &["dialer", "node_tag", "outbound_kind"],
    );
    append_resident_event_first_field_if_present(
        fields,
        event,
        "sniffed",
        &["sniffed", "sniffed_domain"],
    );
    append_resident_event_first_socket_field_if_present(
        fields,
        event,
        "ip",
        &["ip", "original_dst", "direct_target"],
    );
    for key in ["pid", "dscp", "pname", "mac", "error", "reason"] {
        append_resident_event_field_if_present(fields, event, key);
    }
    append_resident_execution_descriptor_fields(fields, event);
}

pub(crate) fn append_resident_execution_descriptor_fields(
    fields: &mut BTreeMap<String, String>,
    event: &Value,
) {
    let Some(descriptor) = event.get("executionDescriptor").and_then(Value::as_object) else {
        return;
    };
    for key in [
        "executor",
        "capability",
        "packetSemantics",
        "securityUnderlay",
        "streamWrapper",
        "protocolFraming",
        "transportUnderlay",
    ] {
        let Some(value) = descriptor.get(key) else {
            continue;
        };
        let value = product_log_field_value(value);
        if !value.is_empty() {
            fields.insert(key.to_owned(), value);
        }
    }
}

pub(crate) fn append_resident_flow_network_field(
    fields: &mut BTreeMap<String, String>,
    event: &Value,
) {
    let event_transport = resident_event_field_str(event, "event").and_then(|event_name| {
        if event_name.starts_with("tcp_") {
            Some("tcp")
        } else if event_name.starts_with("udp_") {
            Some("udp")
        } else {
            None
        }
    });
    if let Some(network) = event_transport.and_then(|transport| {
        resident_event_first_socket_addr(
            event,
            &["ip", "original_dst", "direct_target", "direct_peer_addr"],
        )
        .map(|addr| resident_socket_network_name(transport, addr))
    }) {
        fields.insert("network".to_owned(), network);
        return;
    }
    if let Some(network) = resident_event_field_value(event, "network") {
        fields.insert("network".to_owned(), network);
        return;
    }
    let Some(event_name) = resident_event_field_str(event, "event") else {
        return;
    };
    if event_name.starts_with("tcp_") {
        fields.insert("network".to_owned(), "tcp4".to_owned());
    } else if event_name.starts_with("udp_") {
        fields.insert("network".to_owned(), "udp4".to_owned());
    }
}

pub(crate) fn append_resident_event_first_field_if_present(
    fields: &mut BTreeMap<String, String>,
    event: &Value,
    output_key: &str,
    input_keys: &[&str],
) {
    let Some(value) = input_keys
        .iter()
        .find_map(|key| resident_event_field_value(event, key))
    else {
        return;
    };
    fields.insert(output_key.to_owned(), value);
}

pub(crate) fn append_resident_event_first_socket_field_if_present(
    fields: &mut BTreeMap<String, String>,
    event: &Value,
    output_key: &str,
    input_keys: &[&str],
) {
    let Some(value) = resident_event_first_socket_field_value(event, input_keys) else {
        return;
    };
    fields.insert(output_key.to_owned(), value);
}

pub(crate) fn append_resident_event_field_if_present(
    fields: &mut BTreeMap<String, String>,
    event: &Value,
    key: &str,
) {
    let Some(value) = event.get(key) else {
        return;
    };
    if value.is_null() {
        return;
    }
    let value = product_log_field_value(value);
    if !value.is_empty() {
        fields.insert(key.to_owned(), value);
    }
}

pub(crate) fn resident_event_field_value(event: &Value, key: &str) -> Option<String> {
    let value = event.get(key)?;
    (!value.is_null()).then(|| product_log_field_value(value))
}

pub(crate) fn resident_event_first_socket_field_value(
    event: &Value,
    keys: &[&str],
) -> Option<String> {
    keys.iter()
        .find_map(|key| resident_event_socket_field_value(event, key))
}

pub(crate) fn resident_event_socket_field_value(event: &Value, key: &str) -> Option<String> {
    resident_event_field_value(event, key).map(|value| resident_socket_field_display(&value))
}

pub(crate) fn resident_event_first_socket_addr(event: &Value, keys: &[&str]) -> Option<SocketAddr> {
    keys.iter().find_map(|key| {
        resident_event_field_str(event, key).and_then(|value| value.parse::<SocketAddr>().ok())
    })
}

pub(crate) fn resident_socket_field_display(value: &str) -> String {
    value
        .parse::<SocketAddr>()
        .map(resident_socket_addr_display)
        .unwrap_or_else(|_| value.to_owned())
}

pub(crate) fn resident_socket_addr_display(addr: SocketAddr) -> String {
    match addr {
        SocketAddr::V6(addr) => addr
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), addr.port()))
            .unwrap_or(SocketAddr::V6(addr))
            .to_string(),
        SocketAddr::V4(_) => addr.to_string(),
    }
}

pub(crate) fn resident_socket_network_name(transport: &str, addr: SocketAddr) -> String {
    let suffix = if resident_socket_addr_display(addr).starts_with('[') {
        "6"
    } else {
        "4"
    };
    format!("{transport}{suffix}")
}

pub(crate) fn resident_event_field_str<'a>(event: &'a Value, key: &str) -> Option<&'a str> {
    event
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(crate) fn product_log_field_value(value: &Value) -> String {
    match value {
        Value::String(value) => resident_socket_field_display(value),
        Value::Number(_) | Value::Bool(_) | Value::Null => value.to_string(),
        Value::Array(_) | Value::Object(_) => {
            sanitize_resident_product_log_value(value).to_string()
        }
    }
}

pub(crate) fn sanitize_resident_product_log_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(sanitize_resident_product_log_value)
                .collect(),
        ),
        Value::Object(object) => Value::Object(
            object
                .iter()
                .filter(|(key, _)| !resident_product_log_field_hidden(key))
                .map(|(key, value)| (key.clone(), sanitize_resident_product_log_value(value)))
                .collect(),
        ),
        Value::String(value) => Value::String(resident_socket_field_display(value)),
        _ => value.clone(),
    }
}

pub(crate) fn resident_product_log_field_hidden(key: &str) -> bool {
    matches!(key, "graphId" | "graphIdentityHash" | "graphLinkHash")
}
