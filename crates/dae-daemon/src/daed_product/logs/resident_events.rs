use super::*;
pub(crate) fn append_resident_event_product_log(
    config_dir: &Path,
    state: &Path,
    event: &Value,
) -> io::Result<()> {
    let Some(event_name) = event.get("event").and_then(Value::as_str) else {
        return Ok(());
    };
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

pub(crate) fn resident_event_product_log_level(event_name: &str, event: &Value) -> &'static str {
    if event_name.contains("failed") || event_name.contains("error") {
        return "warn";
    }
    if matches!(
        event_name,
        "tcp_connection_finished" | "tcp_connection_blocked"
    ) && resident_event_has_route_log_context(event)
    {
        return "info";
    }
    if event_name.ends_with("_started") || event_name.ends_with("_stopped") {
        return "info";
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
            if key == "event" {
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
    let peer = resident_event_field_str(event, "peer").unwrap_or("unknown-peer");
    let target = resident_event_first_field_str(
        event,
        &[
            "dial_target",
            "direct_target",
            "original_dst",
            "direct_peer_addr",
        ],
    )
    .unwrap_or("unknown-target");
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
    append_resident_event_first_field_if_present(
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
        "graphId",
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

pub(crate) fn resident_event_first_field_str<'a>(
    event: &'a Value,
    keys: &[&str],
) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| resident_event_field_str(event, key))
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
        Value::String(value) => value.to_owned(),
        Value::Number(_) | Value::Bool(_) | Value::Null => value.to_string(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}
