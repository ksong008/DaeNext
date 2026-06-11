use super::*;
pub(super) fn canonical_resident_vless_net(net: &str) -> String {
    match net {
        "" | "tcp" => "tcp".to_owned(),
        "ws" | "websocket" => "websocket".to_owned(),
        "httpupgrade" => "httpupgrade".to_owned(),
        "grpc" => "grpc".to_owned(),
        "xhttp" => "xhttp".to_owned(),
        other => other.to_owned(),
    }
}

pub(super) fn resident_stream_host(host: &str, server_name: &str) -> String {
    if host.is_empty() {
        server_name.to_owned()
    } else {
        host.to_owned()
    }
}

pub(super) fn resident_stream_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_owned()
    } else {
        path.to_owned()
    }
}

pub(super) fn resident_csv_values(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

pub(super) fn resident_xhttp_stream_path(path: &str) -> String {
    let normalized = ir::normalize_xhttp_path_and_query(path);
    if normalized.query.is_empty() {
        normalized.path
    } else {
        format!("{}?{}", normalized.path, normalized.query)
    }
}

pub(super) fn resident_xhttp_extra_is_empty(extra: &str) -> bool {
    let extra = extra.trim();
    if extra.is_empty() {
        return true;
    }
    serde_json::from_str::<Value>(extra)
        .is_ok_and(|value| value.as_object().is_some_and(|object| object.is_empty()))
}

pub(super) fn resident_grpc_service_name(service_name: &str) -> String {
    if service_name.is_empty() {
        "GunService".to_owned()
    } else {
        service_name.trim_start_matches('/').to_owned()
    }
}
