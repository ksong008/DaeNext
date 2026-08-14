use super::*;
pub(super) fn canonical_resident_vless_net(net: &str) -> String {
    match net {
        "" | "tcp" => "tcp".to_owned(),
        "ws" | "websocket" => "websocket".to_owned(),
        "http" | "h2" => "h2".to_owned(),
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

pub(super) fn resident_websocket_tls_server_name(
    sni: &str,
    stream_host: &str,
    server_host: &str,
) -> String {
    if !sni.is_empty() {
        sni.to_owned()
    } else if !stream_host.is_empty() {
        stream_host.to_owned()
    } else {
        server_host.to_owned()
    }
}

pub(super) fn resident_stream_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_owned()
    } else {
        path.to_owned()
    }
}

pub(super) fn resident_xhttp_stream_path(path: &str) -> String {
    let normalized = ir::normalize_xhttp_path_and_query(path);
    if normalized.query.is_empty() {
        normalized.path
    } else {
        format!("{}?{}", normalized.path, normalized.query)
    }
}

pub(super) fn resident_grpc_service_name(service_name: &str) -> String {
    service_name.to_owned()
}
