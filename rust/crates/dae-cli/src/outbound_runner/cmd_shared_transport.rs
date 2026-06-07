use super::*;

pub(super) fn run_transport(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("contract") => run_transport_contract(),
        Some("xhttp-mode") => run_transport_xhttp_mode(&args[1..]),
        Some("xhttp-alpn") => run_transport_xhttp_alpn(&args[1..]),
        Some("xhttp-path") => run_transport_xhttp_path(&args[1..]),
        Some("xhttp-extra") => run_transport_xhttp_extra(&args[1..]),
        Some("grpc-cache-key") => run_transport_grpc_cache_key(&args[1..]),
        Some("reality") => run_transport_reality(&args[1..]),
        Some("smoke") => run_transport_smoke(),
        Some(subcommand) => RunnerOutput::usage(format!(
            "unsupported outbound transport subcommand: {subcommand}"
        )),
        None => RunnerOutput::usage("missing outbound transport subcommand"),
    }
}

pub(super) fn run_transport_contract() -> RunnerOutput {
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "shared-transport-native-optin",
            "default_go_path": shared_transport::contract::DEFAULT_GO_PATH,
            "rust_adapter_mode": shared_transport::contract::ADAPTER_MODE,
            "protocol_scope": shared_transport::contract::PROTOCOL_SCOPE,
            "transport_scope": shared_transport::contract::TRANSPORT_SCOPE,
            "tls_transport": {
                "schemes": shared_transport::contract::TLS_SCHEMES,
                "allow_insecure_aliases": shared_transport::contract::ALLOW_INSECURE_ALIASES,
                "utls_imitate_query": shared_transport::contract::UTLS_IMITATE_QUERY,
                "global_tls_fragment": shared_transport::contract::GLOBAL_TLS_FRAGMENT,
                "udp_passthrough_key": shared_transport::contract::UDP_PASSTHROUGH_KEY,
                "udp_without_passthrough": shared_transport::contract::UDP_WITHOUT_PASSTHROUGH,
            },
            "reality_transport": {
                "spx_default": shared_transport::contract::REALITY_SPX_DEFAULT,
                "requires_utls_handshake_state": shared_transport::contract::REALITY_REQUIRES_UTLS_HANDSHAKE_STATE,
                "verify_peer_certificate": shared_transport::contract::REALITY_VERIFY_PEER_CERTIFICATE,
                "data_plane_deferred": shared_transport::contract::REALITY_DATA_PLANE_DEFERRED,
            },
            "ws_transport": {
                "schemes": shared_transport::contract::WS_SCHEMES,
                "allow_insecure_aliases": shared_transport::contract::ALLOW_INSECURE_ALIASES,
                "udp_without_passthrough": shared_transport::contract::UDP_WITHOUT_PASSTHROUGH,
            },
            "grpc_transport": {
                "clean_cache_hook": shared_transport::contract::GRPC_CLEAN_CACHE_HOOK,
                "cache_key_fields": shared_transport::contract::GRPC_CACHE_KEY_FIELDS,
                "sample_cache_key_a": shared_transport::ir::grpc_cache_key("addr:443", "sni.example", "dialer-1", true, 1234, true),
                "sample_cache_key_b": shared_transport::ir::grpc_cache_key("addr:443", "sni.example", "dialer-1", true, 1234, false),
                "backoff_base_ms": shared_transport::contract::GRPC_BACKOFF_BASE_MS,
                "backoff_multiplier": shared_transport::contract::GRPC_BACKOFF_MULTIPLIER,
                "backoff_jitter": shared_transport::contract::GRPC_BACKOFF_JITTER,
                "backoff_max_seconds": shared_transport::contract::GRPC_BACKOFF_MAX_SECONDS,
                "keepalive_seconds": shared_transport::contract::GRPC_KEEPALIVE_SECONDS,
                "keepalive_timeout_seconds": shared_transport::contract::GRPC_KEEPALIVE_TIMEOUT_SECONDS,
                "min_connect_timeout_seconds": shared_transport::contract::GRPC_MIN_CONNECT_TIMEOUT_SECONDS,
            },
            "httpupgrade_transport": {
                "https_alpn": shared_transport::contract::HTTPUPGRADE_HTTPS_ALPN,
                "request_method": shared_transport::contract::HTTPUPGRADE_REQUEST_METHOD,
                "connection_header": shared_transport::contract::HTTPUPGRADE_CONNECTION_HEADER,
                "upgrade_header": shared_transport::contract::HTTPUPGRADE_UPGRADE_HEADER,
                "success_status": shared_transport::contract::HTTPUPGRADE_SUCCESS_STATUS,
                "udp": shared_transport::contract::HTTPUPGRADE_UDP,
            },
            "meek_transport": {
                "url_scheme_required": shared_transport::contract::MEEK_URL_SCHEME_REQUIRED,
                "default_alpn": shared_transport::contract::MEEK_DEFAULT_ALPN,
                "max_write": shared_transport::contract::MEEK_MAX_WRITE,
                "initial_polling_ms": shared_transport::contract::MEEK_INITIAL_POLLING_MS,
                "max_polling_ms": shared_transport::contract::MEEK_MAX_POLLING_MS,
                "min_polling_ms": shared_transport::contract::MEEK_MIN_POLLING_MS,
                "backoff": shared_transport::contract::MEEK_BACKOFF,
                "clean_cache_hook": shared_transport::contract::MEEK_CLEAN_CACHE_HOOK,
            },
            "simpleobfs_transport": {
                "supported": shared_transport::contract::SIMPLEOBFS_SUPPORTED,
                "type_keys": shared_transport::contract::SIMPLEOBFS_TYPE_KEYS,
                "host_key": shared_transport::contract::SIMPLEOBFS_HOST_KEY,
                "path_keys": shared_transport::contract::SIMPLEOBFS_PATH_KEYS,
                "protocol_label": shared_transport::contract::SIMPLEOBFS_PROTOCOL_LABEL,
            },
            "mux_transport": {
                "request_header_hex": shared_transport::contract::MUX_REQUEST_HEADER_HEX,
                "data_plane_deferred": shared_transport::contract::MUX_DATA_PLANE_DEFERRED,
            },
            "xhttp_transport": {
                "packet_max_bytes_default": shared_transport::contract::XHTTP_PACKET_MAX_BYTES_DEFAULT,
                "packet_min_gap_ms_default": shared_transport::contract::XHTTP_PACKET_MIN_GAP_MS_DEFAULT,
                "unsupported_extra_fields": shared_transport::contract::XHTTP_UNSUPPORTED_EXTRA_FIELDS,
                "true_data_plane_deferred": shared_transport::contract::XHTTP_TRUE_DATA_PLANE_DEFERRED,
            },
            "live_smoke_required": shared_transport::contract::LIVE_SMOKE_REQUIRED,
        })
    ))
}

pub(super) fn run_transport_xhttp_mode(args: &[String]) -> RunnerOutput {
    let mode = string_arg(args, "--mode").unwrap_or("auto");
    let scheme = string_arg(args, "--scheme").unwrap_or("https");
    let security = string_arg(args, "--security").unwrap_or("tls");
    let has_download = bool_arg(args, "--download").unwrap_or(false);
    let got = shared_transport::ir::normalize_xhttp_mode(mode, scheme, security, has_download);
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "mode": mode,
            "scheme": scheme,
            "security": security,
            "hasDownload": has_download,
            "normalized": got.normalized,
            "ok": got.ok,
            "error_contains": got.error_contains,
        })
    ))
}

pub(super) fn run_transport_xhttp_alpn(args: &[String]) -> RunnerOutput {
    let security = string_arg(args, "--security").unwrap_or("tls");
    let alpn = string_arg(args, "--alpn").unwrap_or("h2");
    let got = shared_transport::ir::validate_xhttp_alpn(security, alpn);
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "security": security,
            "alpn": alpn,
            "ok": got.ok,
            "use_h3": got.use_h3,
            "error_contains": got.error_contains,
        })
    ))
}

pub(super) fn run_transport_xhttp_path(args: &[String]) -> RunnerOutput {
    let input = string_arg(args, "--input").unwrap_or("xhttp");
    let got = shared_transport::ir::normalize_xhttp_path_and_query(input);
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "input": input,
            "path": got.path,
            "query": got.query,
        })
    ))
}

pub(super) fn run_transport_xhttp_extra(args: &[String]) -> RunnerOutput {
    let Some(raw) = string_arg(args, "--raw") else {
        return RunnerOutput::usage("missing outbound transport xhttp-extra --raw");
    };
    match shared_transport::ir::canonical_json(raw) {
        Ok(canonical) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "raw": raw,
                "canonical": canonical,
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_transport_grpc_cache_key(args: &[String]) -> RunnerOutput {
    let address = string_arg(args, "--address").unwrap_or("addr:443");
    let server_name = string_arg(args, "--server-name").unwrap_or("sni.example");
    let dialer_id = string_arg(args, "--dialer").unwrap_or("dialer-1");
    let allow_insecure = bool_arg(args, "--allow-insecure").unwrap_or(true);
    let mark = match u64_arg(args, "--mark").unwrap_or(Ok(1234)) {
        Ok(value) => value as u32,
        Err(err) => return RunnerOutput::stdout_error(err),
    };
    let mptcp = bool_arg(args, "--mptcp").unwrap_or(true);
    let magic = shared_transport::ir::magic_network_encode("tcp", mark, mptcp);
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "address": address,
            "serverName": server_name,
            "dialer_identity": dialer_id,
            "allowInsecure": allow_insecure,
            "somark": mark,
            "mptcp": mptcp,
            "magic_network_hex": hex_encode(&magic),
            "cache_key": shared_transport::ir::grpc_cache_key(address, server_name, dialer_id, allow_insecure, mark, mptcp),
        })
    ))
}

pub(super) fn run_transport_reality(args: &[String]) -> RunnerOutput {
    let sid = string_arg(args, "--sid").unwrap_or("0123456789abcdef");
    let pbk = string_arg(args, "--pbk").unwrap_or("-__--u_uq80BI0VniavN7_v__vrv7qvNASNFZ4mrze8");
    let spx = string_arg(args, "--spx").unwrap_or("/?p=10-20&c=30&t=40&i=50&r=60-70");
    let sid_decoded = match shared_transport::ir::reality_sid_decode(sid) {
        Ok(decoded) => decoded,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let pbk_decoded = match shared_transport::ir::reality_pbk_decode(pbk) {
        Ok(decoded) => decoded,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "sid_input": sid,
            "sid_decoded_hex": hex_encode(&sid_decoded),
            "pbk_input": pbk,
            "pbk_decoded_hex": hex_encode(&pbk_decoded),
            "spx_input": spx,
            "spider_y": shared_transport::ir::reality_spider_y(spx),
            "requires_utls_handshake_state": shared_transport::contract::REALITY_REQUIRES_UTLS_HANDSHAKE_STATE,
            "verify_peer_certificate": shared_transport::contract::REALITY_VERIFY_PEER_CERTIFICATE,
            "data_plane_deferred": shared_transport::contract::REALITY_DATA_PLANE_DEFERRED,
        })
    ))
}

pub(super) fn run_transport_smoke() -> RunnerOutput {
    let extra = r#"{"downloadSettings":{"address":"download.example","port":443,"network":"xhttp","security":"reality","xhttpSettings":{"host":"download.example","path":"/download","extra":"{\"xmux\":{\"maxConnections\":\"3\",\"cMaxReuseTimes\":\"9\"}}"}},"xmux":{"maxConnections":"1"},"xPaddingBytes":"100-200"}"#;
    let mode = shared_transport::ir::normalize_xhttp_mode("auto", "https", "reality", true);
    let alpn = shared_transport::ir::validate_xhttp_alpn("tls", "h3");
    let path = shared_transport::ir::normalize_xhttp_path_and_query("xhttp?ed=2048&foo=bar");
    let canonical = match shared_transport::ir::canonical_json(extra) {
        Ok(canonical) => canonical,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "ok": true,
            "protocol": "shared_transport",
            "rust_adapter_mode": shared_transport::contract::ADAPTER_MODE,
            "default_go_path": shared_transport::contract::DEFAULT_GO_PATH,
            "xhttp": {
                "mode": mode.normalized,
                "mode_ok": mode.ok,
                "alpn_ok": alpn.ok,
                "use_h3": alpn.use_h3,
                "path": path.path,
                "query": path.query,
                "extra_canonical": canonical,
            },
            "grpc": {
                "cache_key": shared_transport::ir::grpc_cache_key("addr:443", "sni.example", "dialer-1", true, 1234, true),
                "clean_cache_hook": shared_transport::contract::GRPC_CLEAN_CACHE_HOOK,
            },
            "reality": {
                "spider_y": shared_transport::ir::reality_spider_y("/?p=10-20&c=30&t=40&i=50&r=60-70"),
                "data_plane_deferred": shared_transport::contract::REALITY_DATA_PLANE_DEFERRED,
            },
            "true_transport_data_plane_deferred": true,
        })
    ))
}
