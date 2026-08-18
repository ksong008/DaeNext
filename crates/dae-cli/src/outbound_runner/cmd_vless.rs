use super::*;

pub(super) fn run_vless(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("contract") => run_vless_contract(),
        Some("link") => run_vless_link(&args[1..]),
        Some("key") => run_vless_key(&args[1..]),
        Some("request-header") => run_vless_request_header(&args[1..]),
        Some("smoke") => run_vless_smoke(&args[1..]),
        Some(subcommand) => RunnerOutput::usage(format!(
            "unsupported outbound vless subcommand: {subcommand}"
        )),
        None => RunnerOutput::usage("missing outbound vless subcommand"),
    }
}

pub(super) fn run_vless_contract() -> RunnerOutput {
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "vless-rust-native",
            "rust_adapter_mode": vless::contract::ADAPTER_MODE,
            "protocol_scope": vless::contract::PROTOCOL_SCOPE,
            "deferred_protocol_scope": vless::contract::DEFERRED_PROTOCOL_SCOPE,
            "live_smoke_required": vless::contract::LIVE_SMOKE_REQUIRED,
            "transport_contract": {
                "vision_flow": vless::contract::XTLS_RPRX_VISION,
                "vision_requires_tls_or_reality_hook": vless::contract::VISION_REQUIRES_TLS_OR_REALITY_HOOK,
                "flow_none_canonical_empty": vless::contract::FLOW_NONE_CANONICAL_EMPTY,
                "reality_allowed_for_vless": vless::contract::REALITY_ALLOWED_FOR_VLESS,
                "grpc_default_service_name": vless::contract::GRPC_DEFAULT_SERVICE_NAME,
                "xhttp_mode_auto_export_omitted": vless::contract::XHTTP_MODE_AUTO_EXPORT_OMITTED,
                "production_data_plane_owner": vless::contract::PRODUCTION_DATA_PLANE_OWNER,
                "standalone_smoke_surface": vless::contract::STANDALONE_SMOKE_SURFACE,
            },
        })
    ))
}

pub(super) fn run_vless_link(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound vless link --link");
    };
    match VLESSLink::parse(link).and_then(|parsed| {
        parsed.validate_flow_client(true)?;
        parsed.validate_transport_contract()?;
        Ok(parsed)
    }) {
        Ok(parsed) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "input": link,
                "ps": parsed.ps,
                "add": parsed.add,
                "port": parsed.port,
                "id": parsed.id,
                "net": parsed.net,
                "type": parsed.r#type,
                "host": parsed.host,
                "sni": parsed.sni,
                "path": parsed.path,
                "mode": parsed.xhttp_mode,
                "extra": parsed.xhttp_extra,
                "tls": parsed.tls,
                "flow": parsed.flow,
                "alpn": parsed.alpn,
                "allowInsecure": parsed.allow_insecure,
                "fp": parsed.fingerprint,
                "pbk": parsed.public_key,
                "sid": parsed.short_id,
                "spx": parsed.spider_x,
                "protocol": parsed.protocol,
                "export": parsed.export_url(),
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_vless_key(args: &[String]) -> RunnerOutput {
    let Some(password) = string_arg(args, "--password") else {
        return RunnerOutput::usage("missing outbound vless key --password");
    };
    match vless::password_to_key(password) {
        Ok(key) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "password": password,
                "key_hex": hex_encode(&key),
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_vless_request_header(args: &[String]) -> RunnerOutput {
    let Some(password) = string_arg(args, "--password") else {
        return RunnerOutput::usage("missing outbound vless request-header --password");
    };
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound vless request-header --target");
    };
    let network = string_arg(args, "--network").unwrap_or("tcp");
    let flow = string_arg(args, "--flow").unwrap_or("");
    let payload = string_arg(args, "--payload").unwrap_or("");
    let mux = bool_arg(args, "--mux").unwrap_or(false);
    let key = match vless::password_to_key(password) {
        Ok(key) => key,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    match vless::packet::first_write_bytes(&key, flow, network, target, mux, payload.as_bytes()) {
        Ok(header) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "target": target,
                "network": network,
                "flow": flow,
                "mux": mux,
                "payload_ascii": payload,
                "key_hex": hex_encode(&key),
                "captured_hex": hex_encode(&header),
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_vless_smoke(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound vless smoke --link");
    };
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound vless smoke --target");
    };
    let network = string_arg(args, "--network").unwrap_or("tcp");
    let payload = string_arg(args, "--payload").unwrap_or("ping");
    let parsed = match VLESSLink::parse(link).and_then(|parsed| {
        parsed.validate_flow_client(true)?;
        parsed.validate_transport_contract()?;
        Ok(parsed)
    }) {
        Ok(parsed) => parsed,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let key = match vless::password_to_key(&parsed.id) {
        Ok(key) => key,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let header = match vless::packet::first_write_bytes(
        &key,
        &parsed.flow,
        network,
        target,
        false,
        payload.as_bytes(),
    ) {
        Ok(header) => header,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "ok": true,
            "link": link,
            "target": target,
            "protocol": parsed.protocol,
            "flow": parsed.flow,
            "export": parsed.export_url(),
            "key_hex": hex_encode(&key),
            "captured_hex": hex_encode(&header),
            "production_data_plane_owner": vless::contract::PRODUCTION_DATA_PLANE_OWNER,
            "standalone_smoke_surface": vless::contract::STANDALONE_SMOKE_SURFACE,
            "vision_requires_tls_or_reality_hook": vless::contract::VISION_REQUIRES_TLS_OR_REALITY_HOOK,
        })
    ))
}
