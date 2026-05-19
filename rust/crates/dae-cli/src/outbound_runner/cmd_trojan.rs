use super::*;

pub(super) fn run_trojan(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("contract") => run_trojan_contract(),
        Some("link") => run_trojan_link(&args[1..]),
        Some("metadata") => run_trojan_metadata(&args[1..]),
        Some("tcp-header") => run_trojan_tcp_header(&args[1..]),
        Some("udp-packet") => run_trojan_udp_packet(&args[1..]),
        Some("smoke") => run_trojan_smoke(&args[1..]),
        Some(subcommand) => RunnerOutput::usage(format!(
            "unsupported outbound trojan subcommand: {subcommand}"
        )),
        None => RunnerOutput::usage("missing outbound trojan subcommand"),
    }
}

pub(super) fn run_trojan_contract() -> RunnerOutput {
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "stage15-trojan-native-optin",
            "default_go_path": trojan::contract::DEFAULT_GO_PATH,
            "rust_adapter_mode": trojan::contract::ADAPTER_MODE,
            "protocol_scope": trojan::contract::PROTOCOL_SCOPE,
            "deferred_protocol_scope": trojan::contract::DEFERRED_PROTOCOL_SCOPE,
            "live_smoke_required": trojan::contract::LIVE_SMOKE_REQUIRED,
            "transport_contract": {
                "default_trojan_tls_before_trojanc": trojan::contract::DEFAULT_TROJAN_TLS_BEFORE_TROJANC,
                "trojan_go_grpc_contains_tls": trojan::contract::TROJAN_GO_GRPC_CONTAINS_TLS,
                "trojan_go_grpc_no_outer_tls": trojan::contract::TROJAN_GO_GRPC_NO_OUTER_TLS,
                "trojan_go_ss_inner_layer": trojan::contract::TROJAN_GO_SS_INNER_LAYER,
                "shared_transport_deferred_to_item": trojan::contract::SHARED_TRANSPORT_DEFERRED_TO_ITEM,
            },
        })
    ))
}

pub(super) fn run_trojan_link(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound trojan link --link");
    };
    match TrojanLink::parse(link) {
        Ok(parsed) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "input": link,
                "server": parsed.server,
                "port": parsed.port,
                "password": parsed.password,
                "sni": parsed.sni,
                "type": parsed.transport_type,
                "encryption": parsed.encryption,
                "host": parsed.host,
                "path": parsed.path,
                "serviceName": parsed.service_name,
                "allowInsecure": parsed.allow_insecure,
                "protocol": parsed.protocol,
                "export": parsed.export_url(),
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_trojan_metadata(args: &[String]) -> RunnerOutput {
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound trojan metadata --target");
    };
    let network = string_arg(args, "--network").unwrap_or("tcp");
    match TrojanMetadata::parse(network, target).and_then(|metadata| {
        let encoded = metadata.encode()?;
        Ok((metadata, encoded))
    }) {
        Ok((metadata, encoded)) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "target": target,
                "network": metadata.network.as_str(),
                "network_byte": metadata.network.byte(),
                "type": metadata.metadata_type_byte(),
                "hostname": metadata.hostname(),
                "port": metadata.port(),
                "hex": hex_encode(&encoded),
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_trojan_tcp_header(args: &[String]) -> RunnerOutput {
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound trojan tcp-header --target");
    };
    let password = string_arg(args, "--password").unwrap_or("");
    let network = string_arg(args, "--network").unwrap_or("tcp");
    let payload = string_arg(args, "--payload").unwrap_or("");
    match trojan::packet::tcp_request_header(password, network, target, payload.as_bytes()) {
        Ok(header) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "target": target,
                "network": network,
                "payload_ascii": payload,
                "header_hex": hex_encode(&header),
                "password_sha224_hex": trojan::packet::password_sha224_hex(password),
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_trojan_udp_packet(args: &[String]) -> RunnerOutput {
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound trojan udp-packet --target");
    };
    let payload = string_arg(args, "--payload").unwrap_or("");
    match trojan::packet::udp_packet(target, payload.as_bytes()) {
        Ok(packet) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "target": target,
                "payload_ascii": payload,
                "packet_hex": hex_encode(&packet),
                "length": payload.len(),
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_trojan_smoke(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound trojan smoke --link");
    };
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound trojan smoke --target");
    };
    let payload = string_arg(args, "--payload").unwrap_or("ping");
    let parsed = match TrojanLink::parse(link) {
        Ok(parsed) => parsed,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let tcp = match trojan::packet::tcp_request_header(
        &parsed.password,
        "tcp",
        target,
        payload.as_bytes(),
    ) {
        Ok(header) => header,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let udp = match trojan::packet::udp_packet(target, payload.as_bytes()) {
        Ok(packet) => packet,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "ok": true,
            "link": link,
            "target": target,
            "protocol": parsed.protocol,
            "type": parsed.transport_type,
            "export": parsed.export_url(),
            "tcp_header_hex": hex_encode(&tcp),
            "udp_packet_hex": hex_encode(&udp),
            "udp_over_tcp_stream": true,
            "transport_data_plane_deferred_to_item": trojan::contract::SHARED_TRANSPORT_DEFERRED_TO_ITEM,
        })
    ))
}
