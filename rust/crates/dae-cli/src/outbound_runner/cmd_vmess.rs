use super::*;

pub(super) fn run_vmess(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("contract") => run_vmess_contract(),
        Some("link") => run_vmess_link(&args[1..]),
        Some("metadata") => run_vmess_metadata(&args[1..]),
        Some("uuid") => run_vmess_uuid(&args[1..]),
        Some("smoke") => run_vmess_smoke(&args[1..]),
        Some(subcommand) => RunnerOutput::usage(format!(
            "unsupported outbound vmess subcommand: {subcommand}"
        )),
        None => RunnerOutput::usage("missing outbound vmess subcommand"),
    }
}

pub(super) fn run_vmess_contract() -> RunnerOutput {
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "vmess-native-optin",
            "default_go_path": vmess::contract::DEFAULT_GO_PATH,
            "rust_adapter_mode": vmess::contract::ADAPTER_MODE,
            "protocol_scope": vmess::contract::PROTOCOL_SCOPE,
            "deferred_protocol_scope": vmess::contract::DEFERRED_PROTOCOL_SCOPE,
            "live_smoke_required": vmess::contract::LIVE_SMOKE_REQUIRED,
            "header_contract": {
                "version": vmess::contract::HEADER_VERSION,
                "option_chunk_stream": vmess::contract::OPTION_CHUNK_STREAM,
                "option_chunk_length_masking": vmess::contract::OPTION_CHUNK_LENGTH_MASKING,
                "option_global_padding": vmess::contract::OPTION_GLOBAL_PADDING,
                "security_auto_cipher": vmess::contract::SECURITY_AUTO_CIPHER,
                "network_tcp": vmess::VMessNetwork::Tcp.byte(),
                "network_udp": vmess::VMessNetwork::Udp.byte(),
                "network_mux": vmess::VMessNetwork::Mux.byte(),
                "metadata_domain_type": vmess::VMessMetadataType::Domain.byte(),
                "packet_addr_udp_domain_contract": true,
            },
            "transport_contract": {
                "ws_tls_uses_wss": vmess::contract::WS_TLS_USES_WSS,
                "grpc_default_service_name": vmess::contract::GRPC_DEFAULT_SERVICE_NAME,
                "http_h2_httpupgrade_meek_xhttp": "deferred-to-shared-transport",
                "vmess_reality_must_error": vmess::contract::VMESS_REALITY_MUST_ERROR,
                "shared_transport_deferred_to_item": vmess::contract::SHARED_TRANSPORT_DEFERRED_TO_ITEM,
            },
        })
    ))
}

pub(super) fn run_vmess_link(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound vmess link --link");
    };
    match VMessLink::parse(link).and_then(|parsed| {
        parsed.validate_aead()?;
        parsed.validate_transport()?;
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
                "aid": parsed.aid,
                "net": parsed.net,
                "type": parsed.r#type,
                "host": parsed.host,
                "sni": parsed.sni,
                "path": parsed.path,
                "tls": parsed.tls,
                "allowInsecure": parsed.allow_insecure,
                "protocol": parsed.protocol,
                "export": parsed.export_url(),
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_vmess_metadata(args: &[String]) -> RunnerOutput {
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound vmess metadata --target");
    };
    let network = string_arg(args, "--network").unwrap_or("tcp");
    match VMessMetadata::parse(network, target).and_then(|metadata| {
        let encoded = metadata.encode_addr()?;
        Ok((metadata, encoded))
    }) {
        Ok((metadata, encoded)) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "target": target,
                "network": metadata.network.as_str(),
                "network_byte": metadata.network.byte(),
                "type": metadata.metadata_type().byte(),
                "hostname": metadata.hostname(),
                "port": metadata.port(),
                "addr_len": metadata.addr_len(),
                "packed_len": encoded.len(),
                "addr_hex": hex_encode(&encoded),
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_vmess_uuid(args: &[String]) -> RunnerOutput {
    let Some(input) = string_arg(args, "--input") else {
        return RunnerOutput::usage("missing outbound vmess uuid --input");
    };
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "input": input,
            "uuid": vmess::uuid::normalize_vmess_uuid(input),
        })
    ))
}

pub(super) fn run_vmess_smoke(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound vmess smoke --link");
    };
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound vmess smoke --target");
    };
    let network = string_arg(args, "--network").unwrap_or("tcp");
    let parsed = match VMessLink::parse(link).and_then(|parsed| {
        parsed.validate_aead()?;
        parsed.validate_transport()?;
        Ok(parsed)
    }) {
        Ok(parsed) => parsed,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let metadata = match VMessMetadata::parse(network, target).and_then(|metadata| {
        let encoded = metadata.encode_addr()?;
        Ok((metadata, encoded))
    }) {
        Ok(value) => value,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "ok": true,
            "link": link,
            "target": target,
            "protocol": parsed.protocol,
            "export": parsed.export_url(),
            "normalized_uuid": vmess::uuid::normalize_vmess_uuid(&parsed.id),
            "metadata_addr_hex": hex_encode(&metadata.1),
            "metadata_network_byte": metadata.0.network.byte(),
            "metadata_type": metadata.0.metadata_type().byte(),
            "header_contract": {
                "version": vmess::contract::HEADER_VERSION,
                "option_chunk_stream": vmess::contract::OPTION_CHUNK_STREAM,
                "option_chunk_length_masking": vmess::contract::OPTION_CHUNK_LENGTH_MASKING,
                "option_global_padding": vmess::contract::OPTION_GLOBAL_PADDING,
                "security_auto_cipher": vmess::contract::SECURITY_AUTO_CIPHER,
            },
            "transport_data_plane_deferred_to_item": vmess::contract::SHARED_TRANSPORT_DEFERRED_TO_ITEM,
        })
    ))
}
