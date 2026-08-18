use super::*;

pub(super) fn run_anytls(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("contract") => run_anytls_contract(),
        Some("link") => run_anytls_link(&args[1..]),
        Some("auth-key") => run_anytls_auth_key(&args[1..]),
        Some("frame") => run_anytls_frame(&args[1..]),
        Some("packet") => run_anytls_packet(&args[1..]),
        Some("underlay") => run_anytls_underlay(&args[1..]),
        Some("smoke") => run_anytls_smoke(&args[1..]),
        Some(subcommand) => RunnerOutput::usage(format!(
            "unsupported outbound anytls subcommand: {subcommand}"
        )),
        None => RunnerOutput::usage("missing outbound anytls subcommand"),
    }
}

pub(super) fn run_anytls_contract() -> RunnerOutput {
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "anytls-rust-native",
            "rust_adapter_mode": anytls::contract::ADAPTER_MODE,
            "protocol_scope": anytls::contract::PROTOCOL_SCOPE,
            "deferred_protocol_scope": anytls::contract::DEFERRED_PROTOCOL_SCOPE,
            "live_smoke_required": anytls::contract::LIVE_SMOKE_REQUIRED,
            "tls_contract": {
                "empty_sni_server_name": anytls::contract::EMPTY_SNI_SERVER_NAME,
                "insecure_only_when": anytls::contract::INSECURE_ONLY_WHEN,
                "peer_overrides_sni": anytls::contract::PEER_OVERRIDES_SNI,
            },
            "session_contract": {
                "idle_session_reuse_map": anytls::contract::IDLE_SESSION_REUSE_MAP,
                "session_counter": anytls::contract::SESSION_COUNTER,
                "padding": {
                    "stop": anytls::contract::PADDING_STOP,
                    "raw": anytls::contract::DEFAULT_PADDING_RAW,
                    "md5": anytls::contract::DEFAULT_PADDING_MD5,
                    "settings": String::from_utf8(anytls::link::settings_bytes()).unwrap(),
                    "settings_hex": hex_encode(&anytls::link::settings_bytes()),
                    "check_mark": anytls::contract::CHECK_MARK,
                },
                "frame": {
                    "header_overhead_size": anytls::contract::HEADER_OVERHEAD_SIZE,
                    "cmd_waste": anytls::contract::CMD_WASTE,
                    "cmd_syn": anytls::contract::CMD_SYN,
                    "cmd_psh": anytls::contract::CMD_PSH,
                    "cmd_fin": anytls::contract::CMD_FIN,
                    "cmd_settings": anytls::contract::CMD_SETTINGS,
                    "cmd_alert": anytls::contract::CMD_ALERT,
                    "cmd_update_padding": anytls::contract::CMD_UPDATE_PADDING,
                    "cmd_synack": anytls::contract::CMD_SYNACK,
                    "cmd_heart_request": anytls::contract::CMD_HEART_REQUEST,
                    "cmd_heart_response": anytls::contract::CMD_HEART_RESPONSE,
                    "cmd_server_settings": anytls::contract::CMD_SERVER_SETTINGS,
                },
            },
            "underlay_contract": {
                "underlay_always_tcp": anytls::contract::UNDERLAY_ALWAYS_TCP,
                "underlay_preserves_mark": anytls::contract::UNDERLAY_PRESERVES_MARK,
                "underlay_preserves_mptcp": anytls::contract::UNDERLAY_PRESERVES_MPTCP,
                "true_session_data_plane_deferred": anytls::contract::TRUE_SESSION_DATA_PLANE_DEFERRED_ITEM,
            },
        })
    ))
}

pub(super) fn run_anytls_link(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound anytls link --link");
    };
    match AnyTLSLink::parse(link) {
        Ok(parsed) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "input": link,
                "name": parsed.name,
                "auth": parsed.auth,
                "host": parsed.host,
                "hostname": parsed.hostname,
                "sni": parsed.sni,
                "tls_server_name": parsed.tls_server_name,
                "insecure": parsed.insecure,
                "protocol": parsed.protocol,
                "link_preserved": parsed.export_url(),
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_anytls_auth_key(args: &[String]) -> RunnerOutput {
    let Some(auth) = string_arg(args, "--auth") else {
        return RunnerOutput::usage("missing outbound anytls auth-key --auth");
    };
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "auth": auth,
            "sha256_hex": hex_encode(&anytls::link::auth_key(auth)),
            "handshake_hex": hex_encode(&anytls::link::handshake_auth_bytes(auth)),
        })
    ))
}

pub(super) fn run_anytls_frame(args: &[String]) -> RunnerOutput {
    let target = string_arg(args, "--target").unwrap_or("fixture.invalid:443");
    let settings = anytls::link::settings_bytes();
    let addr = match anytls::link::socks_addr(target) {
        Ok(addr) => addr,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let settings_frame = match anytls::link::frame(anytls::contract::CMD_SETTINGS, 1, &settings) {
        Ok(frame) => frame,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let syn_frame = match anytls::link::frame(anytls::contract::CMD_SYN, 1, &[]) {
        Ok(frame) => frame,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let psh_addr_frame = match anytls::link::frame(anytls::contract::CMD_PSH, 1, &addr) {
        Ok(frame) => frame,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "target": target,
            "settings_hex": hex_encode(&settings),
            "settings_frame_hex": hex_encode(&settings_frame),
            "syn_frame_hex": hex_encode(&syn_frame),
            "psh_addr_frame_hex": hex_encode(&psh_addr_frame),
        })
    ))
}

pub(super) fn run_anytls_packet(args: &[String]) -> RunnerOutput {
    let target = string_arg(args, "--target").unwrap_or("fixture.invalid:53");
    let payload = string_arg(args, "--payload").unwrap_or("ping");
    let stream_target = match anytls::link::udp_stream_target(target) {
        Ok(target) => target,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let first = match anytls::link::packet_first_write(target, payload.as_bytes()) {
        Ok(first) => first,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let next_write = match anytls::link::packet_next_write(payload.as_bytes()) {
        Ok(next_write) => next_write,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "udp_magic_domain": anytls::contract::UDP_MAGIC_DOMAIN,
            "udp_input_target": target,
            "udp_stream_target": stream_target,
            "udp_original_packet_addr": target,
            "first_write_hex": hex_encode(&first),
            "next_write_hex": hex_encode(&next_write),
        })
    ))
}

pub(super) fn run_anytls_underlay(args: &[String]) -> RunnerOutput {
    let network = string_arg(args, "--network").unwrap_or("udp");
    let mark = match u64_arg(args, "--mark").unwrap_or(Ok(0)) {
        Ok(value) => value as u32,
        Err(err) => return RunnerOutput::stdout_error(err),
    };
    let mptcp = bool_arg(args, "--mptcp").unwrap_or(false);
    let contract = match anytls::link::underlay_contract(network, mark, mptcp) {
        Ok(contract) => contract,
        Err(error) => return RunnerOutput::stdout_error(error.to_string()),
    };
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "input_network": contract.input_network,
            "input_mark": contract.input_mark,
            "input_mptcp": contract.input_mptcp,
            "input_hex": hex_encode(&contract.input_encoded),
            "underlay_network": contract.underlay_network,
            "underlay_mark": contract.underlay_mark,
            "underlay_mptcp": contract.underlay_mptcp,
            "underlay_hex": hex_encode(&contract.underlay_encoded),
            "same_encoded_value": contract.same_encoded_value,
        })
    ))
}

pub(super) fn run_anytls_smoke(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound anytls smoke --link");
    };
    let parsed = match AnyTLSLink::parse(link) {
        Ok(parsed) => parsed,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let packet_target = "fixture.invalid:53";
    let stream_target = match anytls::link::udp_stream_target(packet_target) {
        Ok(target) => target,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let udp_underlay = anytls::link::underlay_contract("udp", 1234, true)
        .expect("fixed AnyTLS UDP network fits MagicNetwork framing");
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "ok": true,
            "link": link,
            "protocol": "anytls",
            "export": parsed.export_url(),
            "sni": parsed.sni,
            "tls_server_name": parsed.tls_server_name,
            "insecure": parsed.insecure,
            "auth_key_hex": hex_encode(&anytls::link::auth_key(&parsed.auth)),
            "udp_stream_target": stream_target,
            "underlay": {
                "underlay_network": udp_underlay.underlay_network,
                "underlay_mark": udp_underlay.underlay_mark,
                "underlay_mptcp": udp_underlay.underlay_mptcp,
            },
            "transport_data_plane_deferred_to_item": anytls::contract::TRUE_SESSION_DATA_PLANE_DEFERRED_ITEM,
        })
    ))
}
