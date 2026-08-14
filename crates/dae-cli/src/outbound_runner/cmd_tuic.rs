use super::*;

pub(super) fn run_tuic(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("contract") => run_tuic_contract(),
        Some("link") => run_tuic_link(&args[1..]),
        Some("uuid") => run_tuic_uuid(&args[1..]),
        Some("underlay") => run_tuic_underlay(&args[1..]),
        Some("smoke") => run_tuic_smoke(&args[1..]),
        Some(subcommand) => RunnerOutput::usage(format!(
            "unsupported outbound tuic subcommand: {subcommand}"
        )),
        None => RunnerOutput::usage("missing outbound tuic subcommand"),
    }
}

pub(super) fn run_tuic_contract() -> RunnerOutput {
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "tuic-rust-native",
            "rust_adapter_mode": tuic::contract::ADAPTER_MODE,
            "protocol_scope": tuic::contract::PROTOCOL_SCOPE,
            "deferred_protocol_scope": tuic::contract::DEFERRED_PROTOCOL_SCOPE,
            "live_smoke_required": tuic::contract::LIVE_SMOKE_REQUIRED,
            "quic_contract": {
                "tls_min_version": tuic::contract::TLS_MIN_VERSION,
                "enable_datagrams": tuic::contract::ENABLE_DATAGRAMS,
                "keepalive_seconds": tuic::contract::KEEPALIVE_SECONDS,
                "handshake_idle_timeout_seconds": tuic::contract::HANDSHAKE_IDLE_TIMEOUT_SECONDS,
                "initial_stream_receive_window": tuic::contract::INITIAL_STREAM_RECEIVE_WINDOW,
                "max_stream_receive_window": tuic::contract::MAX_STREAM_RECEIVE_WINDOW,
                "initial_connection_receive_window": tuic::contract::INITIAL_CONNECTION_RECEIVE_WINDOW,
                "max_connection_receive_window": tuic::contract::MAX_CONNECTION_RECEIVE_WINDOW,
                "max_udp_relay_packet_size": tuic::contract::MAX_UDP_RELAY_PACKET_SIZE,
                "congestion_default_or_unknown_uses": tuic::contract::CONGESTION_DEFAULT_OR_UNKNOWN_USES,
            },
            "udp_relay_mode": {
                "query_value": tuic::contract::UDP_RELAY_MODE_QUERY_VALUE,
                "adapter_sets_flag": tuic::contract::UDP_RELAY_MODE_ADAPTER_SETS_FLAG,
                "flag_value": tuic::contract::UDP_RELAY_MODE_FLAG_VALUE,
                "protocol_effective_mode": tuic::contract::UDP_RELAY_MODE_PROTOCOL_EFFECTIVE_MODE,
                "common_quic_numeric_value": tuic::contract::UDP_RELAY_MODE_COMMON_QUIC_NUMERIC_VALUE,
                "common_native_value": tuic::contract::UDP_RELAY_MODE_COMMON_NATIVE_VALUE,
                "quic_mode_deferred": tuic::contract::UDP_RELAY_MODE_QUIC_DEFERRED,
            },
            "underlay_contract": {
                "tcp_underlay_uses_udp": tuic::contract::TCP_UNDERLAY_USES_UDP,
                "tcp_underlay_preserves_mark": tuic::contract::TCP_UNDERLAY_PRESERVES_MARK,
                "tcp_underlay_drops_mptcp": tuic::contract::TCP_UNDERLAY_DROPS_MPTCP,
                "udp_underlay_uses_original": tuic::contract::UDP_UNDERLAY_USES_ORIGINAL,
                "true_quic_data_plane_deferred": tuic::contract::TRUE_QUIC_DATA_PLANE_DEFERRED_ITEM,
            },
        })
    ))
}

pub(super) fn run_tuic_link(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound tuic link --link");
    };
    match TuicLink::parse(link) {
        Ok(parsed) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "input": link,
                "user": parsed.user,
                "password": parsed.password,
                "server": parsed.server,
                "port": parsed.port,
                "sni": parsed.sni,
                "allowInsecure": parsed.allow_insecure,
                "disable_sni": parsed.disable_sni,
                "congestion_control": parsed.congestion_control,
                "alpn": parsed.alpn,
                "udp_relay_mode": parsed.udp_relay_mode,
                "protocol": parsed.protocol,
                "export": parsed.export_url(),
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_tuic_uuid(args: &[String]) -> RunnerOutput {
    let Some(user) = string_arg(args, "--user") else {
        return RunnerOutput::usage("missing outbound tuic uuid --user");
    };
    match tuic::link::validate_uuid(user) {
        Ok(()) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "user": user,
                "ok": true,
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_tuic_underlay(args: &[String]) -> RunnerOutput {
    let network = string_arg(args, "--network").unwrap_or("tcp");
    let mark = match u64_arg(args, "--mark").unwrap_or(Ok(0)) {
        Ok(value) => value as u32,
        Err(err) => return RunnerOutput::stdout_error(err),
    };
    let mptcp = bool_arg(args, "--mptcp").unwrap_or(false);
    let contract = tuic::link::underlay_contract(network, mark, mptcp);
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

pub(super) fn run_tuic_smoke(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound tuic smoke --link");
    };
    let parsed = match TuicLink::parse(link) {
        Ok(parsed) => parsed,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    if let Err(err) = parsed.validate_uuid() {
        return RunnerOutput::stdout_error(err.to_string());
    }
    let tcp_underlay = tuic::link::underlay_contract("tcp", 1234, true);
    let udp_relay_mode = match TuicUdpRelayMode::from_config(&parsed.udp_relay_mode) {
        Ok(mode) => mode,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "ok": true,
            "link": link,
            "protocol": "tuic",
            "export": parsed.export_url(),
            "sni": parsed.sni,
            "allowInsecure": parsed.allow_insecure,
            "disable_sni": parsed.disable_sni,
            "udp_relay_mode": parsed.udp_relay_mode,
            "udp_relay_effective_mode": udp_relay_mode.as_str(),
            "tcp_underlay": {
                "underlay_network": tcp_underlay.underlay_network,
                "underlay_mark": tcp_underlay.underlay_mark,
                "underlay_mptcp": tcp_underlay.underlay_mptcp,
            },
            "transport_data_plane_deferred_to_item": tuic::contract::TRUE_QUIC_DATA_PLANE_DEFERRED_ITEM,
        })
    ))
}
