use super::*;

pub(super) fn run_juicity(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("contract") => run_juicity_contract(),
        Some("link") => run_juicity_link(&args[1..]),
        Some("uuid") => run_juicity_uuid(&args[1..]),
        Some("pin") => run_juicity_pin(&args[1..]),
        Some("underlay") => run_juicity_underlay(&args[1..]),
        Some("smoke") => run_juicity_smoke(&args[1..]),
        Some(subcommand) => RunnerOutput::usage(format!(
            "unsupported outbound juicity subcommand: {subcommand}"
        )),
        None => RunnerOutput::usage("missing outbound juicity subcommand"),
    }
}

pub(super) fn run_juicity_contract() -> RunnerOutput {
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "juicity-rust-native",
            "rust_adapter_mode": juicity::contract::ADAPTER_MODE,
            "protocol_scope": juicity::contract::PROTOCOL_SCOPE,
            "deferred_protocol_scope": juicity::contract::DEFERRED_PROTOCOL_SCOPE,
            "live_smoke_required": juicity::contract::LIVE_SMOKE_REQUIRED,
            "quic_contract": {
                "alpn": juicity::contract::ALPN,
                "tls_min_version": juicity::contract::TLS_MIN_VERSION,
                "enable_datagrams": juicity::contract::ENABLE_DATAGRAMS,
                "keepalive_seconds": juicity::contract::KEEPALIVE_SECONDS,
                "handshake_idle_timeout_seconds": juicity::contract::HANDSHAKE_IDLE_TIMEOUT_SECONDS,
                "initial_stream_receive_window": juicity::contract::INITIAL_STREAM_RECEIVE_WINDOW,
                "max_stream_receive_window": juicity::contract::MAX_STREAM_RECEIVE_WINDOW,
                "initial_connection_receive_window": juicity::contract::INITIAL_CONNECTION_RECEIVE_WINDOW,
                "max_connection_receive_window": juicity::contract::MAX_CONNECTION_RECEIVE_WINDOW,
                "max_open_incoming_streams": juicity::contract::MAX_OPEN_INCOMING_STREAMS,
                "quic_max_open_incoming_streams": juicity::contract::QUIC_MAX_OPEN_INCOMING_STREAMS,
                "reserved_streams_capability": juicity::contract::RESERVED_STREAMS_CAPABILITY,
                "underlay_auth_channel_capacity": juicity::contract::UNDERLAY_AUTH_CHANNEL_CAPACITY,
                "congestion_default_or_unknown_uses": juicity::contract::CONGESTION_DEFAULT_OR_UNKNOWN_USES,
            },
            "underlay_contract": {
                "tcp_underlay_uses_udp": juicity::contract::TCP_UNDERLAY_USES_UDP,
                "tcp_underlay_preserves_mark": juicity::contract::TCP_UNDERLAY_PRESERVES_MARK,
                "tcp_underlay_drops_mptcp": juicity::contract::TCP_UNDERLAY_DROPS_MPTCP,
                "udp_underlay_uses_original": juicity::contract::UDP_UNDERLAY_USES_ORIGINAL,
                "udp_port_zero_packet_conn": juicity::contract::UDP_PORT_ZERO_PACKET_CONN,
                "udp_nonzero_port_packet_conn": juicity::contract::UDP_NONZERO_PORT_PACKET_CONN,
                "transport_packet_conn_uses_auth": juicity::contract::TRANSPORT_PACKET_CONN_USES_AUTH,
                "transport_packet_conn_cipher_info": juicity::contract::TRANSPORT_PACKET_CONN_CIPHER_INFO,
                "true_quic_data_plane_deferred": juicity::contract::TRUE_QUIC_DATA_PLANE_DEFERRED_ITEM,
            },
        })
    ))
}

pub(super) fn run_juicity_link(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound juicity link --link");
    };
    match JuicityLink::parse(link) {
        Ok(parsed) => {
            let pin = match juicity::link::decode_pinned_certchain(&parsed.pinned_certchain_sha256)
            {
                Ok(pin) => pin,
                Err(err) => return RunnerOutput::stdout_error(err.to_string()),
            };
            RunnerOutput::ok(format!(
                "{}\n",
                json!({
                    "input": link,
                    "user": parsed.user,
                    "password": parsed.password,
                    "server": parsed.server,
                    "port": parsed.port,
                    "sni": parsed.sni,
                    "allowInsecure": parsed.allow_insecure,
                    "congestion_control": parsed.congestion_control,
                    "pinned_certchain_sha256": parsed.pinned_certchain_sha256,
                    "pinned_certchain_decoded": {
                        "ok": pin.ok,
                        "format": pin.format,
                        "decoded_hex": hex_encode(&pin.decoded),
                    },
                    "protocol": parsed.protocol,
                    "export": parsed.export_url(),
                    "pin_forces_insecure_verify": parsed.pin_forces_insecure_verify(),
                })
            ))
        }
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_juicity_uuid(args: &[String]) -> RunnerOutput {
    let Some(user) = string_arg(args, "--user") else {
        return RunnerOutput::usage("missing outbound juicity uuid --user");
    };
    match juicity::link::validate_uuid(user) {
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

pub(super) fn run_juicity_pin(args: &[String]) -> RunnerOutput {
    let Some(input) = string_arg(args, "--input") else {
        return RunnerOutput::usage("missing outbound juicity pin --input");
    };
    match juicity::link::decode_pinned_certchain(input) {
        Ok(pin) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "input": input,
                "ok": pin.ok,
                "format": pin.format,
                "decoded_hex": hex_encode(&pin.decoded),
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_juicity_underlay(args: &[String]) -> RunnerOutput {
    let network = string_arg(args, "--network").unwrap_or("tcp");
    let mark = match u64_arg(args, "--mark").unwrap_or(Ok(0)) {
        Ok(value) => value as u32,
        Err(err) => return RunnerOutput::stdout_error(err),
    };
    let mptcp = bool_arg(args, "--mptcp").unwrap_or(false);
    let contract = juicity::link::underlay_contract(network, mark, mptcp);
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

pub(super) fn run_juicity_smoke(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound juicity smoke --link");
    };
    let parsed = match JuicityLink::parse(link) {
        Ok(parsed) => parsed,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    if let Err(err) = parsed.validate_uuid() {
        return RunnerOutput::stdout_error(err.to_string());
    }
    let pin = match juicity::link::decode_pinned_certchain(&parsed.pinned_certchain_sha256) {
        Ok(pin) => pin,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let tcp_underlay = juicity::link::underlay_contract("tcp", 1234, true);
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "ok": true,
            "link": link,
            "protocol": "juicity",
            "export": parsed.export_url(),
            "sni": parsed.sni,
            "allowInsecure": parsed.allow_insecure,
            "pin_forces_insecure_verify": parsed.pin_forces_insecure_verify(),
            "pinned_certchain_format": pin.format,
            "quic_alpn": juicity::contract::ALPN,
            "quic_enable_datagrams": juicity::contract::ENABLE_DATAGRAMS,
            "udp_port_zero_packet_conn": juicity::contract::UDP_PORT_ZERO_PACKET_CONN,
            "udp_nonzero_port_packet_conn": juicity::contract::UDP_NONZERO_PORT_PACKET_CONN,
            "tcp_underlay": {
                "underlay_network": tcp_underlay.underlay_network,
                "underlay_mark": tcp_underlay.underlay_mark,
                "underlay_mptcp": tcp_underlay.underlay_mptcp,
            },
            "transport_data_plane_deferred_to_item": juicity::contract::TRUE_QUIC_DATA_PLANE_DEFERRED_ITEM,
        })
    ))
}
