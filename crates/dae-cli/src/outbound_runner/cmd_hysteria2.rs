use super::*;

pub(super) fn run_hysteria2(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("contract") => run_hysteria2_contract(),
        Some("link") => run_hysteria2_link(&args[1..]),
        Some("pin") => run_hysteria2_pin(&args[1..]),
        Some("server") => run_hysteria2_server(&args[1..]),
        Some("smoke") => run_hysteria2_smoke(&args[1..]),
        Some(subcommand) => RunnerOutput::usage(format!(
            "unsupported outbound hysteria2 subcommand: {subcommand}"
        )),
        None => RunnerOutput::usage("missing outbound hysteria2 subcommand"),
    }
}

pub(super) fn run_hysteria2_contract() -> RunnerOutput {
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "hysteria2-rust-native",
            "rust_adapter_mode": hysteria2::contract::ADAPTER_MODE,
            "protocol_scope": hysteria2::contract::PROTOCOL_SCOPE,
            "deferred_protocol_scope": hysteria2::contract::DEFERRED_PROTOCOL_SCOPE,
            "live_smoke_required": hysteria2::contract::LIVE_SMOKE_REQUIRED,
            "underlay_contract": {
                "always_udp_underlay": hysteria2::contract::ALWAYS_UDP_UNDERLAY,
                "tcp_target_uses_hysteria2_client": hysteria2::contract::TCP_TARGET_USES_HYSTERIA2_CLIENT,
                "udp_target_uses_hysteria2_client": hysteria2::contract::UDP_TARGET_USES_HYSTERIA2_CLIENT,
                "preserve_mark": hysteria2::contract::PRESERVE_MARK,
                "preserve_mptcp_field_even_for_udp": hysteria2::contract::PRESERVE_MPTCP_FIELD_EVEN_FOR_UDP,
                "route_cache_key_is_underlay_network": hysteria2::contract::ROUTE_CACHE_KEY_IS_UNDERLAY_NETWORK,
                "port_hopping_detects_dash_or_comma": hysteria2::contract::PORT_HOPPING_DETECTS_DASH_OR_COMMA,
                "udp_hop_interval_from_extra_option": hysteria2::contract::UDP_HOP_INTERVAL_FROM_EXTRA_OPTION,
                "true_quic_data_plane_deferred_item": hysteria2::contract::TRUE_QUIC_DATA_PLANE_DEFERRED_ITEM,
            },
        })
    ))
}

pub(super) fn run_hysteria2_link(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound hysteria2 link --link");
    };
    match Hysteria2Link::parse(link) {
        Ok(parsed) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "input": link,
                "user": parsed.user,
                "password": parsed.password,
                "server": parsed.server,
                "insecure": parsed.insecure,
                "sni": parsed.sni,
                "pinSHA256": parsed.pin_sha256,
                "pinSHA256_normal": hysteria2::link::normalize_pin_sha256(&parsed.pin_sha256),
                "maxTx": parsed.max_tx,
                "maxRx": parsed.max_rx,
                "export": parsed.export_url(),
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_hysteria2_pin(args: &[String]) -> RunnerOutput {
    let Some(input) = string_arg(args, "--input") else {
        return RunnerOutput::usage("missing outbound hysteria2 pin --input");
    };
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "input": input,
            "normalized": hysteria2::link::normalize_pin_sha256(input),
        })
    ))
}

pub(super) fn run_hysteria2_server(args: &[String]) -> RunnerOutput {
    let Some(server) = string_arg(args, "--server") else {
        return RunnerOutput::usage("missing outbound hysteria2 server --server");
    };
    let contract = hysteria2::link::server_contract(server);
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "server": contract.server,
            "host": contract.host,
            "port": contract.port,
            "host_port": contract.host_port,
            "port_hopping": contract.port_hopping,
        })
    ))
}

pub(super) fn run_hysteria2_smoke(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound hysteria2 smoke --link");
    };
    let parsed = match Hysteria2Link::parse(link) {
        Ok(parsed) => parsed,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let server = hysteria2::link::server_contract(&parsed.server);
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "ok": true,
            "link": link,
            "protocol": "hysteria2",
            "export": parsed.export_url(),
            "pinSHA256_normal": hysteria2::link::normalize_pin_sha256(&parsed.pin_sha256),
            "server": {
                "host": server.host,
                "port": server.port,
                "host_port": server.host_port,
                "port_hopping": server.port_hopping,
            },
            "underlay_network": "udp",
            "transport_data_plane_deferred_to_item": hysteria2::contract::TRUE_QUIC_DATA_PLANE_DEFERRED_ITEM,
        })
    ))
}
