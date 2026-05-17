use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use dae_outbound::http_proxy::{self, HttpConnectOptions, HttpProxyLink, request as http_request};
use dae_outbound::hysteria2::{self, Hysteria2Link};
use dae_outbound::parse_link_chain;
use dae_outbound::shadowsocks::{self, ShadowsocksLink, ShadowsocksMetadata};
use dae_outbound::socks5::{self, Socks5Address, handshake, udp_packet};
use dae_outbound::trojan::{self, TrojanLink, TrojanMetadata};
use dae_outbound::vless::{self, VLESSLink};
use dae_outbound::vmess::{self, VMessLink, VMessMetadata};
use serde_json::json;

use crate::runner::RunnerOutput;

pub(crate) fn run_outbound(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("socks5") => run_socks5(&args[1..]),
        Some("http") => run_http(&args[1..]),
        Some("shadowsocks") | Some("ss") => run_shadowsocks(&args[1..]),
        Some("trojan") | Some("trojan-go") => run_trojan(&args[1..]),
        Some("vmess") => run_vmess(&args[1..]),
        Some("vless") => run_vless(&args[1..]),
        Some("hysteria2") | Some("hy2") => run_hysteria2(&args[1..]),
        Some(subcommand) => {
            RunnerOutput::usage(format!("unsupported outbound subcommand: {subcommand}"))
        }
        None => RunnerOutput::usage("missing outbound subcommand"),
    }
}

fn run_hysteria2(args: &[String]) -> RunnerOutput {
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

fn run_hysteria2_contract() -> RunnerOutput {
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "stage15-hysteria2-native-optin",
            "default_go_path": hysteria2::contract::DEFAULT_GO_PATH,
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

fn run_hysteria2_link(args: &[String]) -> RunnerOutput {
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

fn run_hysteria2_pin(args: &[String]) -> RunnerOutput {
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

fn run_hysteria2_server(args: &[String]) -> RunnerOutput {
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

fn run_hysteria2_smoke(args: &[String]) -> RunnerOutput {
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

fn run_vless(args: &[String]) -> RunnerOutput {
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

fn run_vless_contract() -> RunnerOutput {
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "stage15-vless-native-optin",
            "default_go_path": vless::contract::DEFAULT_GO_PATH,
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
                "shared_transport_deferred_to_item": vless::contract::SHARED_TRANSPORT_DEFERRED_TO_ITEM,
            },
        })
    ))
}

fn run_vless_link(args: &[String]) -> RunnerOutput {
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

fn run_vless_key(args: &[String]) -> RunnerOutput {
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

fn run_vless_request_header(args: &[String]) -> RunnerOutput {
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

fn run_vless_smoke(args: &[String]) -> RunnerOutput {
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
            "transport_data_plane_deferred_to_item": vless::contract::SHARED_TRANSPORT_DEFERRED_TO_ITEM,
            "vision_requires_tls_or_reality_hook": vless::contract::VISION_REQUIRES_TLS_OR_REALITY_HOOK,
        })
    ))
}

fn run_vmess(args: &[String]) -> RunnerOutput {
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

fn run_vmess_contract() -> RunnerOutput {
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "stage15-vmess-native-optin",
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

fn run_vmess_link(args: &[String]) -> RunnerOutput {
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

fn run_vmess_metadata(args: &[String]) -> RunnerOutput {
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

fn run_vmess_uuid(args: &[String]) -> RunnerOutput {
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

fn run_vmess_smoke(args: &[String]) -> RunnerOutput {
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

fn run_trojan(args: &[String]) -> RunnerOutput {
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

fn run_trojan_contract() -> RunnerOutput {
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

fn run_trojan_link(args: &[String]) -> RunnerOutput {
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

fn run_trojan_metadata(args: &[String]) -> RunnerOutput {
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

fn run_trojan_tcp_header(args: &[String]) -> RunnerOutput {
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

fn run_trojan_udp_packet(args: &[String]) -> RunnerOutput {
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

fn run_trojan_smoke(args: &[String]) -> RunnerOutput {
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

fn run_shadowsocks(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("contract") => run_shadowsocks_contract(),
        Some("link") => run_shadowsocks_link(&args[1..]),
        Some("cipher") => run_shadowsocks_cipher(&args[1..]),
        Some("metadata") => run_shadowsocks_metadata(&args[1..]),
        Some("ss2022-psk") => run_shadowsocks_ss2022_psk(&args[1..]),
        Some("replay-filter") => run_shadowsocks_replay_filter(&args[1..]),
        Some("smoke") => run_shadowsocks_smoke(&args[1..]),
        Some(subcommand) => RunnerOutput::usage(format!(
            "unsupported outbound shadowsocks subcommand: {subcommand}"
        )),
        None => RunnerOutput::usage("missing outbound shadowsocks subcommand"),
    }
}

fn run_shadowsocks_contract() -> RunnerOutput {
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "stage15-shadowsocks-native-optin",
            "default_go_path": shadowsocks::contract::DEFAULT_GO_PATH,
            "rust_adapter_mode": shadowsocks::contract::ADAPTER_MODE,
            "protocol_scope": shadowsocks::contract::PROTOCOL_SCOPE,
            "deferred_protocol_scope": shadowsocks::contract::DEFERRED_PROTOCOL_SCOPE,
            "live_smoke_required": shadowsocks::contract::LIVE_SMOKE_REQUIRED,
            "sip003": {
                "simple_obfs_aliases": shadowsocks::contract::SIMPLE_OBFS_ALIASES,
                "default_simple_obfs_host": shadowsocks::contract::SIMPLE_OBFS_DEFAULT_HOST,
                "path_without_slash_go_behavior": shadowsocks::contract::SIP003_PATH_WITHOUT_SLASH_GO_BEHAVIOR,
                "transport_native_data_plane_deferred_to_item": shadowsocks::contract::TRANSPORT_NATIVE_DATA_PLANE_DEFERRED_TO_ITEM,
            },
        })
    ))
}

fn run_shadowsocks_link(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound shadowsocks link --link");
    };
    match ShadowsocksLink::parse(link) {
        Ok(parsed) => {
            let capability = match parsed.capability_label() {
                Ok(capability) => capability,
                Err(err) => return RunnerOutput::stdout_error(err.to_string()),
            };
            RunnerOutput::ok(format!(
                "{}\n",
                json!({
                    "input": link,
                    "server": parsed.server,
                    "port": parsed.port,
                    "cipher": parsed.cipher,
                    "password": parsed.password,
                    "udp": parsed.udp,
                    "protocol": parsed.protocol,
                    "capability": capability,
                    "export": parsed.export_url(),
                    "plugin": {
                        "name": parsed.plugin.name,
                        "tls": parsed.plugin.opts.tls,
                        "obfs": parsed.plugin.opts.obfs,
                        "host": parsed.plugin.opts.host,
                        "path": parsed.plugin.opts.path,
                    },
                })
            ))
        }
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

fn run_shadowsocks_cipher(args: &[String]) -> RunnerOutput {
    let Some(cipher) = string_arg(args, "--cipher") else {
        return RunnerOutput::usage("missing outbound shadowsocks cipher --cipher");
    };
    match shadowsocks::classify_cipher(cipher) {
        Ok(info) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "cipher": info.cipher,
                "go_protocol_dialer": info.go_protocol_dialer,
                "rust_capability_label": info.rust_capability_label,
                "export_userinfo_plain": info.export_userinfo_plain,
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

fn run_shadowsocks_metadata(args: &[String]) -> RunnerOutput {
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound shadowsocks metadata --target");
    };
    match ShadowsocksMetadata::parse(target).and_then(|metadata| {
        let encoded = metadata.encode()?;
        Ok((metadata, encoded))
    }) {
        Ok((metadata, encoded)) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "target": target,
                "type": metadata.metadata_type().byte(),
                "hostname": metadata.hostname(),
                "port": metadata.port(),
                "hex": hex_encode(&encoded),
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

fn run_shadowsocks_ss2022_psk(args: &[String]) -> RunnerOutput {
    let Some(cipher) = string_arg(args, "--cipher") else {
        return RunnerOutput::usage("missing outbound shadowsocks ss2022-psk --cipher");
    };
    let Some(password) = string_arg(args, "--password") else {
        return RunnerOutput::usage("missing outbound shadowsocks ss2022-psk --password");
    };
    match shadowsocks::ss2022::validate_psk_list(cipher, password) {
        Ok(info) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "cipher": info.cipher,
                "password": password,
                "psk_count": info.psk_count,
                "psk_key_lens": info.psk_key_lens,
                "upsk_index": info.upsk_index,
                "expected_key_len": info.expected_key_len,
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

fn run_shadowsocks_replay_filter(args: &[String]) -> RunnerOutput {
    let window = match u64_arg(args, "--window").unwrap_or(Ok(4)) {
        Ok(value) => value as usize,
        Err(message) => return RunnerOutput::usage(message),
    };
    let mut duplicate = shadowsocks::ss2022::SlidingWindowFilter::new(window);
    let first = duplicate.check_and_update(1);
    let duplicate_packet = duplicate.check_and_update(1);
    let mut old = shadowsocks::ss2022::SlidingWindowFilter::new(window);
    let mut monotonic = Vec::new();
    for packet_id in [10, 11, 12, 13, 14] {
        monotonic.push(old.check_and_update(packet_id));
    }
    let too_old = old.check_and_update(10);
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "window": window,
            "first_packet_accepted": first,
            "duplicate_packet_accepted": duplicate_packet,
            "monotonic_accepts": monotonic,
            "too_old_packet_accepted": too_old,
        })
    ))
}

fn run_shadowsocks_smoke(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound shadowsocks smoke --link");
    };
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound shadowsocks smoke --target");
    };
    let parsed = match ShadowsocksLink::parse(link) {
        Ok(parsed) => parsed,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let metadata = match ShadowsocksMetadata::parse(target).and_then(|metadata| {
        let encoded = metadata.encode()?;
        Ok((metadata, encoded))
    }) {
        Ok(value) => value,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let psk = if parsed.cipher.starts_with("2022-blake3-") {
        match shadowsocks::ss2022::validate_psk_list(&parsed.cipher, &parsed.password) {
            Ok(info) => Some(json!({
                "psk_count": info.psk_count,
                "upsk_index": info.upsk_index,
                "expected_key_len": info.expected_key_len,
            })),
            Err(err) => return RunnerOutput::stdout_error(err.to_string()),
        }
    } else {
        None
    };
    let mut replay = shadowsocks::ss2022::SlidingWindowFilter::new(4);
    let replay_ok = replay.check_and_update(1) && !replay.check_and_update(1);
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "ok": true,
            "link": link,
            "target": target,
            "capability": parsed.capability_label().unwrap_or("shadowsocks"),
            "export": parsed.export_url(),
            "metadata_hex": hex_encode(&metadata.1),
            "metadata_authority": metadata.0.authority(),
            "ss2022_psk": psk,
            "replay_duplicate_rejected": replay_ok,
            "transport_data_plane_deferred_to_item": shadowsocks::contract::TRANSPORT_NATIVE_DATA_PLANE_DEFERRED_TO_ITEM,
        })
    ))
}

fn run_http(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("contract") => run_http_contract(),
        Some("link") => run_http_link(&args[1..]),
        Some("connect") => run_http_connect(&args[1..]),
        Some("forward") => run_http_forward(&args[1..]),
        Some("smoke") => run_http_smoke(&args[1..]),
        Some(subcommand) => RunnerOutput::usage(format!(
            "unsupported outbound http subcommand: {subcommand}"
        )),
        None => RunnerOutput::usage("missing outbound http subcommand"),
    }
}

fn run_http_contract() -> RunnerOutput {
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "stage15-http-native-optin",
            "default_go_path": http_proxy::contract::DEFAULT_GO_PATH,
            "rust_adapter_mode": http_proxy::contract::ADAPTER_MODE,
            "protocol_scope": http_proxy::contract::PROTOCOL_SCOPE,
            "allow_insecure_aliases": http_proxy::contract::ALLOW_INSECURE_ALIASES,
            "https": {
                "default_port": 443,
                "default_alpn_query_value": http_proxy::contract::HTTPS_DEFAULT_ALPN_QUERY_VALUE,
                "default_tls_implementation": http_proxy::contract::HTTPS_DEFAULT_TLS_IMPLEMENTATION,
                "h2_route_context_required": http_proxy::contract::HTTPS_H2_ROUTE_CONTEXT_REQUIRED,
            },
            "live_smoke_required": http_proxy::contract::LIVE_SMOKE_REQUIRED,
        })
    ))
}

fn run_http_link(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound http link --link");
    };
    match HttpProxyLink::parse(link) {
        Ok(parsed) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "input": link,
                "server": parsed.server,
                "port": parsed.port,
                "username": parsed.username,
                "password": parsed.password,
                "sni": parsed.sni,
                "effective_sni": parsed.effective_sni(),
                "protocol": parsed.protocol.as_str(),
                "allowInsecure": parsed.allow_insecure,
                "export": parsed.export_url(),
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

fn run_http_connect(args: &[String]) -> RunnerOutput {
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound http connect --target");
    };
    let options = http_options_from_args(target, args);
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "target": options.target,
            "transport": options.transport.enabled,
            "request_hex": hex_encode(&http_request::connect_request(&options)),
            "basic_auth_header": http_request::basic_auth_header(&options.username, &options.password),
        })
    ))
}

fn run_http_forward(args: &[String]) -> RunnerOutput {
    let Some(raw_hex) = string_arg(args, "--raw-hex") else {
        return RunnerOutput::usage("missing outbound http forward --raw-hex");
    };
    let raw = match hex_decode(raw_hex) {
        Ok(raw) => raw,
        Err(err) => return RunnerOutput::stdout_error(err),
    };
    match http_request::forward_http_request(&raw) {
        Ok(request) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "request_hex": hex_encode(&request),
                "proxy_connection_removed": true,
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

fn run_http_smoke(args: &[String]) -> RunnerOutput {
    let Some(proxy) = string_arg(args, "--proxy") else {
        return RunnerOutput::usage("missing outbound http smoke --proxy");
    };
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound http smoke --target");
    };
    let timeout_ms = match u64_arg(args, "--timeout-ms").unwrap_or(Ok(2000)) {
        Ok(value) => value,
        Err(message) => return RunnerOutput::usage(message),
    };
    let options = http_options_from_args(target, args);
    match http_smoke(proxy, &options, Duration::from_millis(timeout_ms)) {
        Ok(report) => RunnerOutput::ok(format!("{report}\n")),
        Err(err) => RunnerOutput::stdout_error(err),
    }
}

fn http_options_from_args(target: &str, args: &[String]) -> HttpConnectOptions {
    let mut options = HttpConnectOptions::connect(target);
    options.username = string_arg(args, "--username").unwrap_or("").to_owned();
    options.password = string_arg(args, "--password").unwrap_or("").to_owned();
    options.host_override = string_arg(args, "--host").unwrap_or("").to_owned();
    options.transport.enabled = bool_arg(args, "--transport").unwrap_or(false);
    options.transport.path = string_arg(args, "--path").unwrap_or("/").to_owned();
    options
}

fn http_smoke(
    proxy: &str,
    options: &HttpConnectOptions,
    timeout: Duration,
) -> Result<String, String> {
    let mut stream = TcpStream::connect(proxy).map_err(|err| err.to_string())?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| err.to_string())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| err.to_string())?;
    let request = http_request::connect_request(options);
    stream.write_all(&request).map_err(|err| err.to_string())?;
    let mut response = Vec::new();
    let mut buf = [0_u8; 512];
    loop {
        let n = stream.read(&mut buf).map_err(|err| err.to_string())?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let status = http_request::parse_connect_response(&response).map_err(|err| err.to_string())?;
    if status != 200 {
        return Err(format!("http proxy status: {status}"));
    }
    Ok(format!(
        "{}",
        json!({
            "ok": true,
            "proxy": proxy,
            "target": options.target,
            "transport": options.transport.enabled,
            "status": status,
            "request_hex": hex_encode(&request),
        })
    ))
}

fn run_socks5(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("contract") => run_socks5_contract(),
        Some("codec") => run_socks5_codec(&args[1..]),
        Some("handshake") => run_socks5_handshake(&args[1..]),
        Some("udp-packet") => run_socks5_udp_packet(&args[1..]),
        Some("smoke") => run_socks5_smoke(&args[1..]),
        Some(subcommand) => RunnerOutput::usage(format!(
            "unsupported outbound socks5 subcommand: {subcommand}"
        )),
        None => RunnerOutput::usage("missing outbound socks5 subcommand"),
    }
}

fn run_socks5_contract() -> RunnerOutput {
    let link =
        "manual-name:socks5://user:pass@127.0.0.1:1080#outer -> socks://127.0.0.2:1081#inner";
    let parsed = parse_link_chain(link).unwrap();
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "stage15-socks5-native-optin",
            "default_go_path": socks5::contract::DEFAULT_GO_PATH,
            "rust_adapter_mode": socks5::contract::ADAPTER_MODE,
            "protocol_scope": socks5::contract::PROTOCOL_SCOPE,
            "deferred_protocol_scope": socks5::contract::DEFERRED_PROTOCOL_SCOPE,
            "live_smoke_required": socks5::contract::LIVE_SMOKE_REQUIRED,
            "deadline_contract": socks5::contract::DEADLINE_CONTRACT,
            "link_parser": {
                "input": link,
                "plaintext_tag": parsed.plaintext_tag,
                "linklike": parsed.linklike,
                "name": parsed.property_name,
                "protocol": parsed.property_protocol,
                "address": parsed.property_address,
                "first_adapter_mode": parsed.nodes.first().map(|node| node.adapter_mode.as_str()).unwrap_or(""),
            }
        })
    ))
}

fn run_socks5_codec(args: &[String]) -> RunnerOutput {
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound socks5 codec --target");
    };
    match Socks5Address::parse(target).and_then(|addr| {
        let encoded = addr.encode()?;
        let (decoded, consumed) = Socks5Address::decode(&encoded)?;
        Ok((addr, encoded, decoded, consumed))
    }) {
        Ok((addr, encoded, decoded, consumed)) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "target": target,
                "kind": format!("{:?}", addr.kind()).to_ascii_lowercase(),
                "encoded_hex": hex_encode(&encoded),
                "decoded": decoded.authority(),
                "consumed": consumed,
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

fn run_socks5_handshake(args: &[String]) -> RunnerOutput {
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound socks5 handshake --target");
    };
    let username = string_arg(args, "--username").unwrap_or("");
    let password = string_arg(args, "--password").unwrap_or("");
    let command = match string_arg(args, "--command").unwrap_or("connect") {
        "connect" => handshake::Socks5Command::Connect,
        "udp-associate" => handshake::Socks5Command::UdpAssociate,
        value => {
            return RunnerOutput::usage(format!(
                "bad outbound socks5 handshake --command: {value}"
            ));
        }
    };
    let target = match Socks5Address::parse(target) {
        Ok(target) => target,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let request = match handshake::request(command, &target) {
        Ok(request) => request,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let auth = if handshake::password_auth_allowed(username, password) {
        match handshake::username_password_auth(username, password) {
            Ok(auth) => Some(hex_encode(&auth)),
            Err(err) => return RunnerOutput::stdout_error(err.to_string()),
        }
    } else {
        None
    };
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "target": target.authority(),
            "command": match command {
                handshake::Socks5Command::Connect => "connect",
                handshake::Socks5Command::UdpAssociate => "udp-associate",
            },
            "greeting_hex": hex_encode(&handshake::greeting(username, password)),
            "auth_hex": auth,
            "request_hex": hex_encode(&request),
        })
    ))
}

fn run_socks5_udp_packet(args: &[String]) -> RunnerOutput {
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound socks5 udp-packet --target");
    };
    let payload = string_arg(args, "--payload").unwrap_or("");
    let wrapped = match udp_packet::wrap_target(target, payload.as_bytes()) {
        Ok(wrapped) => wrapped,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let unwrapped = match udp_packet::unwrap(&wrapped) {
        Ok(unwrapped) => unwrapped,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "target": unwrapped.target.authority(),
            "payload": String::from_utf8_lossy(&unwrapped.payload),
            "packet_hex": hex_encode(&wrapped),
            "reserved": unwrapped.reserved,
            "fragment": unwrapped.fragment,
        })
    ))
}

fn run_socks5_smoke(args: &[String]) -> RunnerOutput {
    let Some(proxy) = string_arg(args, "--proxy") else {
        return RunnerOutput::usage("missing outbound socks5 smoke --proxy");
    };
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound socks5 smoke --target");
    };
    let username = string_arg(args, "--username").unwrap_or("");
    let password = string_arg(args, "--password").unwrap_or("");
    let timeout_ms = match u64_arg(args, "--timeout-ms").unwrap_or(Ok(2000)) {
        Ok(value) => value,
        Err(message) => return RunnerOutput::usage(message),
    };
    let command = match string_arg(args, "--command").unwrap_or("connect") {
        "connect" => handshake::Socks5Command::Connect,
        "udp-associate" => handshake::Socks5Command::UdpAssociate,
        value => {
            return RunnerOutput::usage(format!("bad outbound socks5 smoke --command: {value}"));
        }
    };
    match socks5_smoke(
        proxy,
        target,
        username,
        password,
        command,
        Duration::from_millis(timeout_ms),
    ) {
        Ok(report) => RunnerOutput::ok(format!("{report}\n")),
        Err(err) => RunnerOutput::stdout_error(err),
    }
}

fn socks5_smoke(
    proxy: &str,
    target: &str,
    username: &str,
    password: &str,
    command: handshake::Socks5Command,
    timeout: Duration,
) -> Result<String, String> {
    let target = Socks5Address::parse(target).map_err(|err| err.to_string())?;
    let mut stream = TcpStream::connect(proxy).map_err(|err| err.to_string())?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| err.to_string())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| err.to_string())?;

    let greeting = handshake::greeting(username, password);
    stream.write_all(&greeting).map_err(|err| err.to_string())?;

    let mut method_selection = [0_u8; 2];
    stream
        .read_exact(&mut method_selection)
        .map_err(|err| err.to_string())?;
    let method =
        handshake::parse_method_selection(&method_selection).map_err(|err| err.to_string())?;

    let mut auth_status = None;
    if method == handshake::AUTH_PASSWORD {
        let auth =
            handshake::username_password_auth(username, password).map_err(|err| err.to_string())?;
        stream.write_all(&auth).map_err(|err| err.to_string())?;
        let mut auth_reply = [0_u8; 2];
        stream
            .read_exact(&mut auth_reply)
            .map_err(|err| err.to_string())?;
        if auth_reply[0] != handshake::PASSWORD_AUTH_VERSION || auth_reply[1] != 0 {
            return Err(format!("socks5 auth rejected: {:02x?}", auth_reply));
        }
        auth_status = Some(auth_reply[1]);
    }

    let request = handshake::request(command, &target).map_err(|err| err.to_string())?;
    stream.write_all(&request).map_err(|err| err.to_string())?;

    let mut reply = [0_u8; 3];
    stream
        .read_exact(&mut reply)
        .map_err(|err| err.to_string())?;
    let mut reply_bytes = reply.to_vec();
    reply_bytes.extend(read_socks5_address_bytes(&mut stream).map_err(|err| err.to_string())?);
    let parsed_reply =
        handshake::parse_server_reply(&reply_bytes).map_err(|err| err.to_string())?;

    Ok(format!(
        "{}",
        json!({
            "ok": true,
            "proxy": proxy,
            "target": target.authority(),
            "command": match command {
                handshake::Socks5Command::Connect => "connect",
                handshake::Socks5Command::UdpAssociate => "udp-associate",
            },
            "method": method,
            "auth_status": auth_status,
            "bind": parsed_reply.bind.authority(),
            "greeting_hex": hex_encode(&greeting),
            "request_hex": hex_encode(&request),
        })
    ))
}

fn read_socks5_address_bytes(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut atyp = [0_u8; 1];
    stream.read_exact(&mut atyp)?;
    let mut out = atyp.to_vec();
    match atyp[0] {
        1 => {
            let mut rest = [0_u8; 6];
            stream.read_exact(&mut rest)?;
            out.extend_from_slice(&rest);
        }
        3 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len)?;
            out.extend_from_slice(&len);
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream.read_exact(&mut rest)?;
            out.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0_u8; 18];
            stream.read_exact(&mut rest)?;
            out.extend_from_slice(&rest);
        }
        _ => {}
    }
    Ok(out)
}

fn string_arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == name {
            return iter.next().map(String::as_str);
        }
        if let Some((key, value)) = arg.split_once('=') {
            if key == name {
                return Some(value);
            }
        }
    }
    None
}

fn u64_arg(args: &[String], name: &str) -> Option<Result<u64, String>> {
    string_arg(args, name).map(|value| {
        value
            .parse::<u64>()
            .map_err(|err| format!("bad outbound socks5 {name}: {err}"))
    })
}

fn bool_arg(args: &[String], name: &str) -> Option<bool> {
    string_arg(args, name).and_then(|value| match value {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err("odd hex length".to_owned());
    }
    input
        .as_bytes()
        .chunks(2)
        .map(|chunk| Ok((hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?))
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("bad hex byte: {byte}")),
    }
}
