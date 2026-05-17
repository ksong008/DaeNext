use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use dae_outbound::http_proxy::{self, HttpConnectOptions, HttpProxyLink, request as http_request};
use dae_outbound::parse_link_chain;
use dae_outbound::shadowsocks::{self, ShadowsocksLink, ShadowsocksMetadata};
use dae_outbound::socks5::{self, Socks5Address, handshake, udp_packet};
use serde_json::json;

use crate::runner::RunnerOutput;

pub(crate) fn run_outbound(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("socks5") => run_socks5(&args[1..]),
        Some("http") => run_http(&args[1..]),
        Some("shadowsocks") | Some("ss") => run_shadowsocks(&args[1..]),
        Some(subcommand) => {
            RunnerOutput::usage(format!("unsupported outbound subcommand: {subcommand}"))
        }
        None => RunnerOutput::usage("missing outbound subcommand"),
    }
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
