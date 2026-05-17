use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use dae_outbound::parse_link_chain;
use dae_outbound::socks5::{self, Socks5Address, handshake, udp_packet};
use serde_json::json;

use crate::runner::RunnerOutput;

pub(crate) fn run_outbound(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("socks5") => run_socks5(&args[1..]),
        Some(subcommand) => {
            RunnerOutput::usage(format!("unsupported outbound subcommand: {subcommand}"))
        }
        None => RunnerOutput::usage("missing outbound subcommand"),
    }
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
            return RunnerOutput::usage(format!("bad outbound socks5 handshake --command: {value}"));
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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
