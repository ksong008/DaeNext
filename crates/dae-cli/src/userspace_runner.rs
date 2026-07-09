use std::net::IpAddr;
use std::str::FromStr;

use dae_dns::DnsCacheKey;
use dae_netutil::{encode_magic_network, parse_magic_network};
use dae_outbound::policy::parse_policy;
use dae_outbound::{Annotation, Dialer, DialerGroup, NetworkType};
use dae_routing::{Query, RoutingMatcher};
use dae_sniffing::sniff_tcp;
use serde_json::json;

use crate::runner::RunnerOutput;

pub(crate) fn run_userspace(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("route-match") => run_route_match(&args[1..]),
        Some("dns-cache-key") => run_dns_cache_key(&args[1..]),
        Some("outbound-select") => run_outbound_select(&args[1..]),
        Some("sniff-tcp") => run_sniff_tcp(&args[1..]),
        Some("magic-network") => run_magic_network(&args[1..]),
        Some(subcommand) => {
            RunnerOutput::usage(format!("unsupported userspace subcommand: {subcommand}"))
        }
        None => RunnerOutput::usage("missing userspace subcommand"),
    }
}

fn run_route_match(args: &[String]) -> RunnerOutput {
    let mut domain = None;
    let mut dest = None;
    let mut port = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--domain" => domain = iter.next().map(String::as_str),
            "--dest" => dest = iter.next().map(String::as_str),
            "--port" => port = iter.next().map(String::as_str),
            _ if arg.starts_with("--domain=") => {
                domain = arg.split_once('=').map(|(_, value)| value);
            }
            _ if arg.starts_with("--dest=") => {
                dest = arg.split_once('=').map(|(_, value)| value);
            }
            _ if arg.starts_with("--port=") => {
                port = arg.split_once('=').map(|(_, value)| value);
            }
            _ => {
                return RunnerOutput::usage(format!(
                    "unsupported userspace route-match argument: {arg}"
                ));
            }
        }
    }
    let Some(domain) = domain else {
        return RunnerOutput::usage("missing userspace route-match --domain");
    };
    let Some(dest) = dest else {
        return RunnerOutput::usage("missing userspace route-match --dest");
    };
    let Some(port) = port else {
        return RunnerOutput::usage("missing userspace route-match --port");
    };

    let dest_ip = match IpAddr::from_str(dest) {
        Ok(dest_ip) => dest_ip,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let dest_port = match port.parse::<u16>() {
        Ok(dest_port) => dest_port,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let matcher_fixture = json!({
        "domain_sets": [
            {
                "bit": 0,
                "key": "suffix",
                "patterns": ["fixture.invalid"]
            }
        ],
        "matches": [
            {
                "outbound": "direct",
                "type": "domain_set"
            },
            {
                "outbound": "block",
                "type": "fallback"
            }
        ]
    });
    let matcher = match RoutingMatcher::from_fixture_value(&matcher_fixture) {
        Ok(matcher) => matcher,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let outbound = match matcher.match_query(&Query {
        dest: dest_ip,
        dest_port,
        domain: domain.to_owned(),
        ..Query::default()
    }) {
        Ok(outbound) => outbound,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };

    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "domain": domain,
            "dest": dest,
            "dest_port": dest_port,
            "outbound": outbound.to_string(),
            "userspace_only": true,
        })
    ))
}

fn run_dns_cache_key(args: &[String]) -> RunnerOutput {
    let mut qname = None;
    let mut qtype = None;
    let mut qclass = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--qname" => qname = iter.next().map(String::as_str),
            "--qtype" => qtype = iter.next().map(String::as_str),
            "--qclass" => qclass = iter.next().map(String::as_str),
            _ if arg.starts_with("--qname=") => {
                qname = arg.split_once('=').map(|(_, value)| value);
            }
            _ if arg.starts_with("--qtype=") => {
                qtype = arg.split_once('=').map(|(_, value)| value);
            }
            _ if arg.starts_with("--qclass=") => {
                qclass = arg.split_once('=').map(|(_, value)| value);
            }
            _ => {
                return RunnerOutput::usage(format!(
                    "unsupported userspace dns-cache-key argument: {arg}"
                ));
            }
        }
    }
    let Some(qname) = qname else {
        return RunnerOutput::usage("missing userspace dns-cache-key --qname");
    };
    let qtype = match parse_u16_arg(qtype, "userspace dns-cache-key --qtype") {
        Ok(qtype) => qtype,
        Err(output) => return output,
    };
    let qclass = match parse_u16_arg(qclass, "userspace dns-cache-key --qclass") {
        Ok(qclass) => qclass,
        Err(output) => return output,
    };
    let key = DnsCacheKey::new(qname, qtype, qclass);
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "qname": key.qname,
            "qtype": key.qtype,
            "qclass": key.qclass,
            "key": key.to_string(),
            "userspace_only": true,
        })
    ))
}

fn run_outbound_select(args: &[String]) -> RunnerOutput {
    let mut policy = None;
    let mut network = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--policy" => policy = iter.next().map(String::as_str),
            "--network" => network = iter.next().map(String::as_str),
            _ if arg.starts_with("--policy=") => {
                policy = arg.split_once('=').map(|(_, value)| value);
            }
            _ if arg.starts_with("--network=") => {
                network = arg.split_once('=').map(|(_, value)| value);
            }
            _ => {
                return RunnerOutput::usage(format!(
                    "unsupported userspace outbound-select argument: {arg}"
                ));
            }
        }
    }
    let Some(policy_raw) = policy else {
        return RunnerOutput::usage("missing userspace outbound-select --policy");
    };
    let Some(network_raw) = network else {
        return RunnerOutput::usage("missing userspace outbound-select --network");
    };
    let policy = match parse_policy(policy_raw) {
        Ok(policy) => policy,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let network = match parse_network_type(network_raw) {
        Some(network) => network,
        None => {
            return RunnerOutput::usage(format!(
                "unsupported userspace outbound-select --network: {network_raw}"
            ));
        }
    };

    let mut group = DialerGroup::new(
        "fixture",
        (0..4)
            .map(|index| Dialer::new(format!("dialer{index}"), ""))
            .collect(),
        vec![Annotation::default(); 4],
        policy.clone(),
        true,
        0,
    );
    for (index, latency) in [200, 100, 300, 150].iter().copied().enumerate() {
        group.set_last_latency(index, network, latency);
        group.notify_alive(index, network, true);
    }
    let selected = match group.select(network, false) {
        Ok(selected) => selected,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };

    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "policy": policy.as_str(),
            "network": network_raw,
            "selected_index": selected.index,
            "latency_ms": selected.latency_ms,
            "userspace_only": true,
        })
    ))
}

fn run_sniff_tcp(args: &[String]) -> RunnerOutput {
    let mut kind = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--kind" => kind = iter.next().map(String::as_str),
            _ if arg.starts_with("--kind=") => {
                kind = arg.split_once('=').map(|(_, value)| value);
            }
            _ => {
                return RunnerOutput::usage(format!(
                    "unsupported userspace sniff-tcp argument: {arg}"
                ));
            }
        }
    }
    let Some(kind) = kind else {
        return RunnerOutput::usage("missing userspace sniff-tcp --kind");
    };
    let data = match kind {
        "http" => {
            b"GET /path HTTP/1.1\r\nHost: Fixture.Invalid:443\r\nUser-Agent: dae\r\n\r\n".as_slice()
        }
        _ => {
            return RunnerOutput::usage(format!("unsupported userspace sniff-tcp --kind: {kind}"));
        }
    };
    match sniff_tcp(data) {
        Ok(domain) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "kind": kind,
                "domain": domain,
                "relay_reader_must_keep_buffer": true,
                "userspace_only": true,
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

fn run_magic_network(args: &[String]) -> RunnerOutput {
    let mut network = None;
    let mut mark = None;
    let mut mptcp = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--network" => network = iter.next().map(String::as_str),
            "--mark" => mark = iter.next().map(String::as_str),
            "--mptcp" => mptcp = iter.next().map(String::as_str),
            _ if arg.starts_with("--network=") => {
                network = arg.split_once('=').map(|(_, value)| value);
            }
            _ if arg.starts_with("--mark=") => {
                mark = arg.split_once('=').map(|(_, value)| value);
            }
            _ if arg.starts_with("--mptcp=") => {
                mptcp = arg.split_once('=').map(|(_, value)| value);
            }
            _ => {
                return RunnerOutput::usage(format!(
                    "unsupported userspace magic-network argument: {arg}"
                ));
            }
        }
    }
    let Some(network) = network else {
        return RunnerOutput::usage("missing userspace magic-network --network");
    };
    let mark = match mark.unwrap_or("0").parse::<u32>() {
        Ok(mark) => mark,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let mptcp = match parse_bool(mptcp.unwrap_or("false")) {
        Some(mptcp) => mptcp,
        None => return RunnerOutput::usage("bad userspace magic-network --mptcp"),
    };
    let encoded = match encode_magic_network(network, mark, mptcp) {
        Ok(encoded) => encoded,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let parsed = match parse_magic_network(&encoded) {
        Ok(parsed) => parsed,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let parsed_network = match parsed.network_str() {
        Ok(network) => network,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };

    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "network": network,
            "mark": mark,
            "mptcp": mptcp,
            "encoded_hex": hex_encode(&encoded),
            "plain": encoded == network.as_bytes(),
            "parsed_network": parsed_network,
            "parsed_mark": parsed.mark,
            "parsed_mptcp": parsed.mptcp,
            "userspace_only": true,
        })
    ))
}

fn parse_u16_arg(raw: Option<&str>, name: &str) -> Result<u16, RunnerOutput> {
    let Some(raw) = raw else {
        return Err(RunnerOutput::usage(format!("missing {name}")));
    };
    raw.parse::<u16>()
        .map_err(|err| RunnerOutput::stdout_error(err.to_string()))
}

fn parse_network_type(input: &str) -> Option<NetworkType> {
    match input {
        "tcp4" => Some(NetworkType::TCP4),
        "tcp6" => Some(NetworkType::TCP6),
        "udp4" => Some(NetworkType::DATA_UDP4),
        "udp6" => Some(NetworkType::DATA_UDP6),
        _ => None,
    }
}

fn parse_bool(input: &str) -> Option<bool> {
    match input {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
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
