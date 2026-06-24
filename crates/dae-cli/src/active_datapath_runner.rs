use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use dae_datapath::{RouteRule, magic_network_bytes, route_loop, udp_endpoint_pool_trim_target};
use dae_ebpf_support::{
    DaeParamInput, FeatureGateReport, PinnedMapAction, TPROXY_MARK, Version, build_dae_param,
    map_catalog, pinned_map_action, pinned_reuse_maps,
};
use dae_runtime_control::{CoreFlip, ReloadCoreState, RuntimeDependencyPlan};
use serde_json::json;

use crate::runner::RunnerOutput;

pub(crate) fn run_active_datapath(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("preflight") => run_preflight(&args[1..]),
        Some("contract") => run_contract(),
        Some("reload-ownership") => run_reload_ownership(),
        Some("magic-dial") => run_magic_dial(&args[1..]),
        Some(subcommand) => RunnerOutput::usage(format!(
            "unsupported active-datapath subcommand: {subcommand}"
        )),
        None => RunnerOutput::usage("missing active-datapath subcommand"),
    }
}

fn run_preflight(args: &[String]) -> RunnerOutput {
    let mut tproxy_port = 12345_u16;
    let mut so_mark = 0_u32;
    let mut mptcp = false;
    let mut lan_count = 0_usize;
    let mut wan_count = 0_usize;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--tproxy-port" => {
                tproxy_port =
                    match parse_next::<u16>(&mut iter, "active-datapath preflight --tproxy-port") {
                        Ok(value) => value,
                        Err(output) => return output,
                    };
            }
            "--so-mark" => {
                so_mark = match parse_next::<u32>(&mut iter, "active-datapath preflight --so-mark")
                {
                    Ok(value) => value,
                    Err(output) => return output,
                };
            }
            "--mptcp" => {
                mptcp = match iter.next().and_then(|value| parse_bool(value)) {
                    Some(value) => value,
                    None => return RunnerOutput::usage("bad active-datapath preflight --mptcp"),
                };
            }
            "--lan-count" => {
                lan_count =
                    match parse_next::<usize>(&mut iter, "active-datapath preflight --lan-count") {
                        Ok(value) => value,
                        Err(output) => return output,
                    };
            }
            "--wan-count" => {
                wan_count =
                    match parse_next::<usize>(&mut iter, "active-datapath preflight --wan-count") {
                        Ok(value) => value,
                        Err(output) => return output,
                    };
            }
            _ if arg.starts_with("--tproxy-port=") => {
                tproxy_port = match parse_value(arg, "active-datapath preflight --tproxy-port") {
                    Ok(value) => value,
                    Err(output) => return output,
                };
            }
            _ if arg.starts_with("--so-mark=") => {
                so_mark = match parse_value(arg, "active-datapath preflight --so-mark") {
                    Ok(value) => value,
                    Err(output) => return output,
                };
            }
            _ if arg.starts_with("--mptcp=") => {
                mptcp = match arg.split_once('=').and_then(|(_, value)| parse_bool(value)) {
                    Some(value) => value,
                    None => return RunnerOutput::usage("bad active-datapath preflight --mptcp"),
                };
            }
            _ if arg.starts_with("--lan-count=") => {
                lan_count = match parse_value(arg, "active-datapath preflight --lan-count") {
                    Ok(value) => value,
                    Err(output) => return output,
                };
            }
            _ if arg.starts_with("--wan-count=") => {
                wan_count = match parse_value(arg, "active-datapath preflight --wan-count") {
                    Ok(value) => value,
                    Err(output) => return output,
                };
            }
            _ => {
                return RunnerOutput::usage(format!(
                    "unsupported active-datapath preflight argument: {arg}"
                ));
            }
        }
    }

    let gates = preflight_gates(lan_count > 0, wan_count > 0);
    let allowed = gates.values().copied().all(|value| value);
    let output = format!(
        "{}\n",
        json!({
            "allowed": allowed,
            "gates": gates,
            "tproxy_port": tproxy_port,
            "so_mark": so_mark,
            "mptcp": mptcp,
            "lan_configured": lan_count > 0,
            "wan_configured": wan_count > 0,
            "bpffs_path": "/sys/fs/bpf",
            "pre_side_effect_gate": true,
        })
    );
    if allowed {
        RunnerOutput::ok(output)
    } else {
        RunnerOutput::stdout_error(output.trim_end())
    }
}

fn run_contract() -> RunnerOutput {
    let gates = RuntimeDependencyPlan::default_env_gates()
        .gates
        .iter()
        .map(|gate| json!({"name": gate.name, "required": gate.required}))
        .collect::<Vec<_>>();
    let param = build_dae_param(DaeParamInput {
        tproxy_port: 12345,
        control_plane_pid: 4242,
        dae0_ifindex: 17,
        dae_netns_id: 23,
        dae0peer_mac: [2, 0, 0, 0, 0, 1],
        has_bpf_get_current_task: false,
        task_struct_mm_offset: 0,
        mm_struct_arg_start_offset: 0,
    });
    let map_names = map_catalog().iter().map(|map| map.name).collect::<Vec<_>>();
    let pinned_action =
        match pinned_map_action("use pinned map routing_tuples_map: key size mismatch") {
            PinnedMapAction::DeleteAndRetry { map_name } => {
                json!({"action": "delete_and_retry", "map": map_name})
            }
            PinnedMapAction::ReturnError => json!({"action": "return_error"}),
        };
    let route = route_loop(&[
        RouteRule {
            kind: "IpSet".to_owned(),
            outbound: 7,
            mark: 0x1234,
            must: false,
            matched: false,
        },
        RouteRule {
            kind: "Port".to_owned(),
            outbound: 8,
            mark: TPROXY_MARK,
            must: false,
            matched: true,
        },
        RouteRule {
            kind: "Fallback".to_owned(),
            outbound: 1,
            mark: 0,
            must: false,
            matched: true,
        },
    ])
    .unwrap();
    let magic = magic_network_bytes("tcp", 1234, true);
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "fixture-active-datapath-runtime-contract",
            "required_environment": gates,
            "preflight_before_side_effects": true,
            "ebpf": {
                "pin_root": "/sys/fs/bpf",
                "map_count": map_catalog().len(),
                "map_names": map_names,
                "pinned_reuse_maps": pinned_reuse_maps(),
                "incompatible_pinned_map_action": pinned_action,
                "tproxy_port_big_endian": param.tproxy_port,
                "listen_socket_map_keys": [0, 1]
            },
            "attach_order": [
                "kernel feature gate",
                "remove memlock",
                "netns setup",
                "load or reuse eBPF objects",
                "bind LAN tc filters",
                "bind WAN tc/cgroup filters",
                "bind dae0/dae0peer tc filters",
                "build routing kernspace/userspace",
                "create DNS controller",
                "ListenAndServe writes TCP/UDP sockets into listen_socket_map"
            ],
            "reload_restore_injects_previous_bpf": true,
            "route_loop": {
                "outbound": route.outbound,
                "mark": route.mark,
                "must": route.must,
                "fallback": route.fallback
            },
            "udp_endpoint_trim_4096": udp_endpoint_pool_trim_target(4096),
            "tcp_udp": {
                "tcp_sniff_before_bpf_result": true,
                "tcp_relay_uses_sniffer_reader": true,
                "udp_53_dns_controller": true,
                "udp_quic_target_stays_ip": true
            },
            "magic_network": {
                "network": "tcp",
                "mark": 1234,
                "mptcp": true,
                "encoded_hex": hex_encode(&magic),
                "plain": magic == b"tcp"
            },
            "netns_same_interface_risk": {
                "tc_act_pipe_required": true,
                "do_not_reorder_tc_filters": true,
                "netkit_native_attach_defer": true
            }
        })
    ))
}

fn run_reload_ownership() -> RunnerOutput {
    RunnerOutput::ok(format!("{}\n", reload_ownership_json()))
}

fn reload_ownership_json() -> serde_json::Value {
    let mut flip = CoreFlip::default();
    let mut fresh = ReloadCoreState::new(false, &mut flip);
    let mut steps = vec![reload_step("fresh_init", &fresh)];
    fresh.eject_bpf();
    steps.push(reload_step("after_eject", &fresh));
    fresh.inject_bpf();
    steps.push(reload_step("after_inject", &fresh));
    let mut reload = ReloadCoreState::new(true, &mut flip);
    steps.push(reload_step("reload_init", &reload));
    reload.eject_bpf();
    steps.push(reload_step("reload_after_eject", &reload));
    json!({
        "steps": steps,
        "reload_restore_injects_previous_bpf": true,
        "dns_cache_snapshot_required": true,
        "listener_reuse_required": true
    })
}

fn reload_step(step: &str, state: &ReloadCoreState) -> serde_json::Value {
    json!({
        "step": step,
        "is_reload": state.is_reload,
        "bpf_ejected": state.bpf_ejected,
        "defer_func_count": state.defer_func_count,
        "flip": state.flip,
    })
}

fn run_magic_dial(args: &[String]) -> RunnerOutput {
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
                    "unsupported active-datapath magic-dial argument: {arg}"
                ));
            }
        }
    }
    let Some(network) = network else {
        return RunnerOutput::usage("missing active-datapath magic-dial --network");
    };
    let mark = match mark.unwrap_or("0").parse::<u32>() {
        Ok(mark) => mark,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let mptcp = match parse_bool(mptcp.unwrap_or("false")) {
        Some(mptcp) => mptcp,
        None => return RunnerOutput::usage("bad active-datapath magic-dial --mptcp"),
    };
    let encoded = magic_network_bytes(network, mark, mptcp);
    let parsed_network = if encoded == network.as_bytes() {
        network.to_owned()
    } else {
        let len = encoded.get(1).copied().unwrap_or(0) as usize;
        String::from_utf8_lossy(&encoded[2..2 + len]).to_string()
    };
    let parsed_mark = if encoded == network.as_bytes() {
        0
    } else {
        let len = encoded[1] as usize;
        u32::from_be_bytes([
            encoded[2 + len],
            encoded[3 + len],
            encoded[4 + len],
            encoded[5 + len],
        ])
    };
    let parsed_mptcp = encoded != network.as_bytes() && encoded.last().copied() == Some(1);
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "network": network,
            "mark": mark,
            "mptcp": mptcp,
            "encoded_hex": hex_encode(&encoded),
            "plain": encoded == network.as_bytes(),
            "parsed_network": parsed_network,
            "parsed_mark": parsed_mark,
            "parsed_mptcp": parsed_mptcp,
            "active_path": true,
        })
    ))
}

fn preflight_gates(lan_configured: bool, wan_configured: bool) -> BTreeMap<&'static str, bool> {
    let mut gates = BTreeMap::new();
    gates.insert("root", effective_uid() == Some(0));
    gates.insert("bpffs", bpffs_mounted());
    gates.insert("netns_permission", Path::new("/proc/self/ns/net").exists());
    gates.insert(
        "memlock",
        max_locked_memory_bytes()
            .map(|value| value > 0)
            .unwrap_or(false),
    );
    let kernel_ok = current_kernel_version()
        .map(|version| FeatureGateReport::new(version, lan_configured, wan_configured).allowed())
        .unwrap_or(false);
    gates.insert("kernel_feature_version", kernel_ok);
    gates
}

fn effective_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest
                .split_whitespace()
                .nth(1)
                .and_then(|value| value.parse::<u32>().ok());
        }
    }
    None
}

fn bpffs_mounted() -> bool {
    let Ok(mounts) = fs::read_to_string("/proc/mounts") else {
        return false;
    };
    mounts.lines().any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields.len() >= 3 && fields[1] == "/sys/fs/bpf" && fields[2] == "bpf"
    })
}

fn max_locked_memory_bytes() -> Option<u64> {
    let limits = fs::read_to_string("/proc/self/limits").ok()?;
    for line in limits.lines() {
        if !line.starts_with("Max locked memory") {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let soft = fields.get(fields.len().saturating_sub(3))?;
        if *soft == "unlimited" {
            return Some(u64::MAX);
        }
        return soft.parse::<u64>().ok();
    }
    None
}

fn current_kernel_version() -> Option<Version> {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    let version = release
        .split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .next()?;
    let mut parts = version.split('.');
    let major = parts.next()?.parse::<u16>().ok()?;
    let minor = parts.next().unwrap_or("0").parse::<u16>().ok()?;
    let patch = parts.next().unwrap_or("0").parse::<u16>().ok()?;
    Some(Version::new(major, minor, patch))
}

fn parse_bool(input: &str) -> Option<bool> {
    match input {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn parse_next<T: std::str::FromStr>(
    iter: &mut std::slice::Iter<'_, String>,
    name: &str,
) -> Result<T, RunnerOutput>
where
    T::Err: std::fmt::Display,
{
    let Some(value) = iter.next() else {
        return Err(RunnerOutput::usage(format!("missing {name}")));
    };
    value
        .parse::<T>()
        .map_err(|err| RunnerOutput::stdout_error(err.to_string()))
}

fn parse_value<T: std::str::FromStr>(arg: &str, name: &str) -> Result<T, RunnerOutput>
where
    T::Err: std::fmt::Display,
{
    let Some((_, value)) = arg.split_once('=') else {
        return Err(RunnerOutput::usage(format!("missing {name}")));
    };
    value
        .parse::<T>()
        .map_err(|err| RunnerOutput::stdout_error(err.to_string()))
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
