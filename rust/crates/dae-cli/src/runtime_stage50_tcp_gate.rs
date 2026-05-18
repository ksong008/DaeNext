use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use dae_ebpf_support::{
    DaeParamInput, RuntimeMapInfo, build_dae_param, map_ids, map_info,
    open_live_loaded_tproxy_listen_socket_map_in_netns, open_map_fd, update_map_elem_bytes,
    write_param_aware_object,
};
use serde_json::{Map, Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_STAGE50_ROOT: &str = "/tmp/dae-stage50-candidate";
const DEFAULT_STAGE50_SOURCE_OBJECT: &str = "control/bpf_bpfel.o";
const DEFAULT_STAGE50_PEER_SECTION: &str = "tc/dae0peer_ingress";
const DEFAULT_STAGE50_HOST_SECTION: &str = "tc/dae0_ingress";
const DEFAULT_STAGE50_LAN_SECTION: &str = "tc/lan_ingress_l2";
const DEFAULT_STAGE50_TPROXY_PORT: u16 = 35050;
const DEFAULT_STAGE50_DAE_NETNS_ID: u32 = 50;
const DEFAULT_STAGE50_TARGET_PORT: u16 = 18080;
const DEFAULT_STAGE50_CLIENT_IP: &str = "10.220.50.2";
const DEFAULT_STAGE50_LAN_GATEWAY_IP: &str = "10.220.50.1";
const DEFAULT_STAGE50_TARGET_IP: &str = "198.18.50.1";
const STAGE50_FILTER_PREF: &str = "49500";
const STAGE50_LAN_FILTER_PREF: &str = "49501";
const PRODUCTION_NETNS: &str = "daens";
const PRODUCTION_HOST_IFACE: &str = "dae0";
const PRODUCTION_PEER_IFACE: &str = "dae0peer";
const CLIENT_NETNS: &str = "dae50client";
const LAN_HOST_IFACE: &str = "dae50lan0";
const LAN_CLIENT_IFACE: &str = "dae50cli0";
const ROUTING_MAP_KERNEL_NAME: &str = "routing_map";
const LISTEN_SOCKET_MAP_KERNEL_NAME: &str = "listen_socket_m";
const MATCH_TYPE_FALLBACK: u8 = 10;
const OUTBOUND_STAGE50_PROXY: u8 = 2;
const TCP_PAYLOAD: &[u8] = b"stage50-tcp-ping";
const TCP_RESPONSE: &[u8] = b"stage50-tcp-ack";

pub(crate) fn run_stage50_active_tcp_tproxy_ingress_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage50Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage50_report(&opts);
    output_with_execution_status(
        report,
        opts.execute_smoke,
        "active_tcp_tproxy_ingress_smoke_passed",
    )
}

fn output_with_execution_status(report: Value, executed: bool, pass_key: &str) -> RunnerOutput {
    let passed = report[pass_key].as_bool().unwrap_or(false);
    let blocked = report["blocked"].as_bool().unwrap_or(false);
    let output = format!("{report}\n");
    if executed && (blocked || !passed) {
        RunnerOutput::stdout_error(output.trim_end())
    } else {
        RunnerOutput::ok(output)
    }
}

#[derive(Debug, Clone)]
struct Stage50Options {
    root: PathBuf,
    source_object: PathBuf,
    param_object: PathBuf,
    execute_smoke: bool,
    ack_root_gate: bool,
    peer_section: String,
    host_section: String,
    lan_section: String,
    tproxy_port: u16,
    dae_netns_id: u32,
    target_ip: String,
    client_ip: String,
    target_port: u16,
    so_mark: u32,
    mptcp: bool,
}

impl Default for Stage50Options {
    fn default() -> Self {
        let root = PathBuf::from(DEFAULT_STAGE50_ROOT);
        Self {
            param_object: root.join("bpf_bpfel.param.o"),
            root,
            source_object: PathBuf::from(DEFAULT_STAGE50_SOURCE_OBJECT),
            execute_smoke: false,
            ack_root_gate: false,
            peer_section: DEFAULT_STAGE50_PEER_SECTION.to_owned(),
            host_section: DEFAULT_STAGE50_HOST_SECTION.to_owned(),
            lan_section: DEFAULT_STAGE50_LAN_SECTION.to_owned(),
            tproxy_port: DEFAULT_STAGE50_TPROXY_PORT,
            dae_netns_id: DEFAULT_STAGE50_DAE_NETNS_ID,
            target_ip: DEFAULT_STAGE50_TARGET_IP.to_owned(),
            client_ip: DEFAULT_STAGE50_CLIENT_IP.to_owned(),
            target_port: DEFAULT_STAGE50_TARGET_PORT,
            so_mark: 1234,
            mptcp: true,
        }
    }
}

impl Stage50Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--root" => {
                    opts.root = PathBuf::from(next_value(&mut iter, "stage50 --root")?);
                    if opts.param_object
                        == PathBuf::from(DEFAULT_STAGE50_ROOT).join("bpf_bpfel.param.o")
                    {
                        opts.param_object = opts.root.join("bpf_bpfel.param.o");
                    }
                }
                "--object" => {
                    opts.source_object = PathBuf::from(next_value(&mut iter, "stage50 --object")?);
                }
                "--param-object" => {
                    opts.param_object =
                        PathBuf::from(next_value(&mut iter, "stage50 --param-object")?);
                }
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--peer-section" => {
                    opts.peer_section = next_value(&mut iter, "stage50 --peer-section")?;
                }
                "--host-section" => {
                    opts.host_section = next_value(&mut iter, "stage50 --host-section")?;
                }
                "--lan-section" => {
                    opts.lan_section = next_value(&mut iter, "stage50 --lan-section")?;
                }
                "--tproxy-port" => {
                    opts.tproxy_port =
                        parse_port(&next_value(&mut iter, "stage50 --tproxy-port")?, arg)?;
                }
                "--dae-netns-id" => {
                    opts.dae_netns_id =
                        parse_u32(&next_value(&mut iter, "stage50 --dae-netns-id")?, arg)?;
                }
                "--target-ip" => opts.target_ip = next_value(&mut iter, "stage50 --target-ip")?,
                "--client-ip" => opts.client_ip = next_value(&mut iter, "stage50 --client-ip")?,
                "--target-port" => {
                    opts.target_port =
                        parse_port(&next_value(&mut iter, "stage50 --target-port")?, arg)?;
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage50 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                _ if arg.starts_with("--root=") => {
                    opts.root = PathBuf::from(value_after_equals(arg, "stage50 --root")?);
                    if opts.param_object
                        == PathBuf::from(DEFAULT_STAGE50_ROOT).join("bpf_bpfel.param.o")
                    {
                        opts.param_object = opts.root.join("bpf_bpfel.param.o");
                    }
                }
                _ if arg.starts_with("--object=") => {
                    opts.source_object =
                        PathBuf::from(value_after_equals(arg, "stage50 --object")?);
                }
                _ if arg.starts_with("--param-object=") => {
                    opts.param_object =
                        PathBuf::from(value_after_equals(arg, "stage50 --param-object")?);
                }
                _ if arg.starts_with("--peer-section=") => {
                    opts.peer_section = value_after_equals(arg, "stage50 --peer-section")?;
                }
                _ if arg.starts_with("--host-section=") => {
                    opts.host_section = value_after_equals(arg, "stage50 --host-section")?;
                }
                _ if arg.starts_with("--lan-section=") => {
                    opts.lan_section = value_after_equals(arg, "stage50 --lan-section")?;
                }
                _ if arg.starts_with("--tproxy-port=") => {
                    opts.tproxy_port =
                        parse_port(&value_after_equals(arg, "stage50 --tproxy-port")?, arg)?;
                }
                _ if arg.starts_with("--dae-netns-id=") => {
                    opts.dae_netns_id =
                        parse_u32(&value_after_equals(arg, "stage50 --dae-netns-id")?, arg)?;
                }
                _ if arg.starts_with("--target-ip=") => {
                    opts.target_ip = value_after_equals(arg, "stage50 --target-ip")?;
                }
                _ if arg.starts_with("--client-ip=") => {
                    opts.client_ip = value_after_equals(arg, "stage50 --client-ip")?;
                }
                _ if arg.starts_with("--target-port=") => {
                    opts.target_port =
                        parse_port(&value_after_equals(arg, "stage50 --target-port")?, arg)?;
                }
                _ if arg.starts_with("--so-mark=") => {
                    opts.so_mark = parse_u32(&value_after_equals(arg, "stage50 --so-mark")?, arg)?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage50-active-tcp-tproxy-ingress-admission argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn stage50_report(opts: &Stage50Options) -> Value {
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "isolated-root-under-tmp",
        tmp_root_allowed(&opts.root),
        json!({"path": path_string(&opts.root)}),
        &mut blockers,
        "stage50 root must be an absolute /tmp child path",
    );
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !opts.execute_smoke || opts.ack_root_gate,
        json!({"execute_smoke": opts.execute_smoke, "ack_root_gate": opts.ack_root_gate}),
        &mut blockers,
        "stage50 root-gated smoke requires --ack-root-gate",
    );
    for tool in ["ip", "tc", "python3", "sysctl"] {
        push_check(
            &mut checks,
            &format!("tool-{tool}-available"),
            command_exists(tool),
            json!({"tool": tool}),
            &mut blockers,
            "required host tool is missing",
        );
    }
    push_check(
        &mut checks,
        "source-object-present",
        opts.source_object.exists(),
        json!({"path": path_string(&opts.source_object)}),
        &mut blockers,
        "stage50 source eBPF object is missing",
    );
    push_check(
        &mut checks,
        "tproxy-port-valid",
        opts.tproxy_port != 0,
        json!({"tproxy_port": opts.tproxy_port}),
        &mut blockers,
        "stage50 tproxy port must be non-zero",
    );
    push_check(
        &mut checks,
        "target-port-valid",
        opts.target_port != 0,
        json!({"target_port": opts.target_port}),
        &mut blockers,
        "stage50 target port must be non-zero",
    );
    if opts.execute_smoke {
        push_check(
            &mut checks,
            "stage50-resource-names-free",
            resource_leftovers().is_empty(),
            json!({"leftovers": resource_leftovers()}),
            &mut blockers,
            "stage50 temporary or production names are already in use",
        );
        push_check(
            &mut checks,
            "tproxy-port-free",
            tproxy_port_available(opts.tproxy_port),
            json!({"tproxy_port": opts.tproxy_port}),
            &mut blockers,
            "stage50 tproxy port is already in use",
        );
    }

    let before_pin_snapshot = if opts.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let before_map_ids = if opts.execute_smoke && blockers.is_empty() {
        match map_ids() {
            Ok(ids) => ids,
            Err(err) => {
                blockers.push(format!("stage50 cannot snapshot BPF map ids: {err}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut topology_values = Value::Null;
    let mut param_image = Value::Null;
    let mut peer_attach_show = Value::Null;
    let mut lan_attach_show = Value::Null;
    let mut host_attach_show = Value::Null;
    let mut loaded_map_handoff = Value::Null;
    let mut route_map_update = Value::Null;
    let mut tcp_accept = Value::Null;
    let mut client_traffic = Value::Null;
    let mut post_traffic_peer_stats = Value::Null;
    let mut post_traffic_lan_stats = Value::Null;
    let mut post_traffic_host_stats = Value::Null;
    let mut discovered_listen_map_id = None;
    let mut discovered_routing_map_id = None;
    let mut active_tcp_tproxy_ingress_smoke_passed = false;
    let mut original_destination_observed = false;
    let mut tcp_reply_path_succeeded = false;
    if opts.execute_smoke && blockers.is_empty() {
        let result = execute_stage50_smoke(opts, &before_map_ids);
        executed_steps = result.executed_steps;
        cleanup_steps = result.cleanup_steps;
        topology_values = result.topology_values;
        param_image = result.param_image;
        peer_attach_show = result.peer_attach_show;
        lan_attach_show = result.lan_attach_show;
        host_attach_show = result.host_attach_show;
        loaded_map_handoff = result.loaded_map_handoff;
        route_map_update = result.route_map_update;
        tcp_accept = result.tcp_accept;
        client_traffic = result.client_traffic;
        post_traffic_peer_stats = result.post_traffic_peer_stats;
        post_traffic_lan_stats = result.post_traffic_lan_stats;
        post_traffic_host_stats = result.post_traffic_host_stats;
        discovered_listen_map_id = result.discovered_listen_map_id;
        discovered_routing_map_id = result.discovered_routing_map_id;
        active_tcp_tproxy_ingress_smoke_passed = result.passed;
        original_destination_observed = result.original_destination_observed;
        tcp_reply_path_succeeded = result.tcp_reply_path_succeeded;
        if !active_tcp_tproxy_ingress_smoke_passed {
            blockers.push("stage50 active TCP tproxy ingress smoke failed".to_owned());
        }
    }
    let after_pin_snapshot = if opts.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let (after_map_ids, loaded_maps_cleaned) = if opts.execute_smoke {
        wait_for_loaded_map_cleanup(&[discovered_listen_map_id, discovered_routing_map_id])
    } else {
        (Vec::new(), true)
    };
    if opts.execute_smoke && !loaded_maps_cleaned {
        blockers.push("stage50 loaded BPF maps remain after cleanup".to_owned());
    }
    let leftovers = resource_leftovers();
    if opts.execute_smoke && !leftovers.is_empty() {
        blockers.push("stage50 resources remain after cleanup".to_owned());
    }
    let sys_fs_bpf_dae_mutated = before_pin_snapshot != after_pin_snapshot;
    if opts.execute_smoke && sys_fs_bpf_dae_mutated {
        blockers.push("stage50 unexpectedly mutated /sys/fs/bpf/dae".to_owned());
    }

    let mut report = Map::new();
    report.insert(
        "name".to_owned(),
        json!("stage50-active-tcp-tproxy-ingress-admission"),
    );
    report.insert("stage".to_owned(), json!("stage50"));
    report.insert(
        "evidence_class".to_owned(),
        json!("root-gated-active-tcp-tproxy-ingress-transparent-accept-smoke"),
    );
    report.insert("root".to_owned(), json!(path_string(&opts.root)));
    report.insert("execute_smoke".to_owned(), json!(opts.execute_smoke));
    report.insert(
        "root_gate_acknowledged".to_owned(),
        json!(opts.ack_root_gate),
    );
    report.insert("read_only".to_owned(), json!(!opts.execute_smoke));
    report.insert("blocked".to_owned(), json!(!blockers.is_empty()));
    report.insert(
        "active_tcp_tproxy_ingress_smoke_passed".to_owned(),
        json!(active_tcp_tproxy_ingress_smoke_passed),
    );
    report.insert(
        "active_tcp_tproxy_ingress_admitted".to_owned(),
        json!(active_tcp_tproxy_ingress_smoke_passed),
    );
    report.insert(
        "active_tcp_syn_reached_transparent_listener".to_owned(),
        json!(active_tcp_tproxy_ingress_smoke_passed),
    );
    report.insert(
        "original_destination_observed".to_owned(),
        json!(original_destination_observed),
    );
    report.insert(
        "tcp_reply_path_succeeded".to_owned(),
        json!(tcp_reply_path_succeeded),
    );
    report.insert(
        "active_tproxy_traffic_executed".to_owned(),
        json!(opts.execute_smoke),
    );
    report.insert(
        "active_tcp_tproxy_admitted".to_owned(),
        json!(active_tcp_tproxy_ingress_smoke_passed && original_destination_observed),
    );
    for key in [
        "active_udp_tproxy_admitted",
        "active_dns_tproxy_admitted",
        "route_dial_tcp_rust_control_plane_executed",
        "outbound_true_dataplane_admitted",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "default_switch_allowed",
        "default_path_mutated",
        "product_chain_switch_allowed",
        "true_rust_default_daemon_admitted",
    ] {
        report.insert(key.to_owned(), json!(false));
    }
    report.insert("go_default_path_preserved".to_owned(), json!(true));
    report.insert("go_fallback_required".to_owned(), json!(true));
    report.insert("blockers".to_owned(), json!(blockers));
    report.insert("checks".to_owned(), json!(checks));
    report.insert(
        "active_tcp_contract".to_owned(),
        json!({
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "client_netns": CLIENT_NETNS,
            "lan_host_iface": LAN_HOST_IFACE,
            "lan_client_iface": LAN_CLIENT_IFACE,
            "peer_section": opts.peer_section,
            "host_section": opts.host_section,
            "lan_section": opts.lan_section,
            "filter_pref": STAGE50_FILTER_PREF,
            "lan_filter_pref": STAGE50_LAN_FILTER_PREF,
            "source_object": path_string(&opts.source_object),
            "param_object": path_string(&opts.param_object),
            "listen_socket_map_kernel_name": LISTEN_SOCKET_MAP_KERNEL_NAME,
            "routing_map_kernel_name": ROUTING_MAP_KERNEL_NAME,
            "routing_fallback_outbound": OUTBOUND_STAGE50_PROXY,
            "match_type_fallback": MATCH_TYPE_FALLBACK,
            "tproxy_port": opts.tproxy_port,
            "target": format!("{}:{}", opts.target_ip, opts.target_port),
            "lan_gateway_ip": DEFAULT_STAGE50_LAN_GATEWAY_IP,
            "client_ip": opts.client_ip,
            "so_mark": opts.so_mark,
            "mptcp": opts.mptcp,
            "route_dial_tcp_required_later": true,
        }),
    );
    report.insert("topology_values".to_owned(), topology_values);
    report.insert("param_image".to_owned(), param_image);
    report.insert("loaded_map_handoff".to_owned(), loaded_map_handoff);
    report.insert("route_map_update".to_owned(), route_map_update);
    report.insert("tcp_accept".to_owned(), tcp_accept);
    report.insert("client_traffic".to_owned(), client_traffic);
    report.insert(
        "post_traffic_peer_stats".to_owned(),
        post_traffic_peer_stats,
    );
    report.insert("post_traffic_lan_stats".to_owned(), post_traffic_lan_stats);
    report.insert(
        "post_traffic_host_stats".to_owned(),
        post_traffic_host_stats,
    );
    report.insert("executed_steps".to_owned(), json!(executed_steps));
    report.insert("cleanup_steps".to_owned(), json!(cleanup_steps));
    report.insert("peer_attach_show".to_owned(), peer_attach_show);
    report.insert("lan_attach_show".to_owned(), lan_attach_show);
    report.insert("host_attach_show".to_owned(), host_attach_show);
    report.insert(
        "map_id_snapshots".to_owned(),
        json!({
            "before_attach": before_map_ids,
            "after_cleanup": after_map_ids,
            "discovered_listen_map_id": discovered_listen_map_id,
            "discovered_routing_map_id": discovered_routing_map_id,
            "loaded_maps_cleaned": loaded_maps_cleaned,
        }),
    );
    report.insert(
        "temporary_resources".to_owned(),
        json!({
            "leftovers_after_cleanup": leftovers,
        }),
    );
    report.insert(
        "sys_fs_bpf_dae".to_owned(),
        json!({
            "before": before_pin_snapshot,
            "after": after_pin_snapshot,
            "mutated": sys_fs_bpf_dae_mutated,
        }),
    );
    report.insert("remaining_blockers".to_owned(), json!(remaining_blockers()));
    Value::Object(report)
}

struct Stage50SmokeResult {
    passed: bool,
    original_destination_observed: bool,
    tcp_reply_path_succeeded: bool,
    discovered_listen_map_id: Option<u32>,
    discovered_routing_map_id: Option<u32>,
    executed_steps: Vec<Value>,
    cleanup_steps: Vec<Value>,
    topology_values: Value,
    param_image: Value,
    peer_attach_show: Value,
    lan_attach_show: Value,
    host_attach_show: Value,
    loaded_map_handoff: Value,
    route_map_update: Value,
    tcp_accept: Value,
    client_traffic: Value,
    post_traffic_peer_stats: Value,
    post_traffic_lan_stats: Value,
    post_traffic_host_stats: Value,
}

fn execute_stage50_smoke(opts: &Stage50Options, before_map_ids: &[u32]) -> Stage50SmokeResult {
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut ok = true;

    ok &= setup_production_topology(&mut executed_steps, opts);
    ok &= setup_client_topology(&mut executed_steps, opts);
    let (topology_values, dae0_ifindex, dae0_mac, dae0peer_mac) =
        read_topology_values(&mut executed_steps, opts);
    ok &= topology_values["status"].as_str() == Some("pass");
    if let Some(dae0_mac) = dae0_mac {
        ok &= setup_production_ipv4_datapath(&mut executed_steps, dae0_mac);
    }
    let param_image = if let (Some(dae0_ifindex), Some(dae0peer_mac)) = (dae0_ifindex, dae0peer_mac)
    {
        write_param_image(opts, dae0_ifindex, dae0peer_mac)
    } else {
        json!({
            "status": "skipped",
            "path": path_string(&opts.param_object),
            "reason": "topology runtime PARAM values were not available",
        })
    };
    ok &= param_image["status"].as_str() == Some("pass")
        && param_image["rewritten_param_matches"]
            .as_bool()
            .unwrap_or(false);

    if ok {
        ok &= attach_peer_program(&mut executed_steps, opts);
    }
    let peer_attach_show = show_peer_program(&mut executed_steps);

    let live_handoff = if ok {
        match open_live_loaded_tproxy_listen_socket_map_in_netns(
            before_map_ids,
            opts.tproxy_port,
            PRODUCTION_NETNS,
        ) {
            Ok(handoff) => Some(handoff),
            Err(err) => {
                ok = false;
                executed_steps.push(json!({
                    "name": "open-live-loaded-tproxy-listen-socket-map",
                    "status": "fail",
                    "error": err.to_string(),
                }));
                None
            }
        }
    } else {
        None
    };
    let (loaded_map_handoff, discovered_listen_map_id) = match live_handoff.as_ref() {
        Some(handoff) => (live_handoff_json(handoff), Some(handoff.map.id)),
        None => (
            json!({
                "status": "skipped",
                "reason": "peer PARAM-aware attach did not pass",
            }),
            None,
        ),
    };

    let before_lan_map_ids = map_ids().unwrap_or_default();
    if ok {
        ok &= attach_lan_program(&mut executed_steps, opts);
    }
    let lan_attach_show = show_lan_program(&mut executed_steps);
    let (route_map_update, discovered_routing_map_id) = if ok {
        match update_stage50_routing_map(&before_lan_map_ids, opts.so_mark) {
            Ok((value, id)) => (value, Some(id)),
            Err(err) => {
                ok = false;
                (json!({"status": "fail", "error": err}), None)
            }
        }
    } else {
        (
            json!({
                "status": "skipped",
                "reason": "LAN PARAM-aware attach did not pass",
            }),
            None,
        )
    };

    if ok {
        ok &= attach_host_program(&mut executed_steps, opts);
    }
    let host_attach_show = show_host_program(&mut executed_steps);

    let (tcp_accept, client_traffic, original_destination_observed, tcp_reply_path_succeeded) =
        if ok {
            let listener = live_handoff
                .as_ref()
                .and_then(|handoff| handoff.listeners.tcp_listener.try_clone().ok());
            match listener {
                Some(listener) => run_active_tcp_probe(listener, opts),
                None => (
                    json!({"status": "fail", "error": "failed to clone tproxy TCP listener"}),
                    Value::Null,
                    false,
                    false,
                ),
            }
        } else {
            (
                json!({
                    "status": "skipped",
                    "reason": "BPF attach or routing map update did not pass",
                }),
                Value::Null,
                false,
                false,
            )
        };
    let post_traffic_peer_stats = show_peer_program_stats(&mut executed_steps);
    let post_traffic_lan_stats = show_lan_program_stats(&mut executed_steps);
    let post_traffic_host_stats = show_host_program_stats(&mut executed_steps);
    ok &= tcp_accept["status"].as_str() == Some("pass")
        && client_traffic["status"].as_str() == Some("pass")
        && original_destination_observed;

    cleanup_stage50(&mut cleanup_steps);

    let peer_output = peer_attach_show["stdout"].as_str().unwrap_or_default();
    let lan_output = lan_attach_show["stdout"].as_str().unwrap_or_default();
    let host_output = host_attach_show["stdout"].as_str().unwrap_or_default();
    Stage50SmokeResult {
        passed: ok
            && peer_attach_show["status"].as_str() == Some("pass")
            && peer_output.contains(&opts.peer_section)
            && peer_output.contains("tproxy_dae0peer")
            && lan_attach_show["status"].as_str() == Some("pass")
            && lan_output.contains(&opts.lan_section)
            && lan_output.contains("tproxy_lan_ingr")
            && host_attach_show["status"].as_str() == Some("pass")
            && host_output.contains(&opts.host_section)
            && host_output.contains("tproxy_dae0_ing")
            && resource_leftovers().is_empty(),
        original_destination_observed,
        tcp_reply_path_succeeded,
        discovered_listen_map_id,
        discovered_routing_map_id,
        executed_steps,
        cleanup_steps,
        topology_values,
        param_image,
        peer_attach_show,
        lan_attach_show,
        host_attach_show,
        loaded_map_handoff,
        route_map_update,
        tcp_accept,
        client_traffic,
        post_traffic_peer_stats,
        post_traffic_lan_stats,
        post_traffic_host_stats,
    }
}

fn setup_production_topology(steps: &mut Vec<Value>, opts: &Stage50Options) -> bool {
    let mut ok = true;
    ok &= run_step(
        steps,
        "create-production-veth-pair",
        CommandSpec::new(
            "ip",
            &[
                "link",
                "add",
                PRODUCTION_HOST_IFACE,
                "type",
                "veth",
                "peer",
                "name",
                PRODUCTION_PEER_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "create-production-netns",
        CommandSpec::new("ip", &["netns", "add", PRODUCTION_NETNS]),
    );
    ok &= run_step(
        steps,
        "assign-production-netns-id",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "set",
                PRODUCTION_NETNS,
                &opts.dae_netns_id.to_string(),
            ],
        ),
    );
    ok &= run_step(
        steps,
        "move-production-peer-into-netns",
        CommandSpec::new(
            "ip",
            &[
                "link",
                "set",
                PRODUCTION_PEER_IFACE,
                "netns",
                PRODUCTION_NETNS,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "bring-production-host-link-up",
        CommandSpec::new("ip", &["link", "set", PRODUCTION_HOST_IFACE, "up"]),
    );
    ok &= run_step(
        steps,
        "bring-production-netns-loopback-up",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "link",
                "set",
                "lo",
                "up",
            ],
        ),
    );
    ok &= run_step(
        steps,
        "bring-production-peer-link-up",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "link",
                "set",
                PRODUCTION_PEER_IFACE,
                "up",
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-daens-fwmark-rule",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "rule",
                "add",
                "fwmark",
                "0x8000000/0x8000000",
                "table",
                "2023",
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-daens-local-route",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "route",
                "add",
                "local",
                "default",
                "dev",
                "lo",
                "table",
                "2023",
            ],
        ),
    );
    ok
}

fn setup_client_topology(steps: &mut Vec<Value>, opts: &Stage50Options) -> bool {
    let mut ok = true;
    ok &= run_step(
        steps,
        "create-client-netns",
        CommandSpec::new("ip", &["netns", "add", CLIENT_NETNS]),
    );
    ok &= run_step(
        steps,
        "create-lan-veth-pair",
        CommandSpec::new(
            "ip",
            &[
                "link",
                "add",
                LAN_HOST_IFACE,
                "type",
                "veth",
                "peer",
                "name",
                LAN_CLIENT_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "move-lan-client-into-netns",
        CommandSpec::new(
            "ip",
            &["link", "set", LAN_CLIENT_IFACE, "netns", CLIENT_NETNS],
        ),
    );
    ok &= run_step(
        steps,
        "assign-lan-host-ip",
        CommandSpec::new(
            "ip",
            &[
                "addr",
                "add",
                &format!("{DEFAULT_STAGE50_LAN_GATEWAY_IP}/24"),
                "dev",
                LAN_HOST_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "bring-lan-host-link-up",
        CommandSpec::new("ip", &["link", "set", LAN_HOST_IFACE, "up"]),
    );
    ok &= run_step(
        steps,
        "disable-lan-host-send-redirects",
        CommandSpec::new(
            "sysctl",
            &[
                "-w",
                &format!("net.ipv4.conf.{LAN_HOST_IFACE}.send_redirects=0"),
            ],
        ),
    );
    ok &= run_step(
        steps,
        "disable-lan-host-rp-filter",
        CommandSpec::new(
            "sysctl",
            &["-w", &format!("net.ipv4.conf.{LAN_HOST_IFACE}.rp_filter=0")],
        ),
    );
    ok &= run_step(
        steps,
        "bring-client-loopback-up",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                CLIENT_NETNS,
                "ip",
                "link",
                "set",
                "lo",
                "up",
            ],
        ),
    );
    ok &= run_step(
        steps,
        "assign-lan-client-ip",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                CLIENT_NETNS,
                "ip",
                "addr",
                "add",
                &format!("{}/24", opts.client_ip),
                "dev",
                LAN_CLIENT_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "bring-lan-client-link-up",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                CLIENT_NETNS,
                "ip",
                "link",
                "set",
                LAN_CLIENT_IFACE,
                "up",
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-client-default-route-via-lan-gateway",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                CLIENT_NETNS,
                "ip",
                "route",
                "add",
                "default",
                "via",
                DEFAULT_STAGE50_LAN_GATEWAY_IP,
                "dev",
                LAN_CLIENT_IFACE,
            ],
        ),
    );
    ok
}

fn read_topology_values(
    steps: &mut Vec<Value>,
    opts: &Stage50Options,
) -> (Value, Option<u32>, Option<[u8; 6]>, Option<[u8; 6]>) {
    let dae0_ifindex_step = run_observation_step(
        steps,
        "read-production-dae0-ifindex",
        CommandSpec::new(
            "cat",
            &[&format!("/sys/class/net/{PRODUCTION_HOST_IFACE}/ifindex")],
        ),
    );
    let dae0_mac_step = run_observation_step(
        steps,
        "read-production-dae0-mac",
        CommandSpec::new(
            "cat",
            &[&format!("/sys/class/net/{PRODUCTION_HOST_IFACE}/address")],
        ),
    );
    let dae0peer_mac_step = run_observation_step(
        steps,
        "read-production-dae0peer-mac",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "cat",
                &format!("/sys/class/net/{PRODUCTION_PEER_IFACE}/address"),
            ],
        ),
    );
    let dae0_ifindex = parse_step_u32(&dae0_ifindex_step).ok();
    let dae0_mac = parse_step_mac(&dae0_mac_step).ok();
    let dae0peer_mac = parse_step_mac(&dae0peer_mac_step).ok();
    let value = match (dae0_ifindex, dae0_mac, dae0peer_mac) {
        (Some(dae0_ifindex), Some(dae0_mac), Some(dae0peer_mac)) => json!({
            "status": "pass",
            "dae0_ifindex": dae0_ifindex,
            "dae_netns_id": opts.dae_netns_id,
            "dae0_mac": mac_string(dae0_mac),
            "dae0peer_mac": mac_string(dae0peer_mac),
            "control_plane_pid": std::process::id(),
        }),
        _ => json!({
            "status": "fail",
            "dae0_ifindex_step": dae0_ifindex_step,
            "dae0_mac_step": dae0_mac_step,
            "dae0peer_mac_step": dae0peer_mac_step,
        }),
    };
    (value, dae0_ifindex, dae0_mac, dae0peer_mac)
}

fn setup_production_ipv4_datapath(steps: &mut Vec<Value>, dae0_mac: [u8; 6]) -> bool {
    let host_mac = mac_string(dae0_mac);
    let mut ok = true;
    ok &= run_step(
        steps,
        "set-daens-dae0peer-accept-local",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "sysctl",
                "-w",
                &format!("net.ipv4.conf.{PRODUCTION_PEER_IFACE}.accept_local=1"),
            ],
        ),
    );
    ok &= run_step(
        steps,
        "disable-production-dae0-send-redirects",
        CommandSpec::new(
            "sysctl",
            &[
                "-w",
                &format!("net.ipv4.conf.{PRODUCTION_HOST_IFACE}.send_redirects=0"),
            ],
        ),
    );
    ok &= run_step(
        steps,
        "disable-production-dae0-rp-filter",
        CommandSpec::new(
            "sysctl",
            &[
                "-w",
                &format!("net.ipv4.conf.{PRODUCTION_HOST_IFACE}.rp_filter=0"),
            ],
        ),
    );
    ok &= run_step(
        steps,
        "assign-daens-dae0peer-link-ip",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "addr",
                "add",
                "169.254.0.11/32",
                "dev",
                PRODUCTION_PEER_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-daens-dae0peer-link-route",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "route",
                "add",
                "169.254.0.1",
                "dev",
                PRODUCTION_PEER_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-daens-dae0peer-default-route",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "route",
                "add",
                "default",
                "via",
                "169.254.0.1",
                "dev",
                PRODUCTION_PEER_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-daens-dae0peer-host-neighbor",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "neigh",
                "replace",
                "169.254.0.1",
                "dev",
                PRODUCTION_PEER_IFACE,
                "lladdr",
                &host_mac,
                "nud",
                "permanent",
            ],
        ),
    );
    ok
}

fn write_param_image(opts: &Stage50Options, dae0_ifindex: u32, dae0peer_mac: [u8; 6]) -> Value {
    let param = build_dae_param(DaeParamInput {
        tproxy_port: opts.tproxy_port,
        control_plane_pid: std::process::id(),
        dae0_ifindex,
        dae_netns_id: opts.dae_netns_id,
        dae0peer_mac,
        has_bpf_get_current_task: true,
    });
    match write_param_aware_object(&opts.source_object, &opts.param_object, param) {
        Ok(report) => json!({
            "status": "pass",
            "path": path_string(&opts.param_object),
            "rewritten_param_matches": report.rewritten_param_matches,
            "previous_param_was_zero": report.previous_param_was_zero,
            "source_len": report.source_len,
            "output_len": report.output_len,
            "param": {
                "tproxy_port": param.tproxy_port,
                "control_plane_pid": param.control_plane_pid,
                "dae0_ifindex": param.dae0_ifindex,
                "dae_netns_id": param.dae_netns_id,
                "dae0peer_mac": mac_string(param.dae0peer_mac),
                "has_bpf_get_current_task": param.has_bpf_get_current_task,
            },
            "location": {
                "symbol": report.location.symbol,
                "section": report.location.section,
                "symbol_size": report.location.symbol_size,
                "file_offset": report.location.file_offset,
            },
        }),
        Err(err) => json!({
            "status": "fail",
            "path": path_string(&opts.param_object),
            "error": err.to_string(),
        }),
    }
}

fn attach_peer_program(steps: &mut Vec<Value>, opts: &Stage50Options) -> bool {
    let param_object = path_string(&opts.param_object);
    let mut ok = true;
    ok &= run_step(
        steps,
        "attach-production-peer-clsact-qdisc",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "qdisc",
                "add",
                "dev",
                PRODUCTION_PEER_IFACE,
                "clsact",
            ],
        ),
    );
    ok &= run_step(
        steps,
        "attach-production-dae0peer-param-aware-ebpf-program",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "filter",
                "add",
                "dev",
                PRODUCTION_PEER_IFACE,
                "ingress",
                "pref",
                STAGE50_FILTER_PREF,
                "bpf",
                "da",
                "obj",
                &param_object,
                "sec",
                &opts.peer_section,
            ],
        ),
    );
    ok
}

fn attach_lan_program(steps: &mut Vec<Value>, opts: &Stage50Options) -> bool {
    let param_object = path_string(&opts.param_object);
    let mut ok = true;
    ok &= run_step(
        steps,
        "attach-lan-host-clsact-qdisc",
        CommandSpec::new("tc", &["qdisc", "add", "dev", LAN_HOST_IFACE, "clsact"]),
    );
    ok &= run_step(
        steps,
        "attach-lan-ingress-param-aware-ebpf-program",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "add",
                "dev",
                LAN_HOST_IFACE,
                "ingress",
                "pref",
                STAGE50_LAN_FILTER_PREF,
                "bpf",
                "da",
                "obj",
                &param_object,
                "sec",
                &opts.lan_section,
            ],
        ),
    );
    ok
}

fn attach_host_program(steps: &mut Vec<Value>, opts: &Stage50Options) -> bool {
    let param_object = path_string(&opts.param_object);
    let mut ok = true;
    ok &= run_step(
        steps,
        "attach-production-host-clsact-qdisc",
        CommandSpec::new(
            "tc",
            &["qdisc", "add", "dev", PRODUCTION_HOST_IFACE, "clsact"],
        ),
    );
    ok &= run_step(
        steps,
        "attach-production-dae0-param-aware-ebpf-program",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "add",
                "dev",
                PRODUCTION_HOST_IFACE,
                "ingress",
                "pref",
                STAGE50_FILTER_PREF,
                "bpf",
                "da",
                "obj",
                &param_object,
                "sec",
                &opts.host_section,
            ],
        ),
    );
    ok
}

fn show_peer_program(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-production-dae0peer-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "filter",
                "show",
                "dev",
                PRODUCTION_PEER_IFACE,
                "ingress",
            ],
        ),
    )
}

fn show_lan_program(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-lan-ingress-param-aware-ebpf-program-filter",
        CommandSpec::new("tc", &["filter", "show", "dev", LAN_HOST_IFACE, "ingress"]),
    )
}

fn show_host_program(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-production-dae0-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &["filter", "show", "dev", PRODUCTION_HOST_IFACE, "ingress"],
        ),
    )
}

fn show_peer_program_stats(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-production-dae0peer-param-aware-ebpf-program-filter-stats",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "-s",
                "filter",
                "show",
                "dev",
                PRODUCTION_PEER_IFACE,
                "ingress",
            ],
        ),
    )
}

fn show_lan_program_stats(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-lan-ingress-param-aware-ebpf-program-filter-stats",
        CommandSpec::new(
            "tc",
            &["-s", "filter", "show", "dev", LAN_HOST_IFACE, "ingress"],
        ),
    )
}

fn show_host_program_stats(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-production-dae0-param-aware-ebpf-program-filter-stats",
        CommandSpec::new(
            "tc",
            &[
                "-s",
                "filter",
                "show",
                "dev",
                PRODUCTION_HOST_IFACE,
                "ingress",
            ],
        ),
    )
}

fn live_handoff_json(handoff: &dae_ebpf_support::LiveLoadedTproxyListenSocketMap) -> Value {
    json!({
        "status": "pass",
        "map": map_json(&handoff.map),
        "new_map_ids": handoff.new_map_ids,
        "keys_updated": handoff.keys_updated,
        "tcp_listener_fd_observed": handoff.tcp_listener_fd >= 0,
        "udp_socket_fd_observed": handoff.udp_socket_fd >= 0,
        "tcp_options": {
            "ip_transparent": handoff.tcp_options.ip_transparent,
            "so_reuseaddr": handoff.tcp_options.so_reuseaddr,
            "ip_recvorigdstaddr": handoff.tcp_options.ip_recvorigdstaddr,
            "ipv6_recvorigdstaddr": handoff.tcp_options.ipv6_recvorigdstaddr,
            "original_dst_capture_ready": handoff.tcp_options.original_dst_capture_ready,
        },
        "udp_options": {
            "ip_transparent": handoff.udp_options.ip_transparent,
            "so_reuseaddr": handoff.udp_options.so_reuseaddr,
            "ip_recvorigdstaddr": handoff.udp_options.ip_recvorigdstaddr,
            "ipv6_recvorigdstaddr": handoff.udp_options.ipv6_recvorigdstaddr,
            "original_dst_capture_ready": handoff.udp_options.original_dst_capture_ready,
        },
    })
}

fn update_stage50_routing_map(
    before_map_ids: &[u32],
    so_mark: u32,
) -> Result<(Value, u32), String> {
    let (fd, info, new_map_ids) =
        open_unique_new_map(before_map_ids, ROUTING_MAP_KERNEL_NAME, 4, 24)
            .map_err(|err| err.to_string())?;
    let key = 0_u32.to_ne_bytes();
    let value = fallback_match_set_value(OUTBOUND_STAGE50_PROXY, so_mark);
    update_map_elem_bytes(fd.as_raw_fd(), &key, &value).map_err(|err| err.to_string())?;
    Ok((
        json!({
            "status": "pass",
            "map": map_json(&info),
            "new_map_ids": new_map_ids,
            "key": 0,
            "match_type": "Fallback",
            "match_type_value": MATCH_TYPE_FALLBACK,
            "outbound": OUTBOUND_STAGE50_PROXY,
            "mark": so_mark,
            "must": false,
        }),
        info.id,
    ))
}

fn fallback_match_set_value(outbound: u8, mark: u32) -> [u8; 24] {
    let mut value = [0_u8; 24];
    value[17] = MATCH_TYPE_FALLBACK;
    value[18] = outbound;
    value[20..24].copy_from_slice(&mark.to_ne_bytes());
    value
}

fn open_unique_new_map(
    before_map_ids: &[u32],
    name: &str,
    key_size: u32,
    value_size: u32,
) -> std::io::Result<(OwnedFd, RuntimeMapInfo, Vec<u32>)> {
    let current = map_ids()?;
    let new_map_ids = current
        .iter()
        .copied()
        .filter(|id| !before_map_ids.contains(id))
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    for id in &new_map_ids {
        let fd = open_map_fd(*id)?;
        let info = map_info(fd.as_raw_fd())?;
        if info.name == name && info.key_size == key_size && info.value_size == value_size {
            candidates.push((fd, info));
        }
    }
    if candidates.len() != 1 {
        return Err(std::io::Error::other(format!(
            "expected exactly one new map {name}, found {}",
            candidates.len()
        )));
    }
    let (fd, info) = candidates.remove(0);
    Ok((fd, info, new_map_ids))
}

fn run_active_tcp_probe(
    listener: TcpListener,
    opts: &Stage50Options,
) -> (Value, Value, bool, bool) {
    let target = format!("{}:{}", opts.target_ip, opts.target_port);
    let accept_handle = thread::spawn(move || tcp_accept_probe(listener));
    thread::sleep(Duration::from_millis(100));
    let client = run_client_probe(&target);
    let accept = accept_handle
        .join()
        .unwrap_or_else(|_| json!({"status": "fail", "error": "accept thread panicked"}));
    let original_destination_observed = accept["local_addr"].as_str() == Some(target.as_str());
    let tcp_reply_path_succeeded = client["stdout"]
        .as_str()
        .is_some_and(|stdout| stdout.contains("stage50-tcp-ack"));
    (
        accept,
        client,
        original_destination_observed,
        tcp_reply_path_succeeded,
    )
}

fn tcp_accept_probe(listener: TcpListener) -> Value {
    if let Err(err) = listener.set_nonblocking(true) {
        return json!({"status": "fail", "error": err.to_string()});
    }
    let deadline = Instant::now() + Duration::from_secs(4);
    let (mut stream, peer) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return json!({"status": "fail", "error": err.to_string()}),
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let local_addr = stream.local_addr().map(|addr| addr.to_string()).ok();
    let mut buf = vec![0_u8; TCP_PAYLOAD.len()];
    let read_status = stream.read_exact(&mut buf);
    let write_status = if read_status.is_ok() {
        stream.write_all(TCP_RESPONSE)
    } else {
        Ok(())
    };
    let passed = read_status.is_ok() && write_status.is_ok() && buf == TCP_PAYLOAD;
    json!({
        "status": if passed { "pass" } else { "fail" },
        "peer_addr": peer.to_string(),
        "local_addr": local_addr,
        "payload_matched": buf == TCP_PAYLOAD,
        "read_error": read_status.err().map(|err| err.to_string()),
        "write_error": write_status.err().map(|err| err.to_string()),
    })
}

fn run_client_probe(target: &str) -> Value {
    let script = format!(
        "import socket,sys\ns=socket.create_connection(({target_ip:?},{target_port}),3)\ns.settimeout(3)\ns.sendall(b\"stage50-tcp-ping\")\ndata=s.recv(64)\nprint(data.decode('ascii','replace'))\ns.close()\nsys.exit(0 if data == b\"stage50-tcp-ack\" else 2)\n",
        target_ip = target
            .split(':')
            .next()
            .unwrap_or(DEFAULT_STAGE50_TARGET_IP),
        target_port = target
            .split(':')
            .nth(1)
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(DEFAULT_STAGE50_TARGET_PORT),
    );
    run_observation_command(CommandSpec::new(
        "ip",
        &["netns", "exec", CLIENT_NETNS, "python3", "-c", &script],
    ))
}

fn cleanup_stage50(cleanup_steps: &mut Vec<Value>) {
    run_cleanup_step(
        cleanup_steps,
        "delete-production-dae0-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                PRODUCTION_HOST_IFACE,
                "ingress",
                "pref",
                STAGE50_FILTER_PREF,
            ],
        ),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-production-host-clsact-qdisc",
        CommandSpec::new(
            "tc",
            &["qdisc", "del", "dev", PRODUCTION_HOST_IFACE, "clsact"],
        ),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-lan-ingress-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                LAN_HOST_IFACE,
                "ingress",
                "pref",
                STAGE50_LAN_FILTER_PREF,
            ],
        ),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-lan-host-clsact-qdisc",
        CommandSpec::new("tc", &["qdisc", "del", "dev", LAN_HOST_IFACE, "clsact"]),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-production-dae0peer-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "filter",
                "del",
                "dev",
                PRODUCTION_PEER_IFACE,
                "ingress",
                "pref",
                STAGE50_FILTER_PREF,
            ],
        ),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-production-peer-clsact-qdisc",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "qdisc",
                "del",
                "dev",
                PRODUCTION_PEER_IFACE,
                "clsact",
            ],
        ),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-lan-host-link",
        CommandSpec::new("ip", &["link", "del", LAN_HOST_IFACE]),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-production-host-link",
        CommandSpec::new("ip", &["link", "del", PRODUCTION_HOST_IFACE]),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-client-netns",
        CommandSpec::new("ip", &["netns", "del", CLIENT_NETNS]),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-production-netns",
        CommandSpec::new("ip", &["netns", "del", PRODUCTION_NETNS]),
    );
}

fn remaining_blockers() -> Vec<&'static str> {
    vec![
        "RouteDialTcp Rust control-plane path is not executed",
        "SO_MARK and MPTCP are not proven on a real outbound socket in this stage",
        "active UDP tproxy traffic evidence is still missing",
        "active DNS UDP/53 and reload DNS cache migration evidence is still missing",
        "outbound true dataplane admission is still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing",
    ]
}

fn wait_for_loaded_map_cleanup(discovered_map_ids: &[Option<u32>]) -> (Vec<u32>, bool) {
    let ids = discovered_map_ids
        .iter()
        .filter_map(|id| *id)
        .collect::<Vec<_>>();
    let mut current = map_ids().unwrap_or_default();
    if ids.iter().all(|id| !current.contains(id)) {
        return (current, true);
    }
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(50));
        current = map_ids().unwrap_or_default();
        if ids.iter().all(|id| !current.contains(id)) {
            return (current, true);
        }
    }
    (current, false)
}

fn push_check(
    checks: &mut Vec<Value>,
    name: &str,
    passed: bool,
    detail: Value,
    blockers: &mut Vec<String>,
    blocker: &str,
) {
    if !passed {
        blockers.push(blocker.to_owned());
    }
    checks.push(json!({
        "name": name,
        "status": if passed { "pass" } else { "fail" },
        "detail": detail,
        "blocker": if passed { Value::Null } else { Value::String(blocker.to_owned()) },
    }));
}

fn tmp_root_allowed(path: &Path) -> bool {
    path.is_absolute()
        && path
            .parent()
            .map(|parent| parent == Path::new("/tmp"))
            .unwrap_or(false)
}

fn command_exists(command: &str) -> bool {
    env::var_os("PATH").is_some_and(|paths| {
        env::split_paths(&paths).any(|dir| {
            let candidate = dir.join(command);
            candidate.is_file()
        })
    })
}

fn iface_exists(iface: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", "dev", iface])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn netns_exists(name: &str) -> bool {
    ["/var/run/netns", "/run/netns"]
        .into_iter()
        .any(|parent| PathBuf::from(parent).join(name).exists())
}

fn resource_leftovers() -> Vec<String> {
    let mut leftovers = Vec::new();
    for iface in [
        PRODUCTION_HOST_IFACE,
        PRODUCTION_PEER_IFACE,
        LAN_HOST_IFACE,
        LAN_CLIENT_IFACE,
    ] {
        if iface_exists(iface) {
            leftovers.push(format!("iface:{iface}"));
        }
    }
    for netns in [PRODUCTION_NETNS, CLIENT_NETNS] {
        if netns_exists(netns) {
            leftovers.push(format!("netns:{netns}"));
        }
    }
    leftovers
}

fn bpf_dae_snapshot() -> Vec<String> {
    let path = Path::new("/sys/fs/bpf/dae");
    let Ok(entries) = fs::read_dir(path) else {
        return Vec::new();
    };
    let mut names = entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn tproxy_port_available(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok() && UdpSocket::bind(("127.0.0.1", port)).is_ok()
}

fn map_json(info: &RuntimeMapInfo) -> Value {
    json!({
        "id": info.id,
        "name": info.name,
        "map_type": info.map_type,
        "key_size": info.key_size,
        "value_size": info.value_size,
        "max_entries": info.max_entries,
        "flags": info.flags,
    })
}

struct CommandSpec<'a> {
    program: &'a str,
    args: Vec<&'a str>,
}

impl<'a> CommandSpec<'a> {
    fn new(program: &'a str, args: &[&'a str]) -> Self {
        Self {
            program,
            args: args.to_vec(),
        }
    }
}

fn run_step(steps: &mut Vec<Value>, name: &str, spec: CommandSpec<'_>) -> bool {
    let value = run_observation_command(spec);
    let status = value["status"].as_str() == Some("pass");
    let mut with_name = value;
    with_name["name"] = json!(name);
    steps.push(with_name);
    status
}

fn run_cleanup_step(steps: &mut Vec<Value>, name: &str, spec: CommandSpec<'_>) {
    let mut value = run_observation_command(spec);
    value["name"] = json!(name);
    steps.push(value);
}

fn run_observation_step(steps: &mut Vec<Value>, name: &str, spec: CommandSpec<'_>) -> Value {
    let mut value = run_observation_command(spec);
    value["name"] = json!(name);
    steps.push(value.clone());
    value
}

fn run_observation_command(spec: CommandSpec<'_>) -> Value {
    let output = Command::new(spec.program).args(&spec.args).output();
    let (status, code, stdout, stderr) = command_output(output);
    json!({
        "name": Value::Null,
        "status": status,
        "program": spec.program,
        "args": spec.args,
        "exit_code": code,
        "stdout": stdout,
        "stderr": stderr,
    })
}

fn command_output(
    output: std::io::Result<std::process::Output>,
) -> (&'static str, Option<i32>, String, String) {
    match output {
        Ok(output) => (
            if output.status.success() {
                "pass"
            } else {
                "fail"
            },
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).trim().to_owned(),
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ),
        Err(err) => ("fail", None, String::new(), err.to_string()),
    }
}

fn parse_step_u32(step: &Value) -> Result<u32, String> {
    if step["status"].as_str() != Some("pass") {
        return Err(step["stderr"]
            .as_str()
            .unwrap_or("command failed")
            .to_owned());
    }
    step["stdout"]
        .as_str()
        .unwrap_or_default()
        .trim()
        .parse::<u32>()
        .map_err(|err| err.to_string())
        .and_then(|value| {
            if value == 0 {
                Err("value must be non-zero".to_owned())
            } else {
                Ok(value)
            }
        })
}

fn parse_step_mac(step: &Value) -> Result<[u8; 6], String> {
    if step["status"].as_str() != Some("pass") {
        return Err(step["stderr"]
            .as_str()
            .unwrap_or("command failed")
            .to_owned());
    }
    parse_mac(step["stdout"].as_str().unwrap_or_default())
}

fn parse_mac(value: &str) -> Result<[u8; 6], String> {
    let parts = value.trim().split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        return Err("expected six colon-separated hex octets".to_owned());
    }
    let mut mac = [0_u8; 6];
    for (index, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return Err("each octet must have two hex digits".to_owned());
        }
        mac[index] = u8::from_str_radix(part, 16).map_err(|err| err.to_string())?;
    }
    if mac == [0; 6] {
        return Err("mac must be non-zero".to_owned());
    }
    Ok(mac)
}

fn mac_string(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn parse_port(value: &str, flag: &str) -> Result<u16, RunnerOutput> {
    value
        .parse::<u16>()
        .map_err(|err| RunnerOutput::usage(format!("invalid {flag}: {err}")))
        .and_then(|port| {
            if port == 0 {
                Err(RunnerOutput::usage(format!(
                    "invalid {flag}: must be non-zero"
                )))
            } else {
                Ok(port)
            }
        })
}

fn parse_u32(value: &str, flag: &str) -> Result<u32, RunnerOutput> {
    value
        .parse::<u32>()
        .map_err(|err| RunnerOutput::usage(format!("invalid {flag}: {err}")))
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    usage: &str,
) -> Result<String, RunnerOutput> {
    iter.next()
        .cloned()
        .ok_or_else(|| RunnerOutput::usage(format!("missing value for {usage}")))
}

fn value_after_equals(arg: &str, usage: &str) -> Result<String, RunnerOutput> {
    arg.split_once('=')
        .map(|(_, value)| value.to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RunnerOutput::usage(format!("missing value for {usage}")))
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
