use std::env;
use std::fs;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use dae_ebpf_support::{
    DaeParamInput, build_dae_param, map_ids, run_loaded_tproxy_listen_socket_map_fd_smoke,
    write_param_aware_object,
};
use serde_json::{Map, Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_STAGE49_ROOT: &str = "/tmp/dae-stage49-candidate";
const DEFAULT_STAGE49_SOURCE_OBJECT: &str = "control/bpf_bpfel.o";
const DEFAULT_STAGE49_PEER_SECTION: &str = "tc/dae0peer_ingress";
const DEFAULT_STAGE49_HOST_SECTION: &str = "tc/dae0_ingress";
const DEFAULT_STAGE49_TPROXY_PORT: u16 = 12345;
const DEFAULT_STAGE49_DAE_NETNS_ID: u32 = 49;
const STAGE49_FILTER_PREF: &str = "49490";
const PRODUCTION_NETNS: &str = "daens";
const PRODUCTION_HOST_IFACE: &str = "dae0";
const PRODUCTION_PEER_IFACE: &str = "dae0peer";
const LISTEN_SOCKET_MAP_KERNEL_NAME: &str = "listen_socket_m";

pub(crate) fn run_stage49_production_param_listener_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage49Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage49_report(&opts);
    output_with_execution_status(
        report,
        opts.execute_smoke,
        "combined_production_param_listener_smoke_passed",
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
struct Stage49Options {
    root: PathBuf,
    source_object: PathBuf,
    param_object: PathBuf,
    execute_smoke: bool,
    ack_root_gate: bool,
    peer_section: String,
    host_section: String,
    tproxy_port: u16,
    dae_netns_id: u32,
    has_bpf_get_current_task: bool,
}

impl Default for Stage49Options {
    fn default() -> Self {
        let root = PathBuf::from(DEFAULT_STAGE49_ROOT);
        Self {
            param_object: root.join("bpf_bpfel.param.o"),
            root,
            source_object: PathBuf::from(DEFAULT_STAGE49_SOURCE_OBJECT),
            execute_smoke: false,
            ack_root_gate: false,
            peer_section: DEFAULT_STAGE49_PEER_SECTION.to_owned(),
            host_section: DEFAULT_STAGE49_HOST_SECTION.to_owned(),
            tproxy_port: DEFAULT_STAGE49_TPROXY_PORT,
            dae_netns_id: DEFAULT_STAGE49_DAE_NETNS_ID,
            has_bpf_get_current_task: true,
        }
    }
}

impl Stage49Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--root" => {
                    opts.root = PathBuf::from(next_value(&mut iter, "stage49 --root")?);
                    if opts.param_object
                        == PathBuf::from(DEFAULT_STAGE49_ROOT).join("bpf_bpfel.param.o")
                    {
                        opts.param_object = opts.root.join("bpf_bpfel.param.o");
                    }
                }
                "--object" => {
                    opts.source_object = PathBuf::from(next_value(&mut iter, "stage49 --object")?);
                }
                "--param-object" => {
                    opts.param_object =
                        PathBuf::from(next_value(&mut iter, "stage49 --param-object")?);
                }
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--peer-section" => {
                    opts.peer_section = next_value(&mut iter, "stage49 --peer-section")?;
                }
                "--host-section" => {
                    opts.host_section = next_value(&mut iter, "stage49 --host-section")?;
                }
                "--tproxy-port" => {
                    opts.tproxy_port =
                        parse_port(&next_value(&mut iter, "stage49 --tproxy-port")?)?;
                }
                "--dae-netns-id" => {
                    opts.dae_netns_id =
                        parse_u32(&next_value(&mut iter, "stage49 --dae-netns-id")?)?;
                }
                "--has-bpf-get-current-task" => opts.has_bpf_get_current_task = true,
                "--no-bpf-get-current-task" => opts.has_bpf_get_current_task = false,
                _ if arg.starts_with("--root=") => {
                    opts.root = PathBuf::from(value_after_equals(arg, "stage49 --root")?);
                    if opts.param_object
                        == PathBuf::from(DEFAULT_STAGE49_ROOT).join("bpf_bpfel.param.o")
                    {
                        opts.param_object = opts.root.join("bpf_bpfel.param.o");
                    }
                }
                _ if arg.starts_with("--object=") => {
                    opts.source_object =
                        PathBuf::from(value_after_equals(arg, "stage49 --object")?);
                }
                _ if arg.starts_with("--param-object=") => {
                    opts.param_object =
                        PathBuf::from(value_after_equals(arg, "stage49 --param-object")?);
                }
                _ if arg.starts_with("--peer-section=") => {
                    opts.peer_section = value_after_equals(arg, "stage49 --peer-section")?;
                }
                _ if arg.starts_with("--host-section=") => {
                    opts.host_section = value_after_equals(arg, "stage49 --host-section")?;
                }
                _ if arg.starts_with("--tproxy-port=") => {
                    opts.tproxy_port =
                        parse_port(&value_after_equals(arg, "stage49 --tproxy-port")?)?;
                }
                _ if arg.starts_with("--dae-netns-id=") => {
                    opts.dae_netns_id =
                        parse_u32(&value_after_equals(arg, "stage49 --dae-netns-id")?)?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage49-production-param-listener-admission argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn stage49_report(opts: &Stage49Options) -> Value {
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "isolated-root-under-tmp",
        tmp_root_allowed(&opts.root),
        json!({"path": path_string(&opts.root)}),
        &mut blockers,
        "stage49 root must be an absolute /tmp child path",
    );
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !opts.execute_smoke || opts.ack_root_gate,
        json!({"execute_smoke": opts.execute_smoke, "ack_root_gate": opts.ack_root_gate}),
        &mut blockers,
        "stage49 root-gated smoke requires --ack-root-gate",
    );
    for tool in ["ip", "tc"] {
        push_check(
            &mut checks,
            match tool {
                "ip" => "tool-ip-available",
                _ => "tool-tc-available",
            },
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
        "stage49 source eBPF object is missing",
    );
    push_check(
        &mut checks,
        "tproxy-port-valid",
        opts.tproxy_port != 0,
        json!({"tproxy_port": opts.tproxy_port}),
        &mut blockers,
        "stage49 tproxy port must be non-zero",
    );
    push_check(
        &mut checks,
        "dae-netns-id-valid",
        opts.dae_netns_id != 0,
        json!({"dae_netns_id": opts.dae_netns_id}),
        &mut blockers,
        "stage49 dae netns id must be non-zero",
    );
    if opts.execute_smoke {
        push_check(
            &mut checks,
            "production-names-free",
            !iface_exists(PRODUCTION_HOST_IFACE)
                && !iface_exists(PRODUCTION_PEER_IFACE)
                && !netns_exists(PRODUCTION_NETNS),
            json!({
                "host_iface": PRODUCTION_HOST_IFACE,
                "peer_iface": PRODUCTION_PEER_IFACE,
                "netns": PRODUCTION_NETNS,
            }),
            &mut blockers,
            "stage49 production names are already in use",
        );
        push_check(
            &mut checks,
            "tproxy-port-free",
            tproxy_port_available(opts.tproxy_port),
            json!({"tproxy_port": opts.tproxy_port}),
            &mut blockers,
            "stage49 tproxy port is already in use",
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
                blockers.push(format!("stage49 cannot snapshot BPF map ids: {err}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut param_image = Value::Null;
    let mut topology_values = Value::Null;
    let mut peer_attach_show = Value::Null;
    let mut host_attach_show = Value::Null;
    let mut loaded_map_handoff = Value::Null;
    let mut combined_production_param_listener_smoke_passed = false;
    let mut transparent_listener_socket_options_verified = false;
    let mut discovered_map_id = None;
    if opts.execute_smoke && blockers.is_empty() {
        let result = execute_stage49_smoke(opts, &before_map_ids);
        executed_steps = result.executed_steps;
        cleanup_steps = result.cleanup_steps;
        param_image = result.param_image;
        topology_values = result.topology_values;
        peer_attach_show = result.peer_attach_show;
        host_attach_show = result.host_attach_show;
        loaded_map_handoff = result.loaded_map_handoff;
        combined_production_param_listener_smoke_passed = result.passed;
        transparent_listener_socket_options_verified = result.socket_options_verified;
        discovered_map_id = result.discovered_map_id;
        if !combined_production_param_listener_smoke_passed {
            blockers
                .push("stage49 combined production-name PARAM listener smoke failed".to_owned());
        }
    }
    let after_pin_snapshot = if opts.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let (after_map_ids, loaded_map_cleaned) = if opts.execute_smoke {
        wait_for_loaded_map_cleanup(discovered_map_id)
    } else {
        (Vec::new(), true)
    };
    if opts.execute_smoke && !loaded_map_cleaned {
        blockers.push("stage49 loaded listen_socket_map remains after cleanup".to_owned());
    }
    let leftovers = production_resource_leftovers();
    if opts.execute_smoke && !leftovers.is_empty() {
        blockers.push("stage49 production-named resources remain after cleanup".to_owned());
    }
    let sys_fs_bpf_dae_mutated = before_pin_snapshot != after_pin_snapshot;
    if opts.execute_smoke && sys_fs_bpf_dae_mutated {
        blockers.push("stage49 unexpectedly mutated /sys/fs/bpf/dae".to_owned());
    }

    let mut report = Map::new();
    report.insert(
        "name".to_owned(),
        json!("stage49-production-param-listener-admission"),
    );
    report.insert("stage".to_owned(), json!("stage49"));
    report.insert(
        "evidence_class".to_owned(),
        json!("root-gated-combined-production-name-param-aware-transparent-listener-smoke"),
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
        "combined_production_param_listener_smoke_passed".to_owned(),
        json!(combined_production_param_listener_smoke_passed),
    );
    report.insert(
        "combined_production_param_listener_admitted".to_owned(),
        json!(combined_production_param_listener_smoke_passed),
    );
    report.insert(
        "production_name_dae0_dae0peer_attach_executed".to_owned(),
        json!(opts.execute_smoke && combined_production_param_listener_smoke_passed),
    );
    report.insert(
        "param_aware_object_load_executed".to_owned(),
        json!(opts.execute_smoke && combined_production_param_listener_smoke_passed),
    );
    report.insert(
        "transparent_listener_socket_options_verified".to_owned(),
        json!(transparent_listener_socket_options_verified),
    );
    report.insert(
        "production_param_transparent_listener_handoff_executed".to_owned(),
        json!(opts.execute_smoke && combined_production_param_listener_smoke_passed),
    );
    for key in [
        "production_default_daemon_attach_executed",
        "active_tproxy_traffic_executed",
        "active_tcp_tproxy_admitted",
        "active_udp_tproxy_admitted",
        "active_dns_tproxy_admitted",
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
        "combined_contract".to_owned(),
        json!({
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "peer_section": opts.peer_section,
            "host_section": opts.host_section,
            "filter_pref": STAGE49_FILTER_PREF,
            "source_object": path_string(&opts.source_object),
            "param_object": path_string(&opts.param_object),
            "listen_socket_map_kernel_name": LISTEN_SOCKET_MAP_KERNEL_NAME,
            "expected_map_type": "SockMap",
            "expected_key_size": 4,
            "expected_value_size": 8,
            "expected_max_entries": 2,
            "listener_keys": [0, 1],
            "tproxy_port": opts.tproxy_port,
            "dae_netns_id": opts.dae_netns_id,
            "required_socket_options": [
                "IP_TRANSPARENT",
                "SO_REUSEADDR",
                "IP_RECVORIGDSTADDR or IPV6_RECVORIGDSTADDR"
            ]
        }),
    );
    report.insert("topology_values".to_owned(), topology_values);
    report.insert("param_image".to_owned(), param_image);
    report.insert(
        "map_id_snapshots".to_owned(),
        json!({
            "before_attach": before_map_ids,
            "after_cleanup": after_map_ids,
            "discovered_map_id": discovered_map_id,
            "loaded_map_cleaned": loaded_map_cleaned,
        }),
    );
    report.insert("loaded_map_handoff".to_owned(), loaded_map_handoff);
    report.insert(
        "temporary_production_named_resources".to_owned(),
        json!({
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
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
    report.insert("executed_steps".to_owned(), json!(executed_steps));
    report.insert("cleanup_steps".to_owned(), json!(cleanup_steps));
    report.insert("peer_attach_show".to_owned(), peer_attach_show);
    report.insert("host_attach_show".to_owned(), host_attach_show);
    report.insert("remaining_blockers".to_owned(), json!(remaining_blockers()));
    Value::Object(report)
}

struct Stage49SmokeResult {
    passed: bool,
    socket_options_verified: bool,
    discovered_map_id: Option<u32>,
    executed_steps: Vec<Value>,
    cleanup_steps: Vec<Value>,
    topology_values: Value,
    param_image: Value,
    peer_attach_show: Value,
    host_attach_show: Value,
    loaded_map_handoff: Value,
}

fn execute_stage49_smoke(opts: &Stage49Options, before_map_ids: &[u32]) -> Stage49SmokeResult {
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut ok = true;

    ok &= run_step(
        &mut executed_steps,
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
        &mut executed_steps,
        "create-production-netns",
        CommandSpec::new("ip", &["netns", "add", PRODUCTION_NETNS]),
    );
    ok &= run_step(
        &mut executed_steps,
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
        &mut executed_steps,
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
        &mut executed_steps,
        "bring-production-host-link-up",
        CommandSpec::new("ip", &["link", "set", PRODUCTION_HOST_IFACE, "up"]),
    );
    ok &= run_step(
        &mut executed_steps,
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
        &mut executed_steps,
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

    let dae0_ifindex_step = run_observation_step(
        &mut executed_steps,
        "read-production-dae0-ifindex",
        CommandSpec::new(
            "cat",
            &[&format!("/sys/class/net/{PRODUCTION_HOST_IFACE}/ifindex")],
        ),
    );
    let dae0peer_mac_step = run_observation_step(
        &mut executed_steps,
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
    let dae0_ifindex = parse_step_u32(&dae0_ifindex_step);
    let dae0peer_mac = parse_step_mac(&dae0peer_mac_step);
    let topology_values = match (dae0_ifindex, dae0peer_mac) {
        (Ok(dae0_ifindex), Ok(dae0peer_mac)) => json!({
            "status": "pass",
            "dae0_ifindex": dae0_ifindex,
            "dae_netns_id": opts.dae_netns_id,
            "dae_netns_id_source": "ip netns set daens",
            "dae0peer_mac": mac_string(dae0peer_mac),
            "control_plane_pid": std::process::id(),
            "has_bpf_get_current_task": opts.has_bpf_get_current_task,
        }),
        (ifindex, mac) => {
            ok = false;
            json!({
                "status": "fail",
                "dae0_ifindex_error": ifindex.err().map(|err| err.to_string()),
                "dae0peer_mac_error": mac.err().map(|err| err.to_string()),
            })
        }
    };

    let param_image = if ok {
        let dae0_ifindex = topology_values["dae0_ifindex"].as_u64().unwrap() as u32;
        let dae0peer_mac = parse_mac(topology_values["dae0peer_mac"].as_str().unwrap())
            .expect("stage49 topology mac must parse after earlier validation");
        let param = build_dae_param(DaeParamInput {
            tproxy_port: opts.tproxy_port,
            control_plane_pid: std::process::id(),
            dae0_ifindex,
            dae_netns_id: opts.dae_netns_id,
            dae0peer_mac,
            has_bpf_get_current_task: opts.has_bpf_get_current_task,
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
            Err(err) => {
                ok = false;
                json!({
                    "status": "fail",
                    "path": path_string(&opts.param_object),
                    "error": err.to_string(),
                })
            }
        }
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
        let param_object = path_string(&opts.param_object);
        ok &= run_step(
            &mut executed_steps,
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
            &mut executed_steps,
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
                    STAGE49_FILTER_PREF,
                    "bpf",
                    "da",
                    "obj",
                    &param_object,
                    "sec",
                    &opts.peer_section,
                ],
            ),
        );
    }
    let peer_attach_show = run_observation_step(
        &mut executed_steps,
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
    );

    let (loaded_map_handoff, discovered_map_id, handoff_passed, socket_options_verified) = if ok {
        match run_loaded_tproxy_listen_socket_map_fd_smoke(before_map_ids, opts.tproxy_port) {
            Ok(report) => {
                let options_verified =
                    socket_options_verified(&report.tcp_options, &report.udp_options);
                (
                    json!({
                        "status": "pass",
                        "map": {
                            "id": report.map.id,
                            "name": report.map.name,
                            "map_type": report.map.map_type,
                            "key_size": report.map.key_size,
                            "value_size": report.map.value_size,
                            "max_entries": report.map.max_entries,
                            "flags": report.map.flags,
                        },
                        "new_map_ids": report.new_map_ids,
                        "keys_updated": report.keys_updated,
                        "tcp_listener_fd_observed": report.tcp_listener_fd >= 0,
                        "udp_socket_fd_observed": report.udp_socket_fd >= 0,
                        "tcp_options": {
                            "ip_transparent": report.tcp_options.ip_transparent,
                            "so_reuseaddr": report.tcp_options.so_reuseaddr,
                            "ip_recvorigdstaddr": report.tcp_options.ip_recvorigdstaddr,
                            "ipv6_recvorigdstaddr": report.tcp_options.ipv6_recvorigdstaddr,
                            "original_dst_capture_ready": report.tcp_options.original_dst_capture_ready,
                        },
                        "udp_options": {
                            "ip_transparent": report.udp_options.ip_transparent,
                            "so_reuseaddr": report.udp_options.so_reuseaddr,
                            "ip_recvorigdstaddr": report.udp_options.ip_recvorigdstaddr,
                            "ipv6_recvorigdstaddr": report.udp_options.ipv6_recvorigdstaddr,
                            "original_dst_capture_ready": report.udp_options.original_dst_capture_ready,
                        },
                    }),
                    Some(report.map.id),
                    true,
                    options_verified,
                )
            }
            Err(err) => (
                json!({
                    "status": "fail",
                    "error": err.to_string(),
                }),
                None,
                false,
                false,
            ),
        }
    } else {
        (
            json!({
                "status": "skipped",
                "reason": "PARAM-aware dae0peer attach did not pass",
            }),
            None,
            false,
            false,
        )
    };
    ok &= handoff_passed && socket_options_verified;

    if ok {
        let param_object = path_string(&opts.param_object);
        ok &= run_step(
            &mut executed_steps,
            "attach-production-host-clsact-qdisc",
            CommandSpec::new(
                "tc",
                &["qdisc", "add", "dev", PRODUCTION_HOST_IFACE, "clsact"],
            ),
        );
        ok &= run_step(
            &mut executed_steps,
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
                    STAGE49_FILTER_PREF,
                    "bpf",
                    "da",
                    "obj",
                    &param_object,
                    "sec",
                    &opts.host_section,
                ],
            ),
        );
    }
    let host_attach_show = run_observation_step(
        &mut executed_steps,
        "show-production-dae0-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &["filter", "show", "dev", PRODUCTION_HOST_IFACE, "ingress"],
        ),
    );

    ok &= run_step(
        &mut cleanup_steps,
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
                STAGE49_FILTER_PREF,
            ],
        ),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-production-host-clsact-qdisc",
        CommandSpec::new(
            "tc",
            &["qdisc", "del", "dev", PRODUCTION_HOST_IFACE, "clsact"],
        ),
    );
    ok &= run_step(
        &mut cleanup_steps,
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
                STAGE49_FILTER_PREF,
            ],
        ),
    );
    ok &= run_step(
        &mut cleanup_steps,
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
    ok &= run_step(
        &mut cleanup_steps,
        "delete-production-host-link",
        CommandSpec::new("ip", &["link", "del", PRODUCTION_HOST_IFACE]),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-production-netns",
        CommandSpec::new("ip", &["netns", "del", PRODUCTION_NETNS]),
    );

    let peer_output = peer_attach_show["stdout"].as_str().unwrap_or_default();
    let host_output = host_attach_show["stdout"].as_str().unwrap_or_default();
    Stage49SmokeResult {
        passed: ok
            && peer_attach_show["status"].as_str() == Some("pass")
            && peer_output.contains(&opts.peer_section)
            && peer_output.contains("tproxy_dae0peer")
            && host_attach_show["status"].as_str() == Some("pass")
            && host_output.contains(&opts.host_section)
            && host_output.contains("tproxy_dae0_ing")
            && production_resource_leftovers().is_empty(),
        socket_options_verified,
        discovered_map_id,
        executed_steps,
        cleanup_steps,
        topology_values,
        param_image,
        peer_attach_show,
        host_attach_show,
        loaded_map_handoff,
    }
}

fn socket_options_verified(
    tcp: &dae_ebpf_support::TproxySocketOptions,
    udp: &dae_ebpf_support::TproxySocketOptions,
) -> bool {
    tcp.ip_transparent
        && tcp.so_reuseaddr
        && tcp.original_dst_capture_ready
        && udp.ip_transparent
        && udp.so_reuseaddr
        && udp.original_dst_capture_ready
}

fn remaining_blockers() -> Vec<&'static str> {
    vec![
        "active tproxy TCP UDP DNS traffic evidence is still missing",
        "outbound true dataplane admission is still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "production default daemon lifecycle is not executed",
        "clean dae-wing and daed product-chain recertification is still missing",
    ]
}

fn wait_for_loaded_map_cleanup(discovered_map_id: Option<u32>) -> (Vec<u32>, bool) {
    let mut current = map_ids().unwrap_or_default();
    let Some(discovered_map_id) = discovered_map_id else {
        return (current, true);
    };
    if !current.contains(&discovered_map_id) {
        return (current, true);
    }
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(50));
        current = map_ids().unwrap_or_default();
        if !current.contains(&discovered_map_id) {
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

fn production_resource_leftovers() -> Vec<String> {
    let mut leftovers = Vec::new();
    if iface_exists(PRODUCTION_HOST_IFACE) {
        leftovers.push(format!("iface:{PRODUCTION_HOST_IFACE}"));
    }
    if iface_exists(PRODUCTION_PEER_IFACE) {
        leftovers.push(format!("iface:{PRODUCTION_PEER_IFACE}"));
    }
    if netns_exists(PRODUCTION_NETNS) {
        leftovers.push(format!("netns:{PRODUCTION_NETNS}"));
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
    let output = Command::new(spec.program).args(&spec.args).output();
    let (status, code, stdout, stderr) = command_output(output);
    steps.push(json!({
        "name": name,
        "status": status,
        "program": spec.program,
        "args": spec.args,
        "exit_code": code,
        "stdout": stdout,
        "stderr": stderr,
    }));
    status == "pass"
}

fn run_observation_step(steps: &mut Vec<Value>, name: &str, spec: CommandSpec<'_>) -> Value {
    let output = Command::new(spec.program).args(&spec.args).output();
    let (status, code, stdout, stderr) = command_output(output);
    let value = json!({
        "name": name,
        "status": status,
        "program": spec.program,
        "args": spec.args,
        "exit_code": code,
        "stdout": stdout,
        "stderr": stderr,
    });
    steps.push(value.clone());
    value
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

fn parse_port(value: &str) -> Result<u16, RunnerOutput> {
    value
        .parse::<u16>()
        .map_err(|err| RunnerOutput::usage(format!("invalid stage49 --tproxy-port: {err}")))
        .and_then(|port| {
            if port == 0 {
                Err(RunnerOutput::usage(
                    "invalid stage49 --tproxy-port: must be non-zero",
                ))
            } else {
                Ok(port)
            }
        })
}

fn parse_u32(value: &str) -> Result<u32, RunnerOutput> {
    value
        .parse::<u32>()
        .map_err(|err| RunnerOutput::usage(format!("invalid stage49 --dae-netns-id: {err}")))
        .and_then(|parsed| {
            if parsed == 0 {
                Err(RunnerOutput::usage(
                    "invalid stage49 --dae-netns-id: must be non-zero",
                ))
            } else {
                Ok(parsed)
            }
        })
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
