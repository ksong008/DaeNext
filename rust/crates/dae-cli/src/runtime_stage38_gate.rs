use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use dae_ebpf_support::{map_ids, run_loaded_listen_socket_map_fd_smoke};
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_STAGE38_ROOT: &str = "/tmp/dae-stage38-candidate";
const DEFAULT_STAGE38_OBJECT: &str = "control/bpf_bpfel.o";
const DEFAULT_STAGE38_PEER_SECTION: &str = "tc/dae0peer_ingress";
const DEFAULT_STAGE38_HOST_SECTION: &str = "tc/dae0_ingress";
const STAGE38_FILTER_PREF: &str = "49380";
const PRODUCTION_NETNS: &str = "daens";
const PRODUCTION_HOST_IFACE: &str = "dae0";
const PRODUCTION_PEER_IFACE: &str = "dae0peer";
const LISTEN_SOCKET_MAP_KERNEL_NAME: &str = "listen_socket_m";

pub(crate) fn run_stage38_production_dae_attach_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage38Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage38_report(&opts);
    output_with_execution_status(
        report,
        opts.execute_smoke,
        "production_name_attach_handoff_smoke_passed",
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
struct Stage38Options {
    root: PathBuf,
    stage37_report: Option<PathBuf>,
    execute_smoke: bool,
    ack_root_gate: bool,
    object_path: PathBuf,
    peer_section: String,
    host_section: String,
}

impl Default for Stage38Options {
    fn default() -> Self {
        Self {
            root: PathBuf::from(DEFAULT_STAGE38_ROOT),
            stage37_report: None,
            execute_smoke: false,
            ack_root_gate: false,
            object_path: PathBuf::from(DEFAULT_STAGE38_OBJECT),
            peer_section: DEFAULT_STAGE38_PEER_SECTION.to_owned(),
            host_section: DEFAULT_STAGE38_HOST_SECTION.to_owned(),
        }
    }
}

impl Stage38Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--root" => opts.root = PathBuf::from(next_value(&mut iter, "stage38 --root")?),
                "--stage37-report" => {
                    opts.stage37_report = Some(PathBuf::from(next_value(
                        &mut iter,
                        "stage38 --stage37-report",
                    )?));
                }
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--object" => {
                    opts.object_path = PathBuf::from(next_value(&mut iter, "stage38 --object")?);
                }
                "--peer-section" => {
                    opts.peer_section = next_value(&mut iter, "stage38 --peer-section")?;
                }
                "--host-section" => {
                    opts.host_section = next_value(&mut iter, "stage38 --host-section")?;
                }
                _ if arg.starts_with("--root=") => {
                    opts.root = PathBuf::from(value_after_equals(arg, "stage38 --root")?);
                }
                _ if arg.starts_with("--stage37-report=") => {
                    opts.stage37_report = Some(PathBuf::from(value_after_equals(
                        arg,
                        "stage38 --stage37-report",
                    )?));
                }
                _ if arg.starts_with("--object=") => {
                    opts.object_path = PathBuf::from(value_after_equals(arg, "stage38 --object")?);
                }
                _ if arg.starts_with("--peer-section=") => {
                    opts.peer_section = value_after_equals(arg, "stage38 --peer-section")?;
                }
                _ if arg.starts_with("--host-section=") => {
                    opts.host_section = value_after_equals(arg, "stage38 --host-section")?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage38-production-dae-attach-admission argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn stage38_report(opts: &Stage38Options) -> Value {
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "isolated-root-under-tmp",
        tmp_root_allowed(&opts.root),
        json!({"path": path_string(&opts.root)}),
        &mut blockers,
        "stage38 root must be an absolute /tmp child path",
    );
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !opts.execute_smoke || opts.ack_root_gate,
        json!({"execute_smoke": opts.execute_smoke, "ack_root_gate": opts.ack_root_gate}),
        &mut blockers,
        "stage38 root-gated smoke requires --ack-root-gate",
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
        "real-dae-object-present",
        opts.object_path.exists(),
        json!({"path": path_string(&opts.object_path)}),
        &mut blockers,
        "stage38 real dae eBPF object is missing",
    );
    let stage37 = read_report(
        opts.stage37_report.as_deref(),
        "loaded_listen_socket_map_handoff_smoke_passed",
    );
    push_check(
        &mut checks,
        "stage37-real-loaded-map-report-passed",
        !opts.execute_smoke || stage37.passed,
        json!({
            "path": stage37.path.clone(),
            "status": stage37.status,
            "loaded_listen_socket_map_handoff_smoke_passed": stage37.passed,
            "blockers": stage37.blockers.clone(),
        }),
        &mut blockers,
        "stage38 root-gated smoke requires a passed Stage 37 real loaded map report",
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
            "stage38 production names are already in use",
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
                blockers.push(format!("stage38 cannot snapshot BPF map ids: {err}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut peer_attach_show = Value::Null;
    let mut host_attach_show = Value::Null;
    let mut loaded_map_handoff = Value::Null;
    let mut production_name_attach_handoff_smoke_passed = false;
    let mut discovered_map_id = None;
    if opts.execute_smoke && blockers.is_empty() {
        let result = execute_stage38_smoke(opts, &before_map_ids);
        executed_steps = result.executed_steps;
        cleanup_steps = result.cleanup_steps;
        peer_attach_show = result.peer_attach_show;
        host_attach_show = result.host_attach_show;
        loaded_map_handoff = result.loaded_map_handoff;
        production_name_attach_handoff_smoke_passed = result.passed;
        discovered_map_id = result.discovered_map_id;
        if !production_name_attach_handoff_smoke_passed {
            blockers.push("stage38 production-name dae attach handoff smoke failed".to_owned());
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
        blockers.push("stage38 loaded listen_socket_map remains after cleanup".to_owned());
    }
    let leftovers = production_resource_leftovers();
    if opts.execute_smoke && !leftovers.is_empty() {
        blockers.push("stage38 production-named resources remain after cleanup".to_owned());
    }
    let sys_fs_bpf_dae_mutated = before_pin_snapshot != after_pin_snapshot;
    if opts.execute_smoke && sys_fs_bpf_dae_mutated {
        blockers.push("stage38 unexpectedly mutated /sys/fs/bpf/dae".to_owned());
    }
    let production_name_dae0_dae0peer_attach_executed =
        opts.execute_smoke && production_name_attach_handoff_smoke_passed;
    let production_name_listen_socket_map_fd_update_executed =
        opts.execute_smoke && production_name_attach_handoff_smoke_passed;

    json!({
        "name": "stage38-production-dae-attach-admission",
        "stage": "stage38",
        "evidence_class": "root-gated-production-name-dae0-dae0peer-listener-handoff-smoke",
        "root": path_string(&opts.root),
        "execute_smoke": opts.execute_smoke,
        "root_gate_acknowledged": opts.ack_root_gate,
        "read_only": !opts.execute_smoke,
        "blocked": !blockers.is_empty(),
        "production_name_attach_handoff_smoke_passed": production_name_attach_handoff_smoke_passed,
        "production_name_dae0_dae0peer_attach_executed": production_name_dae0_dae0peer_attach_executed,
        "production_name_listen_socket_map_fd_update_executed": production_name_listen_socket_map_fd_update_executed,
        "production_dae0_dae0peer_attach_executed": production_name_dae0_dae0peer_attach_executed,
        "production_listen_socket_map_fd_update_executed": production_name_listen_socket_map_fd_update_executed,
        "production_default_daemon_attach_executed": false,
        "active_tproxy_traffic_executed": false,
        "live_candidate_run_allowed": false,
        "default_switch_allowed": false,
        "default_path_mutated": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "blockers": blockers,
        "checks": checks,
        "stage37_report": {
            "path": stage37.path,
            "status": stage37.status,
            "passed": stage37.passed,
            "blockers": stage37.blockers,
        },
        "production_name_contract": {
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "peer_section": opts.peer_section,
            "host_section": opts.host_section,
            "filter_pref": STAGE38_FILTER_PREF,
            "listen_socket_map_kernel_name": LISTEN_SOCKET_MAP_KERNEL_NAME,
            "expected_map_type": "SockMap",
            "expected_key_size": 4,
            "expected_value_size": 8,
            "expected_max_entries": 2,
            "listener_keys": [0, 1],
            "object_path": path_string(&opts.object_path),
        },
        "map_id_snapshots": {
            "before_attach": before_map_ids,
            "after_cleanup": after_map_ids,
            "discovered_map_id": discovered_map_id,
            "loaded_map_cleaned": loaded_map_cleaned,
        },
        "loaded_map_handoff": loaded_map_handoff,
        "temporary_production_named_resources": {
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "leftovers_after_cleanup": leftovers,
        },
        "sys_fs_bpf_dae": {
            "before": before_pin_snapshot,
            "after": after_pin_snapshot,
            "mutated": sys_fs_bpf_dae_mutated,
        },
        "executed_steps": executed_steps,
        "cleanup_steps": cleanup_steps,
        "peer_attach_show": peer_attach_show,
        "host_attach_show": host_attach_show,
        "remaining_blockers": remaining_blockers(),
    })
}

struct Stage38SmokeResult {
    passed: bool,
    discovered_map_id: Option<u32>,
    executed_steps: Vec<Value>,
    cleanup_steps: Vec<Value>,
    peer_attach_show: Value,
    host_attach_show: Value,
    loaded_map_handoff: Value,
}

fn execute_stage38_smoke(opts: &Stage38Options, before_map_ids: &[u32]) -> Stage38SmokeResult {
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut ok = true;
    let object_path = path_string(&opts.object_path);

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
        "attach-production-dae0peer-ebpf-program",
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
                STAGE38_FILTER_PREF,
                "bpf",
                "da",
                "obj",
                &object_path,
                "sec",
                &opts.peer_section,
            ],
        ),
    );
    let peer_attach_show = run_observation_step(
        &mut executed_steps,
        "show-production-dae0peer-ebpf-program-filter",
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
    let (loaded_map_handoff, discovered_map_id, handoff_passed) =
        match run_loaded_listen_socket_map_fd_smoke(before_map_ids) {
            Ok(report) => (
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
                }),
                Some(report.map.id),
                true,
            ),
            Err(err) => (
                json!({
                    "status": "fail",
                    "error": err.to_string(),
                }),
                None,
                false,
            ),
        };
    ok &= handoff_passed;
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
        "attach-production-dae0-ebpf-program",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "add",
                "dev",
                PRODUCTION_HOST_IFACE,
                "ingress",
                "pref",
                STAGE38_FILTER_PREF,
                "bpf",
                "da",
                "obj",
                &object_path,
                "sec",
                &opts.host_section,
            ],
        ),
    );
    let host_attach_show = run_observation_step(
        &mut executed_steps,
        "show-production-dae0-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &["filter", "show", "dev", PRODUCTION_HOST_IFACE, "ingress"],
        ),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-production-dae0-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                PRODUCTION_HOST_IFACE,
                "ingress",
                "pref",
                STAGE38_FILTER_PREF,
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
        "delete-production-dae0peer-ebpf-program-filter",
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
                STAGE38_FILTER_PREF,
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
    Stage38SmokeResult {
        passed: ok
            && peer_attach_show["status"].as_str() == Some("pass")
            && peer_output.contains(&opts.peer_section)
            && peer_output.contains("tproxy_dae0peer")
            && host_attach_show["status"].as_str() == Some("pass")
            && host_output.contains(&opts.host_section)
            && host_output.contains("tproxy_dae0_ing")
            && production_resource_leftovers().is_empty(),
        discovered_map_id,
        executed_steps,
        cleanup_steps,
        peer_attach_show,
        host_attach_show,
        loaded_map_handoff,
    }
}

fn remaining_blockers() -> Vec<&'static str> {
    vec![
        "production default daemon attach path is not executed",
        "active tproxy TCP UDP DNS traffic evidence is still missing",
        "outbound true dataplane admission is still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
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

#[derive(Debug)]
struct PriorReport {
    path: Option<String>,
    status: &'static str,
    passed: bool,
    blockers: Vec<String>,
}

fn read_report(path: Option<&Path>, pass_key: &str) -> PriorReport {
    let Some(path) = path else {
        return PriorReport {
            path: None,
            status: "not-provided",
            passed: false,
            blockers: Vec::new(),
        };
    };
    match fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(value) => PriorReport {
                path: Some(path_string(path)),
                status: "parsed",
                passed: value[pass_key].as_bool().unwrap_or(false)
                    && !value["blocked"].as_bool().unwrap_or(true),
                blockers: value["blockers"]
                    .as_array()
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                            .collect()
                    })
                    .unwrap_or_default(),
            },
            Err(err) => PriorReport {
                path: Some(path_string(path)),
                status: "invalid-json",
                passed: false,
                blockers: vec![err.to_string()],
            },
        },
        Err(err) => PriorReport {
            path: Some(path_string(path)),
            status: "unreadable",
            passed: false,
            blockers: vec![err.to_string()],
        },
    }
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
    let (status, code, stdout, stderr) = match output {
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
    };
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
    let (status, code, stdout, stderr) = match output {
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
    };
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
