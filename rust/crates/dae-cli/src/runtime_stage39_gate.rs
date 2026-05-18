use std::env;
use std::fs;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use dae_ebpf_support::{map_ids, run_loaded_tproxy_listen_socket_map_fd_smoke};
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_STAGE39_ROOT: &str = "/tmp/dae-stage39-candidate";
const DEFAULT_STAGE39_IFACE: &str = "dae39p0";
const DEFAULT_STAGE39_OBJECT: &str = "control/bpf_bpfel.o";
const DEFAULT_STAGE39_SECTION: &str = "tc/dae0peer_ingress";
const DEFAULT_STAGE39_TPROXY_PORT: u16 = 12345;
const STAGE39_FILTER_PREF: &str = "49390";
const LISTEN_SOCKET_MAP_KERNEL_NAME: &str = "listen_socket_m";

pub(crate) fn run_stage39_transparent_listener_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage39Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage39_report(&opts);
    output_with_execution_status(
        report,
        opts.execute_smoke,
        "transparent_listener_handoff_smoke_passed",
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
struct Stage39Options {
    root: PathBuf,
    stage38_report: Option<PathBuf>,
    execute_smoke: bool,
    ack_root_gate: bool,
    iface: String,
    object_path: PathBuf,
    section: String,
    tproxy_port: u16,
}

impl Default for Stage39Options {
    fn default() -> Self {
        Self {
            root: PathBuf::from(DEFAULT_STAGE39_ROOT),
            stage38_report: None,
            execute_smoke: false,
            ack_root_gate: false,
            iface: DEFAULT_STAGE39_IFACE.to_owned(),
            object_path: PathBuf::from(DEFAULT_STAGE39_OBJECT),
            section: DEFAULT_STAGE39_SECTION.to_owned(),
            tproxy_port: DEFAULT_STAGE39_TPROXY_PORT,
        }
    }
}

impl Stage39Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--root" => opts.root = PathBuf::from(next_value(&mut iter, "stage39 --root")?),
                "--stage38-report" => {
                    opts.stage38_report = Some(PathBuf::from(next_value(
                        &mut iter,
                        "stage39 --stage38-report",
                    )?));
                }
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--iface" => opts.iface = next_value(&mut iter, "stage39 --iface")?,
                "--object" => {
                    opts.object_path = PathBuf::from(next_value(&mut iter, "stage39 --object")?);
                }
                "--section" => opts.section = next_value(&mut iter, "stage39 --section")?,
                "--tproxy-port" => {
                    opts.tproxy_port =
                        parse_port(&next_value(&mut iter, "stage39 --tproxy-port")?)?;
                }
                _ if arg.starts_with("--root=") => {
                    opts.root = PathBuf::from(value_after_equals(arg, "stage39 --root")?);
                }
                _ if arg.starts_with("--stage38-report=") => {
                    opts.stage38_report = Some(PathBuf::from(value_after_equals(
                        arg,
                        "stage39 --stage38-report",
                    )?));
                }
                _ if arg.starts_with("--iface=") => {
                    opts.iface = value_after_equals(arg, "stage39 --iface")?;
                }
                _ if arg.starts_with("--object=") => {
                    opts.object_path = PathBuf::from(value_after_equals(arg, "stage39 --object")?);
                }
                _ if arg.starts_with("--section=") => {
                    opts.section = value_after_equals(arg, "stage39 --section")?;
                }
                _ if arg.starts_with("--tproxy-port=") => {
                    opts.tproxy_port =
                        parse_port(&value_after_equals(arg, "stage39 --tproxy-port")?)?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage39-transparent-listener-admission argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn stage39_report(opts: &Stage39Options) -> Value {
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "isolated-root-under-tmp",
        tmp_root_allowed(&opts.root),
        json!({"path": path_string(&opts.root)}),
        &mut blockers,
        "stage39 root must be an absolute /tmp child path",
    );
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !opts.execute_smoke || opts.ack_root_gate,
        json!({"execute_smoke": opts.execute_smoke, "ack_root_gate": opts.ack_root_gate}),
        &mut blockers,
        "stage39 root-gated smoke requires --ack-root-gate",
    );
    push_check(
        &mut checks,
        "temporary-interface-name-valid",
        iface_name_valid(&opts.iface),
        json!({"iface": opts.iface, "max_linux_ifname_len": 15}),
        &mut blockers,
        "stage39 temporary interface name is invalid",
    );
    push_check(
        &mut checks,
        "temporary-interface-not-production",
        opts.iface != "dae0" && opts.iface != "dae0peer",
        json!({"iface": opts.iface}),
        &mut blockers,
        "stage39 cannot target production dae0/dae0peer names",
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
        "stage39 real dae eBPF object is missing",
    );
    push_check(
        &mut checks,
        "tproxy-port-valid",
        opts.tproxy_port != 0,
        json!({"tproxy_port": opts.tproxy_port}),
        &mut blockers,
        "stage39 tproxy port must be non-zero",
    );
    let stage38 = read_report(
        opts.stage38_report.as_deref(),
        "production_name_attach_handoff_smoke_passed",
    );
    push_check(
        &mut checks,
        "stage38-production-name-report-passed",
        !opts.execute_smoke || stage38.passed,
        json!({
            "path": stage38.path.clone(),
            "status": stage38.status,
            "production_name_attach_handoff_smoke_passed": stage38.passed,
            "blockers": stage38.blockers.clone(),
        }),
        &mut blockers,
        "stage39 root-gated smoke requires a passed Stage 38 production-name report",
    );
    if opts.execute_smoke {
        push_check(
            &mut checks,
            "temporary-interface-name-free",
            !iface_exists(&opts.iface),
            json!({"iface": opts.iface}),
            &mut blockers,
            "stage39 temporary interface name already exists",
        );
        push_check(
            &mut checks,
            "tproxy-port-free",
            tproxy_port_available(opts.tproxy_port),
            json!({"tproxy_port": opts.tproxy_port}),
            &mut blockers,
            "stage39 tproxy port is already in use",
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
                blockers.push(format!("stage39 cannot snapshot BPF map ids: {err}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut attach_show = Value::Null;
    let mut loaded_map_handoff = Value::Null;
    let mut transparent_listener_handoff_smoke_passed = false;
    let mut transparent_listener_socket_options_verified = false;
    let mut discovered_map_id = None;
    if opts.execute_smoke && blockers.is_empty() {
        let result = execute_stage39_smoke(opts, &before_map_ids);
        executed_steps = result.executed_steps;
        cleanup_steps = result.cleanup_steps;
        attach_show = result.attach_show;
        loaded_map_handoff = result.loaded_map_handoff;
        transparent_listener_handoff_smoke_passed = result.passed;
        transparent_listener_socket_options_verified = result.socket_options_verified;
        discovered_map_id = result.discovered_map_id;
        if !transparent_listener_handoff_smoke_passed {
            blockers.push("stage39 transparent listener handoff smoke failed".to_owned());
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
        blockers.push("stage39 loaded listen_socket_map remains after cleanup".to_owned());
    }
    let leftovers = iface_leftovers(&opts.iface);
    if opts.execute_smoke && !leftovers.is_empty() {
        blockers.push("stage39 temporary resources remain after cleanup".to_owned());
    }
    let sys_fs_bpf_dae_mutated = before_pin_snapshot != after_pin_snapshot;
    if opts.execute_smoke && sys_fs_bpf_dae_mutated {
        blockers.push("stage39 unexpectedly mutated /sys/fs/bpf/dae".to_owned());
    }

    json!({
        "name": "stage39-transparent-listener-admission",
        "stage": "stage39",
        "evidence_class": "root-gated-real-loaded-object-transparent-listener-handoff-smoke",
        "root": path_string(&opts.root),
        "execute_smoke": opts.execute_smoke,
        "root_gate_acknowledged": opts.ack_root_gate,
        "read_only": !opts.execute_smoke,
        "blocked": !blockers.is_empty(),
        "transparent_listener_handoff_smoke_passed": transparent_listener_handoff_smoke_passed,
        "real_loaded_object_transparent_listener_fd_update_executed": opts.execute_smoke && transparent_listener_handoff_smoke_passed,
        "transparent_listener_socket_options_verified": transparent_listener_socket_options_verified,
        "production_name_dae0_dae0peer_attach_executed": false,
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
        "stage38_report": {
            "path": stage38.path,
            "status": stage38.status,
            "passed": stage38.passed,
            "blockers": stage38.blockers,
        },
        "transparent_listener_contract": {
            "object_path": path_string(&opts.object_path),
            "section": opts.section,
            "filter_pref": STAGE39_FILTER_PREF,
            "listen_socket_map_kernel_name": LISTEN_SOCKET_MAP_KERNEL_NAME,
            "expected_map_type": "SockMap",
            "expected_key_size": 4,
            "expected_value_size": 8,
            "expected_max_entries": 2,
            "listener_keys": [0, 1],
            "temporary_iface": opts.iface,
            "tproxy_port": opts.tproxy_port,
            "required_socket_options": [
                "IP_TRANSPARENT",
                "SO_REUSEADDR",
                "IP_RECVORIGDSTADDR or IPV6_RECVORIGDSTADDR"
            ]
        },
        "map_id_snapshots": {
            "before_attach": before_map_ids,
            "after_cleanup": after_map_ids,
            "discovered_map_id": discovered_map_id,
            "loaded_map_cleaned": loaded_map_cleaned,
        },
        "loaded_map_handoff": loaded_map_handoff,
        "temporary_resources": {
            "iface": opts.iface,
            "leftovers_after_cleanup": leftovers,
        },
        "sys_fs_bpf_dae": {
            "before": before_pin_snapshot,
            "after": after_pin_snapshot,
            "mutated": sys_fs_bpf_dae_mutated,
        },
        "executed_steps": executed_steps,
        "cleanup_steps": cleanup_steps,
        "attach_show": attach_show,
        "remaining_blockers": remaining_blockers(),
    })
}

struct Stage39SmokeResult {
    passed: bool,
    socket_options_verified: bool,
    discovered_map_id: Option<u32>,
    executed_steps: Vec<Value>,
    cleanup_steps: Vec<Value>,
    attach_show: Value,
    loaded_map_handoff: Value,
}

fn execute_stage39_smoke(opts: &Stage39Options, before_map_ids: &[u32]) -> Stage39SmokeResult {
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut ok = true;
    let object_path = path_string(&opts.object_path);

    ok &= run_step(
        &mut executed_steps,
        "create-temporary-dummy-link",
        CommandSpec::new("ip", &["link", "add", &opts.iface, "type", "dummy"]),
    );
    ok &= run_step(
        &mut executed_steps,
        "bring-temporary-link-up",
        CommandSpec::new("ip", &["link", "set", &opts.iface, "up"]),
    );
    ok &= run_step(
        &mut executed_steps,
        "attach-temporary-clsact-qdisc",
        CommandSpec::new("tc", &["qdisc", "add", "dev", &opts.iface, "clsact"]),
    );
    ok &= run_step(
        &mut executed_steps,
        "attach-real-dae0peer-ebpf-program",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "add",
                "dev",
                &opts.iface,
                "ingress",
                "pref",
                STAGE39_FILTER_PREF,
                "bpf",
                "da",
                "obj",
                &object_path,
                "sec",
                &opts.section,
            ],
        ),
    );
    let attach_show = run_observation_step(
        &mut executed_steps,
        "show-real-dae0peer-ebpf-program-filter",
        CommandSpec::new("tc", &["filter", "show", "dev", &opts.iface, "ingress"]),
    );
    let (loaded_map_handoff, discovered_map_id, handoff_passed, socket_options_verified) =
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
        };
    ok &= handoff_passed && socket_options_verified;
    ok &= run_step(
        &mut cleanup_steps,
        "delete-real-dae0peer-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                &opts.iface,
                "ingress",
                "pref",
                STAGE39_FILTER_PREF,
            ],
        ),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-temporary-clsact-qdisc",
        CommandSpec::new("tc", &["qdisc", "del", "dev", &opts.iface, "clsact"]),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-temporary-link",
        CommandSpec::new("ip", &["link", "del", &opts.iface]),
    );

    let attach_output = attach_show["stdout"].as_str().unwrap_or_default();
    Stage39SmokeResult {
        passed: ok
            && attach_show["status"].as_str() == Some("pass")
            && attach_output.contains(&opts.section)
            && attach_output.contains("tproxy_dae0peer")
            && iface_leftovers(&opts.iface).is_empty(),
        socket_options_verified,
        discovered_map_id,
        executed_steps,
        cleanup_steps,
        attach_show,
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
        "production default daemon attach path is not executed",
        "active tproxy TCP UDP DNS traffic evidence is still missing",
        "outbound true dataplane admission is still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing",
    ]
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

fn iface_name_valid(name: &str) -> bool {
    !name.is_empty() && name.len() <= 15 && !name.chars().any(char::is_whitespace)
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

fn iface_leftovers(iface: &str) -> Vec<String> {
    if iface_exists(iface) {
        vec![format!("iface:{iface}")]
    } else {
        Vec::new()
    }
}

fn tproxy_port_available(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok() && UdpSocket::bind(("127.0.0.1", port)).is_ok()
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

fn parse_port(value: &str) -> Result<u16, RunnerOutput> {
    value
        .parse::<u16>()
        .map_err(|err| RunnerOutput::usage(format!("invalid stage39 --tproxy-port: {err}")))
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
