use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use dae_ebpf_support::{map_catalog, pinned_reuse_maps, run_listen_socket_map_fd_smoke};
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_STAGE35_ROOT: &str = "/tmp/dae-stage35-candidate";
const DEFAULT_STAGE35_IFACE: &str = "dae35d0";
const DEFAULT_STAGE35_OBJECT: &str = "control/bpf_bpfel.o";
const DEFAULT_STAGE35_SECTION: &str = "tc/dae0_ingress";
const STAGE35_FILTER_PREF: &str = "49350";

pub(crate) fn run_stage35_real_ebpf_attach_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage35Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage35_report(&opts);
    output_with_execution_status(
        report,
        opts.execute_smoke,
        "real_program_attach_smoke_passed",
    )
}

pub(crate) fn run_stage36_listen_socket_map_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage36Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage36_report(&opts);
    output_with_execution_status(
        report,
        opts.execute_smoke,
        "listen_socket_map_fd_update_smoke_passed",
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
struct Stage35Options {
    root: PathBuf,
    stage31_report: Option<PathBuf>,
    execute_smoke: bool,
    ack_root_gate: bool,
    iface: String,
    object_path: PathBuf,
    section: String,
}

impl Default for Stage35Options {
    fn default() -> Self {
        Self {
            root: PathBuf::from(DEFAULT_STAGE35_ROOT),
            stage31_report: None,
            execute_smoke: false,
            ack_root_gate: false,
            iface: DEFAULT_STAGE35_IFACE.to_owned(),
            object_path: PathBuf::from(DEFAULT_STAGE35_OBJECT),
            section: DEFAULT_STAGE35_SECTION.to_owned(),
        }
    }
}

impl Stage35Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--root" => opts.root = PathBuf::from(next_value(&mut iter, "stage35 --root")?),
                "--stage31-report" => {
                    opts.stage31_report = Some(PathBuf::from(next_value(
                        &mut iter,
                        "stage35 --stage31-report",
                    )?));
                }
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--iface" => opts.iface = next_value(&mut iter, "stage35 --iface")?,
                "--object" => {
                    opts.object_path = PathBuf::from(next_value(&mut iter, "stage35 --object")?);
                }
                "--section" => opts.section = next_value(&mut iter, "stage35 --section")?,
                _ if arg.starts_with("--root=") => {
                    opts.root = PathBuf::from(value_after_equals(arg, "stage35 --root")?);
                }
                _ if arg.starts_with("--stage31-report=") => {
                    opts.stage31_report = Some(PathBuf::from(value_after_equals(
                        arg,
                        "stage35 --stage31-report",
                    )?));
                }
                _ if arg.starts_with("--iface=") => {
                    opts.iface = value_after_equals(arg, "stage35 --iface")?;
                }
                _ if arg.starts_with("--object=") => {
                    opts.object_path = PathBuf::from(value_after_equals(arg, "stage35 --object")?);
                }
                _ if arg.starts_with("--section=") => {
                    opts.section = value_after_equals(arg, "stage35 --section")?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage35-real-ebpf-attach-admission argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn stage35_report(opts: &Stage35Options) -> Value {
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "isolated-root-under-tmp",
        tmp_root_allowed(&opts.root),
        json!({"path": path_string(&opts.root)}),
        &mut blockers,
        "stage35 root must be an absolute /tmp child path",
    );
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !opts.execute_smoke || opts.ack_root_gate,
        json!({"execute_smoke": opts.execute_smoke, "ack_root_gate": opts.ack_root_gate}),
        &mut blockers,
        "stage35 root-gated smoke requires --ack-root-gate",
    );
    push_check(
        &mut checks,
        "temporary-interface-name-valid",
        iface_name_valid(&opts.iface),
        json!({"iface": opts.iface, "max_linux_ifname_len": 15}),
        &mut blockers,
        "stage35 temporary interface name is invalid",
    );
    push_check(
        &mut checks,
        "temporary-interface-not-production",
        opts.iface != "dae0" && opts.iface != "dae0peer",
        json!({"iface": opts.iface}),
        &mut blockers,
        "stage35 cannot target production dae0/dae0peer names",
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
        "stage35 real dae eBPF object is missing",
    );

    let stage31 = read_report(
        opts.stage31_report.as_deref(),
        "filter_cleanup_smoke_passed",
    );
    push_check(
        &mut checks,
        "stage31-filter-cleanup-report-passed",
        !opts.execute_smoke || stage31.passed,
        json!({
            "path": stage31.path.clone(),
            "status": stage31.status,
            "filter_cleanup_smoke_passed": stage31.passed,
            "blockers": stage31.blockers.clone(),
        }),
        &mut blockers,
        "stage35 root-gated smoke requires a passed Stage 31 filter cleanup report",
    );
    if opts.execute_smoke {
        push_check(
            &mut checks,
            "temporary-interface-name-free",
            !iface_exists(&opts.iface),
            json!({"iface": opts.iface}),
            &mut blockers,
            "stage35 temporary interface name already exists",
        );
    }

    let before_pin_snapshot = if opts.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut attach_show = Value::Null;
    let mut real_program_attach_smoke_passed = false;
    if opts.execute_smoke && blockers.is_empty() {
        let result = execute_stage35_smoke(opts);
        executed_steps = result.executed_steps;
        cleanup_steps = result.cleanup_steps;
        attach_show = result.attach_show;
        real_program_attach_smoke_passed = result.passed;
        if !real_program_attach_smoke_passed {
            blockers.push("stage35 real dae eBPF program attach smoke failed".to_owned());
        }
    }
    let after_pin_snapshot = if opts.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let leftovers = iface_leftovers(&opts.iface);
    if opts.execute_smoke && !leftovers.is_empty() {
        blockers.push("stage35 temporary resources remain after cleanup".to_owned());
    }
    let sys_fs_bpf_dae_mutated = before_pin_snapshot != after_pin_snapshot;
    if opts.execute_smoke && sys_fs_bpf_dae_mutated {
        blockers.push("stage35 unexpectedly mutated /sys/fs/bpf/dae".to_owned());
    }

    json!({
        "name": "stage35-real-ebpf-attach-admission",
        "stage": "stage35",
        "evidence_class": "root-gated-real-dae-ebpf-program-attach-smoke",
        "root": path_string(&opts.root),
        "execute_smoke": opts.execute_smoke,
        "root_gate_acknowledged": opts.ack_root_gate,
        "read_only": !opts.execute_smoke,
        "blocked": !blockers.is_empty(),
        "real_program_attach_smoke_passed": real_program_attach_smoke_passed,
        "actual_dae_ebpf_program_attach_executed": opts.execute_smoke && real_program_attach_smoke_passed,
        "production_dae0_dae0peer_attach_executed": false,
        "listen_socket_map_fd_update_smoke_passed": false,
        "production_listen_socket_map_fd_update_executed": false,
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
        "stage31_report": {
            "path": stage31.path,
            "status": stage31.status,
            "passed": stage31.passed,
            "blockers": stage31.blockers,
        },
        "real_program_attach_contract": {
            "object_path": path_string(&opts.object_path),
            "section": opts.section,
            "filter_pref": STAGE35_FILTER_PREF,
            "map_count": map_catalog().len(),
            "pinned_reuse_maps": pinned_reuse_maps(),
            "temporary_iface": opts.iface,
        },
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

struct Stage35SmokeResult {
    passed: bool,
    executed_steps: Vec<Value>,
    cleanup_steps: Vec<Value>,
    attach_show: Value,
}

fn execute_stage35_smoke(opts: &Stage35Options) -> Stage35SmokeResult {
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
        "attach-real-dae-ebpf-program",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "add",
                "dev",
                &opts.iface,
                "ingress",
                "pref",
                STAGE35_FILTER_PREF,
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
        "show-real-dae-ebpf-program-filter",
        CommandSpec::new("tc", &["filter", "show", "dev", &opts.iface, "ingress"]),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-real-dae-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                &opts.iface,
                "ingress",
                "pref",
                STAGE35_FILTER_PREF,
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
    Stage35SmokeResult {
        passed: ok
            && attach_show["status"].as_str() == Some("pass")
            && attach_output.contains(&opts.section)
            && attach_output.contains("tproxy_dae0_ing")
            && iface_leftovers(&opts.iface).is_empty(),
        executed_steps,
        cleanup_steps,
        attach_show,
    }
}

#[derive(Debug, Clone)]
struct Stage36Options {
    stage35_report: Option<PathBuf>,
    execute_smoke: bool,
    ack_root_gate: bool,
}

impl Stage36Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self {
            stage35_report: None,
            execute_smoke: false,
            ack_root_gate: false,
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--stage35-report" => {
                    opts.stage35_report = Some(PathBuf::from(next_value(
                        &mut iter,
                        "stage36 --stage35-report",
                    )?));
                }
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                _ if arg.starts_with("--stage35-report=") => {
                    opts.stage35_report = Some(PathBuf::from(value_after_equals(
                        arg,
                        "stage36 --stage35-report",
                    )?));
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage36-listen-socket-map-admission argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn stage36_report(opts: &Stage36Options) -> Value {
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !opts.execute_smoke || opts.ack_root_gate,
        json!({"execute_smoke": opts.execute_smoke, "ack_root_gate": opts.ack_root_gate}),
        &mut blockers,
        "stage36 root-gated smoke requires --ack-root-gate",
    );
    let stage35 = read_report(
        opts.stage35_report.as_deref(),
        "real_program_attach_smoke_passed",
    );
    push_check(
        &mut checks,
        "stage35-real-program-attach-report-passed",
        !opts.execute_smoke || stage35.passed,
        json!({
            "path": stage35.path.clone(),
            "status": stage35.status,
            "real_program_attach_smoke_passed": stage35.passed,
            "blockers": stage35.blockers.clone(),
        }),
        &mut blockers,
        "stage36 root-gated smoke requires a passed Stage 35 real program attach report",
    );

    let mut smoke = Value::Null;
    let mut smoke_passed = false;
    if opts.execute_smoke && blockers.is_empty() {
        match run_listen_socket_map_fd_smoke() {
            Ok(report) => {
                smoke_passed = true;
                smoke = json!({
                    "status": "pass",
                    "map_type": report.map_type,
                    "key_size": report.key_size,
                    "value_size": report.value_size,
                    "max_entries": report.max_entries,
                    "keys_updated": report.keys_updated,
                    "tcp_listener_fd_observed": report.tcp_listener_fd >= 0,
                    "udp_socket_fd_observed": report.udp_socket_fd >= 0,
                });
            }
            Err(err) => {
                blockers.push(format!(
                    "stage36 Rust listen_socket_map fd update smoke failed: {err}"
                ));
                smoke = json!({
                    "status": "fail",
                    "error": err.to_string(),
                });
            }
        }
    }

    json!({
        "name": "stage36-listen-socket-map-admission",
        "stage": "stage36",
        "evidence_class": "root-gated-rust-temporary-sockmap-listener-fd-smoke",
        "execute_smoke": opts.execute_smoke,
        "root_gate_acknowledged": opts.ack_root_gate,
        "read_only": !opts.execute_smoke,
        "blocked": !blockers.is_empty(),
        "listen_socket_map_fd_update_smoke_passed": smoke_passed,
        "temporary_sockmap_fd_update_executed": opts.execute_smoke && smoke_passed,
        "production_listen_socket_map_fd_update_executed": false,
        "production_dae0_dae0peer_attach_executed": false,
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
        "stage35_report": {
            "path": stage35.path,
            "status": stage35.status,
            "passed": stage35.passed,
            "blockers": stage35.blockers,
        },
        "temporary_sockmap_smoke": smoke,
        "listen_socket_map_contract": {
            "production_map_name": "listen_socket_map",
            "map_type": "SockMap",
            "key_size": 4,
            "value_size": 8,
            "max_entries": 2,
            "listener_keys": [0, 1],
            "go_reference_updates_tcp_and_udp_listener_fds": true,
            "production_listener_handoff_deferred": true,
        },
        "remaining_blockers": remaining_blockers(),
    })
}

fn remaining_blockers() -> Vec<&'static str> {
    vec![
        "production dae0/dae0peer attach path is not executed",
        "production listen_socket_map update with TCP/UDP listener fds is not executed",
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
