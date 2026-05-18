use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use dae_control::{CoreFlip, ReloadCoreState};
use dae_ebpf_support::{
    DaeParamInput, PinnedMapAction, build_dae_param, map_catalog, pinned_map_action,
    pinned_reuse_maps,
};
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_ROOT: &str = "/tmp/dae-stage30-candidate";
const DEFAULT_NETNS: &str = "dae-stage30-ns";
const DEFAULT_HOST_IFACE: &str = "dae30h0";
const DEFAULT_PEER_IFACE: &str = "dae30p0";

#[derive(Debug, Clone)]
struct Stage30Options {
    root: PathBuf,
    preflight_report: Option<PathBuf>,
    execute_smoke: bool,
    ack_root_gate: bool,
    netns: String,
    host_iface: String,
    peer_iface: String,
}

impl Default for Stage30Options {
    fn default() -> Self {
        Self {
            root: PathBuf::from(DEFAULT_ROOT),
            preflight_report: None,
            execute_smoke: false,
            ack_root_gate: false,
            netns: DEFAULT_NETNS.to_owned(),
            host_iface: DEFAULT_HOST_IFACE.to_owned(),
            peer_iface: DEFAULT_PEER_IFACE.to_owned(),
        }
    }
}

pub(crate) fn run_stage30_attach_cleanup(args: &[String]) -> RunnerOutput {
    let opts = match parse_args(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage30_attach_cleanup_report(&opts);
    let status = report["smoke_passed"].as_bool().unwrap_or(false);
    let blocked = report["blocked"].as_bool().unwrap_or(false);
    let output = format!("{report}\n");
    if opts.execute_smoke && (blocked || !status) {
        RunnerOutput::stdout_error(output.trim_end())
    } else {
        RunnerOutput::ok(output)
    }
}

fn parse_args(args: &[String]) -> Result<Stage30Options, RunnerOutput> {
    let mut opts = Stage30Options::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => opts.root = PathBuf::from(next_value(&mut iter, "stage30 --root")?),
            "--preflight-report" => {
                opts.preflight_report = Some(PathBuf::from(next_value(
                    &mut iter,
                    "stage30 --preflight-report",
                )?));
            }
            "--execute-smoke" => opts.execute_smoke = true,
            "--ack-root-gate" => opts.ack_root_gate = true,
            "--netns" => opts.netns = next_value(&mut iter, "stage30 --netns")?,
            "--host-iface" => {
                opts.host_iface = next_value(&mut iter, "stage30 --host-iface")?;
            }
            "--peer-iface" => {
                opts.peer_iface = next_value(&mut iter, "stage30 --peer-iface")?;
            }
            _ if arg.starts_with("--root=") => {
                opts.root = PathBuf::from(value_after_equals(arg, "stage30 --root")?);
            }
            _ if arg.starts_with("--preflight-report=") => {
                opts.preflight_report = Some(PathBuf::from(value_after_equals(
                    arg,
                    "stage30 --preflight-report",
                )?));
            }
            _ if arg.starts_with("--netns=") => {
                opts.netns = value_after_equals(arg, "stage30 --netns")?;
            }
            _ if arg.starts_with("--host-iface=") => {
                opts.host_iface = value_after_equals(arg, "stage30 --host-iface")?;
            }
            _ if arg.starts_with("--peer-iface=") => {
                opts.peer_iface = value_after_equals(arg, "stage30 --peer-iface")?;
            }
            _ => {
                return Err(RunnerOutput::usage(format!(
                    "unsupported runtime stage30-attach-cleanup argument: {arg}"
                )));
            }
        }
    }
    Ok(opts)
}

fn stage30_attach_cleanup_report(opts: &Stage30Options) -> Value {
    let mut blockers = Vec::new();
    let mut checks = Vec::new();

    push_check(
        &mut checks,
        "isolated-root-under-tmp",
        tmp_root_allowed(&opts.root),
        json!({"path": path_string(&opts.root)}),
        &mut blockers,
        "stage30 root must be an absolute /tmp child path",
    );
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !opts.execute_smoke || opts.ack_root_gate,
        json!({"execute_smoke": opts.execute_smoke, "ack_root_gate": opts.ack_root_gate}),
        &mut blockers,
        "root-gated smoke requires --ack-root-gate",
    );
    push_check(
        &mut checks,
        "temporary-interface-names-valid",
        iface_name_valid(&opts.host_iface) && iface_name_valid(&opts.peer_iface),
        json!({
            "host_iface": opts.host_iface,
            "peer_iface": opts.peer_iface,
            "max_linux_ifname_len": 15,
        }),
        &mut blockers,
        "temporary interface name is invalid",
    );
    push_check(
        &mut checks,
        "temporary-names-not-production",
        opts.host_iface != "dae0" && opts.peer_iface != "dae0peer" && opts.netns != "daens",
        json!({"host_iface": opts.host_iface, "peer_iface": opts.peer_iface, "netns": opts.netns}),
        &mut blockers,
        "stage30 cannot target production dae0/dae0peer/daens names",
    );
    for tool in ["ip", "tc", "sysctl"] {
        push_check(
            &mut checks,
            match tool {
                "ip" => "tool-ip-available",
                "tc" => "tool-tc-available",
                _ => "tool-sysctl-available",
            },
            command_exists(tool),
            json!({"tool": tool}),
            &mut blockers,
            "required host tool is missing",
        );
    }

    let preflight = read_preflight_report(opts.preflight_report.as_deref());
    push_check(
        &mut checks,
        "stage29-preflight-report-passed",
        !opts.execute_smoke || preflight.passed,
        json!({
            "path": preflight.path.clone(),
            "status": preflight.status,
            "preflight_passed": preflight.passed,
            "blockers": preflight.blockers.clone(),
        }),
        &mut blockers,
        "executed attach cleanup smoke requires a passed Stage 29 preflight report",
    );

    if opts.execute_smoke {
        push_check(
            &mut checks,
            "temporary-netns-name-free",
            !netns_exists(&opts.netns),
            json!({"netns": opts.netns}),
            &mut blockers,
            "temporary netns name already exists",
        );
        push_check(
            &mut checks,
            "temporary-host-interface-name-free",
            !iface_exists(&opts.host_iface),
            json!({"host_iface": opts.host_iface, "path": format!("/sys/class/net/{}", opts.host_iface)}),
            &mut blockers,
            "temporary host interface name already exists",
        );
    }

    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut smoke_passed = false;
    if opts.execute_smoke && blockers.is_empty() {
        let result = execute_smoke(opts);
        executed_steps = result.executed_steps;
        cleanup_steps = result.cleanup_steps;
        smoke_passed = result.smoke_passed;
        if !smoke_passed {
            blockers.push("stage30 root-gated attach cleanup smoke failed".to_owned());
        }
    }
    let leftovers = resource_leftovers(opts);
    if opts.execute_smoke && !leftovers.is_empty() {
        blockers.push("stage30 temporary resources remain after cleanup".to_owned());
    }

    let param = build_dae_param(DaeParamInput {
        tproxy_port: 12346,
        control_plane_pid: 4242,
        dae0_ifindex: 17,
        dae_netns_id: 23,
        dae0peer_mac: [2, 0, 0, 0, 0, 1],
        has_bpf_get_current_task: true,
    });
    let mut flip = CoreFlip::default();
    let mut fresh = ReloadCoreState::new(false, &mut flip);
    fresh.eject_bpf();
    fresh.inject_bpf();
    let mut reload = ReloadCoreState::new(true, &mut flip);
    reload.eject_bpf();
    let attach_order = vec![
        "stage29 preflight report must pass",
        "acknowledge root gate explicitly",
        "create temporary netns",
        "create temporary veth pair",
        "move peer into temporary netns",
        "bring host and peer links up",
        "write temporary netns sysctl",
        "attach clsact qdisc to temporary host link",
        "remove clsact qdisc",
        "delete temporary host link",
        "delete temporary netns",
        "verify no temporary resource leftovers",
    ];
    let ebpf_contract = json!({
        "map_count": map_catalog().len(),
        "pinned_reuse_maps": pinned_reuse_maps(),
        "listen_socket_map_keys": [0, 1],
        "tproxy_port_big_endian": param.tproxy_port,
        "incompatible_pinned_map_action": pinned_action_json(),
        "dae_program_attach_deferred": true,
    });
    let reload_ownership_contract = json!({
        "fresh_after_eject_inject_bpf_ejected": fresh.bpf_ejected,
        "reload_after_eject_bpf_ejected": reload.bpf_ejected,
        "reload_rollback_requires_old_bpf_inject": true,
        "dns_cache_snapshot_required": true,
    });
    let production_safety = json!({
        "uses_temporary_netns": true,
        "uses_temporary_veth": true,
        "no_daemon_start": true,
        "no_systemd_mutation": true,
        "no_install_mutation": true,
        "no_release_label_mutation": true,
        "no_daewing_daed_default_mutation": true,
        "no_var_run_mutation": true,
        "no_production_dae0_mutation": true,
        "no_production_daens_mutation": true,
        "no_sys_fs_bpf_dae_mutation": true,
    });
    let remaining_blockers = vec![
        "actual dae eBPF program attach to dae0/dae0peer is not executed in Stage 30",
        "listen socket map update with TCP/UDP listener fds is not executed in Stage 30",
        "active TCP UDP DNS traffic evidence is still missing",
        "outbound true dataplane admission is still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing",
    ];

    json!({
        "name": "stage30-root-gated-attach-cleanup-smoke",
        "stage": "stage30",
        "evidence_class": "root-gated-netns-sysctl-tc-attach-cleanup-smoke",
        "root": path_string(&opts.root),
        "execute_smoke": opts.execute_smoke,
        "root_gate_acknowledged": opts.ack_root_gate,
        "read_only": !opts.execute_smoke,
        "blocked": !blockers.is_empty(),
        "smoke_passed": smoke_passed,
        "live_candidate_run_allowed": false,
        "live_daemon_started": false,
        "actual_dae_ebpf_program_attach_executed": false,
        "tc_attach_cleanup_executed": opts.execute_smoke && smoke_passed,
        "netns_sysctl_cleanup_executed": opts.execute_smoke && smoke_passed,
        "active_traffic_evidence_recorded": false,
        "default_switch_allowed": false,
        "default_path_mutated": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "blockers": blockers,
        "checks": checks,
        "preflight_report": {
            "path": preflight.path,
            "status": preflight.status,
            "preflight_passed": preflight.passed,
            "blockers": preflight.blockers,
        },
        "temporary_resources": {
            "netns": opts.netns,
            "host_iface": opts.host_iface,
            "peer_iface": opts.peer_iface,
            "leftovers_after_cleanup": leftovers,
        },
        "attach_order": attach_order,
        "executed_steps": executed_steps,
        "cleanup_steps": cleanup_steps,
        "ebpf_contract": ebpf_contract,
        "reload_ownership_contract": reload_ownership_contract,
        "production_safety": production_safety,
        "remaining_blockers": remaining_blockers,
    })
}

struct PreflightReport {
    path: Option<String>,
    status: &'static str,
    passed: bool,
    blockers: Vec<Value>,
}

fn read_preflight_report(path: Option<&Path>) -> PreflightReport {
    let Some(path) = path else {
        return PreflightReport {
            path: None,
            status: "not-provided",
            passed: false,
            blockers: Vec::new(),
        };
    };
    let path_text = path_string(path);
    let Ok(content) = fs::read_to_string(path) else {
        return PreflightReport {
            path: Some(path_text),
            status: "read-error",
            passed: false,
            blockers: Vec::new(),
        };
    };
    let Ok(json) = serde_json::from_str::<Value>(&content) else {
        return PreflightReport {
            path: Some(path_text),
            status: "parse-error",
            passed: false,
            blockers: Vec::new(),
        };
    };
    let blockers = json["blockers"].as_array().cloned().unwrap_or_default();
    PreflightReport {
        path: Some(path_text),
        status: "loaded",
        passed: json["preflight_passed"].as_bool().unwrap_or(false),
        blockers,
    }
}

struct SmokeResult {
    smoke_passed: bool,
    executed_steps: Vec<Value>,
    cleanup_steps: Vec<Value>,
}

fn execute_smoke(opts: &Stage30Options) -> SmokeResult {
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut ok = true;

    ok &= run_step(
        &mut executed_steps,
        "create-temporary-netns",
        CommandSpec::new("ip", &["netns", "add", &opts.netns]),
    );
    ok &= run_step(
        &mut executed_steps,
        "create-temporary-veth",
        CommandSpec::new(
            "ip",
            &[
                "link",
                "add",
                &opts.host_iface,
                "type",
                "veth",
                "peer",
                "name",
                &opts.peer_iface,
            ],
        ),
    );
    ok &= run_step(
        &mut executed_steps,
        "move-peer-into-netns",
        CommandSpec::new(
            "ip",
            &["link", "set", &opts.peer_iface, "netns", &opts.netns],
        ),
    );
    ok &= run_step(
        &mut executed_steps,
        "bring-host-link-up",
        CommandSpec::new("ip", &["link", "set", &opts.host_iface, "up"]),
    );
    ok &= run_step(
        &mut executed_steps,
        "bring-netns-loopback-up",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                &opts.netns,
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
        "bring-netns-peer-up",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                &opts.netns,
                "ip",
                "link",
                "set",
                &opts.peer_iface,
                "up",
            ],
        ),
    );
    ok &= run_step(
        &mut executed_steps,
        "write-temporary-netns-sysctl",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                &opts.netns,
                "sysctl",
                "-w",
                "net.ipv4.ip_forward=1",
            ],
        ),
    );
    ok &= run_step(
        &mut executed_steps,
        "attach-temporary-clsact-qdisc",
        CommandSpec::new("tc", &["qdisc", "add", "dev", &opts.host_iface, "clsact"]),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-temporary-clsact-qdisc",
        CommandSpec::new("tc", &["qdisc", "del", "dev", &opts.host_iface, "clsact"]),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-temporary-host-link",
        CommandSpec::new("ip", &["link", "del", &opts.host_iface]),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-temporary-netns",
        CommandSpec::new("ip", &["netns", "del", &opts.netns]),
    );

    SmokeResult {
        smoke_passed: ok && resource_leftovers(opts).is_empty(),
        executed_steps,
        cleanup_steps,
    }
}

struct CommandSpec<'a> {
    program: &'a str,
    args: &'a [&'a str],
}

impl<'a> CommandSpec<'a> {
    fn new(program: &'a str, args: &'a [&'a str]) -> Self {
        Self { program, args }
    }
}

fn run_step(steps: &mut Vec<Value>, name: &'static str, command: CommandSpec<'_>) -> bool {
    let output = Command::new(command.program).args(command.args).output();
    match output {
        Ok(output) => {
            let status = output.status.success();
            steps.push(json!({
                "name": name,
                "command": std::iter::once(command.program).chain(command.args.iter().copied()).collect::<Vec<_>>().join(" "),
                "status": if status { "pass" } else { "fail" },
                "exit_code": output.status.code(),
                "stdout": String::from_utf8_lossy(&output.stdout).trim(),
                "stderr": String::from_utf8_lossy(&output.stderr).trim(),
            }));
            status
        }
        Err(err) => {
            steps.push(json!({
                "name": name,
                "command": std::iter::once(command.program).chain(command.args.iter().copied()).collect::<Vec<_>>().join(" "),
                "status": "error",
                "error": err.to_string(),
            }));
            false
        }
    }
}

fn pinned_action_json() -> Value {
    match pinned_map_action("use pinned map routing_tuples_map: key size mismatch") {
        PinnedMapAction::DeleteAndRetry { map_name } => {
            json!({"action": "delete_and_retry", "map": map_name})
        }
        PinnedMapAction::ReturnError => json!({"action": "return_error"}),
    }
}

fn push_check(
    checks: &mut Vec<Value>,
    name: &'static str,
    pass: bool,
    detail: Value,
    blockers: &mut Vec<String>,
    blocker: &'static str,
) {
    if !pass {
        blockers.push(blocker.to_owned());
    }
    checks.push(json!({
        "name": name,
        "status": if pass { "pass" } else { "block" },
        "detail": detail,
        "blocker": if pass { Value::Null } else { json!(blocker) },
    }));
}

fn command_exists(program: &str) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path).any(|dir| dir.join(program).is_file())
}

fn tmp_root_allowed(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let value = path_string(path);
    value != "/tmp" && value.starts_with("/tmp/")
}

fn iface_name_valid(name: &str) -> bool {
    !name.is_empty() && name.len() <= 15
}

fn iface_exists(name: &str) -> bool {
    PathBuf::from("/sys/class/net").join(name).exists()
}

fn netns_exists(name: &str) -> bool {
    ["/var/run/netns", "/run/netns"]
        .into_iter()
        .any(|parent| PathBuf::from(parent).join(name).exists())
}

fn resource_leftovers(opts: &Stage30Options) -> Vec<Value> {
    let mut leftovers = Vec::new();
    if iface_exists(&opts.host_iface) {
        leftovers.push(json!({"kind": "interface", "name": opts.host_iface}));
    }
    if iface_exists(&opts.peer_iface) {
        leftovers.push(json!({"kind": "interface", "name": opts.peer_iface}));
    }
    for parent in ["/var/run/netns", "/run/netns"] {
        let path = PathBuf::from(parent).join(&opts.netns);
        if path.exists() {
            leftovers
                .push(json!({"kind": "netns", "name": opts.netns, "path": path_string(&path)}));
        }
    }
    leftovers
}

fn next_value(
    iter: &mut std::slice::Iter<'_, String>,
    name: &'static str,
) -> Result<String, RunnerOutput> {
    iter.next()
        .cloned()
        .ok_or_else(|| RunnerOutput::usage(format!("missing runtime {name}")))
}

fn value_after_equals(arg: &str, name: &'static str) -> Result<String, RunnerOutput> {
    arg.split_once('=')
        .map(|(_, value)| value.to_owned())
        .ok_or_else(|| RunnerOutput::usage(format!("missing runtime {name}")))
}

fn path_string(path: &Path) -> String {
    path.as_os_str().to_string_lossy().into_owned()
}
