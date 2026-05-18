use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::runner::RunnerOutput;
use crate::validate_config_text;

const DEFAULT_ROOT: &str = "/tmp/dae-stage26-candidate";
const DEFAULT_ARTIFACT_BINARY: &str = "rust/target/debug/dae-cli-optin";
const TPROXY_PORT: u16 = 12346;
const SO_MARK: u32 = 2234;
const MPTCP: bool = true;
const LAN_IFACE: &str = "daex26lan0";
const WAN_IFACE: &str = "daex26wan0";
const CLIENT_IFACE: &str = "daex26cli0";
const CLIENT_NETNS: &str = "dae-stage26-client";
const DNS_BIND: &str = "udp://127.0.0.1:1153";
const DNS_UPSTREAM: &str = "udp://127.0.0.1:11530";

pub(crate) fn run_stage26_candidate_plan(args: &[String]) -> RunnerOutput {
    let mut root = DEFAULT_ROOT.to_owned();
    let mut artifact_binary = DEFAULT_ARTIFACT_BINARY.to_owned();
    let mut write = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return RunnerOutput::usage("missing runtime stage26-candidate-plan --root");
                };
                root = value.to_owned();
            }
            "--artifact-binary" => {
                let Some(value) = iter.next() else {
                    return RunnerOutput::usage(
                        "missing runtime stage26-candidate-plan --artifact-binary",
                    );
                };
                artifact_binary = value.to_owned();
            }
            "--write" => write = true,
            _ if arg.starts_with("--root=") => {
                root = arg
                    .split_once('=')
                    .map(|(_, value)| value.to_owned())
                    .unwrap_or_default();
            }
            _ if arg.starts_with("--artifact-binary=") => {
                artifact_binary = arg
                    .split_once('=')
                    .map(|(_, value)| value.to_owned())
                    .unwrap_or_default();
            }
            _ => {
                return RunnerOutput::usage(format!(
                    "unsupported runtime stage26-candidate-plan argument: {arg}"
                ));
            }
        }
    }

    let root_path = match temp_root(&root) {
        Ok(path) => path,
        Err(output) => return output,
    };
    let layout = CandidatePlanLayout::new(root_path);
    let config_text = minimal_config_text();
    if let Err(err) = validate_config_text(&config_text) {
        return RunnerOutput::stdout_error(format!("generated config is invalid: {err}"));
    }

    let mut files_written = Vec::new();
    if write {
        if let Err(err) =
            write_candidate_plan_files(&layout, &config_text, &artifact_binary, &mut files_written)
        {
            return RunnerOutput::stdout_error(format!("write stage26 candidate plan: {err}"));
        }
    }

    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "stage26-true-rust-daemon-candidate-plan",
            "stage": "stage26",
            "evidence_class": "opt-in-candidate-plan",
            "default_switch_allowed": false,
            "default_path_mutated": false,
            "candidate_live_run_allowed": false,
            "live_daemon_started": false,
            "go_default_path_preserved": true,
            "go_fallback_required": true,
            "write_requested": write,
            "files_written": files_written,
            "config_valid": true,
            "root": layout.root_string(),
            "candidate": {
                "artifact_binary": artifact_binary,
                "artifact_class": "opt-in helper or future Rust daemon candidate; not a default dae run replacement",
                "current_default_owner": "Go-backed dae run",
                "rust_default_daemon_admitted": false,
                "requires_explicit_selector": true,
                "starts_daemon": false,
            },
            "selector_contract": {
                "accepted_selector": "dae-cli-optin runtime stage26-candidate-plan",
                "planned_run_selector": "dae-cli-optin runtime stage26-run-candidate --root <tmp> --artifact-binary <candidate>",
                "default_alias_forbidden": true,
                "implicit_env_switch_forbidden": true,
                "go_fallback_selector_required": true,
                "product_chain_switch_forbidden": true,
            },
            "inventory": inventory_rows(),
            "paths": {
                "root": layout.root_string(),
                "config": layout.config_string(),
                "readme": layout.readme_string(),
                "run_dir": layout.run_dir_string(),
                "log_file": layout.log_file_string(),
                "candidate_pid_file": layout.candidate_pid_file_string(),
                "candidate_progress_file": layout.candidate_progress_file_string(),
                "traffic_dir": layout.traffic_dir_string(),
                "socket_dir": layout.socket_dir_string(),
                "asset_dir": layout.asset_dir_string(),
                "cache_dir": layout.cache_dir_string(),
                "go_progress_file_fixed": "/var/run/dae.progress",
                "go_pid_file_default": "/var/run/dae.pid",
            },
            "minimum_config": {
                "text": config_text,
                "tproxy_port": TPROXY_PORT,
                "so_mark_from_dae": SO_MARK,
                "mptcp": MPTCP,
                "lan_interface": LAN_IFACE,
                "wan_interface": WAN_IFACE,
                "client_interface": CLIENT_IFACE,
                "client_netns": CLIENT_NETNS,
                "auto_config_kernel_parameter": false,
                "disable_waiting_network": true,
                "dns_bind": DNS_BIND,
                "dns_upstream": DNS_UPSTREAM,
                "routing_fallback": "must_direct",
            },
            "production_safety": {
                "no_systemd_mutation": true,
                "no_install_mutation": true,
                "no_release_label_mutation": true,
                "no_daewing_daed_default_mutation": true,
                "uses_tmp_root_only": true,
                "writes_only_when_requested": true,
                "does_not_start_daemon": true,
                "requires_progress_override_before_candidate_live_run": true,
            },
            "go_baseline_commands": go_baseline_commands(&layout),
            "candidate_commands": candidate_commands(&layout),
            "remaining_blockers": [
                "this helper records selector and layout only; it does not implement or start a true Rust daemon candidate",
                "Go dae run still owns the default daemon path",
                "candidate live run requires a progress file override or exclusive host before it can be admitted",
                "matched Go-vs-Rust default daemon benchmark is still missing",
                "outbound true dataplane admission is still incomplete",
                "dae-wing and daed clean product-chain recertification is still missing"
            ],
        })
    ))
}

struct CandidatePlanLayout {
    root: PathBuf,
    config: PathBuf,
    readme: PathBuf,
    run_dir: PathBuf,
    log_file: PathBuf,
    candidate_pid_file: PathBuf,
    candidate_progress_file: PathBuf,
    traffic_dir: PathBuf,
    socket_dir: PathBuf,
    asset_dir: PathBuf,
    cache_dir: PathBuf,
}

impl CandidatePlanLayout {
    fn new(root: PathBuf) -> Self {
        let run_dir = root.join("run");
        let traffic_dir = root.join("traffic");
        let socket_dir = root.join("sockets");
        let asset_dir = root.join("assets");
        let cache_dir = root.join("cache");
        Self {
            config: root.join("config.dae"),
            readme: root.join("README.stage26-candidate.txt"),
            log_file: root.join("logs").join("dae.log"),
            candidate_pid_file: run_dir.join("dae-stage26.pid"),
            candidate_progress_file: run_dir.join("dae-stage26.progress"),
            run_dir,
            traffic_dir,
            socket_dir,
            asset_dir,
            cache_dir,
            root,
        }
    }

    fn root_string(&self) -> String {
        path_string(&self.root)
    }

    fn config_string(&self) -> String {
        path_string(&self.config)
    }

    fn readme_string(&self) -> String {
        path_string(&self.readme)
    }

    fn run_dir_string(&self) -> String {
        path_string(&self.run_dir)
    }

    fn log_file_string(&self) -> String {
        path_string(&self.log_file)
    }

    fn candidate_pid_file_string(&self) -> String {
        path_string(&self.candidate_pid_file)
    }

    fn candidate_progress_file_string(&self) -> String {
        path_string(&self.candidate_progress_file)
    }

    fn traffic_dir_string(&self) -> String {
        path_string(&self.traffic_dir)
    }

    fn socket_dir_string(&self) -> String {
        path_string(&self.socket_dir)
    }

    fn asset_dir_string(&self) -> String {
        path_string(&self.asset_dir)
    }

    fn cache_dir_string(&self) -> String {
        path_string(&self.cache_dir)
    }
}

fn temp_root(root: &str) -> Result<PathBuf, RunnerOutput> {
    let root = PathBuf::from(root);
    if !root.is_absolute() {
        return Err(RunnerOutput::stdout_error(
            "stage26 candidate root must be an absolute /tmp path",
        ));
    }
    let root_string = path_string(&root);
    if root_string == "/tmp" || !root_string.starts_with("/tmp/") {
        return Err(RunnerOutput::stdout_error(
            "stage26 candidate root must stay under /tmp to avoid production mutation",
        ));
    }
    Ok(root)
}

fn write_candidate_plan_files(
    layout: &CandidatePlanLayout,
    config_text: &str,
    artifact_binary: &str,
    files_written: &mut Vec<String>,
) -> std::io::Result<()> {
    fs::create_dir_all(&layout.run_dir)?;
    fs::create_dir_all(layout.log_file.parent().unwrap_or(&layout.root))?;
    fs::create_dir_all(&layout.traffic_dir)?;
    fs::create_dir_all(&layout.socket_dir)?;
    fs::create_dir_all(&layout.asset_dir)?;
    fs::create_dir_all(&layout.cache_dir)?;
    fs::write(&layout.config, config_text)?;
    set_private_file_mode(&layout.config)?;
    files_written.push(layout.config_string());
    fs::write(&layout.readme, readme_text(layout, artifact_binary))?;
    files_written.push(layout.readme_string());
    Ok(())
}

#[cfg(unix)]
fn set_private_file_mode(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_file_mode(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn minimal_config_text() -> String {
    format!(
        "global {{\n    tproxy_port: {TPROXY_PORT}\n    so_mark_from_dae: {SO_MARK}\n    mptcp: {MPTCP}\n    lan_interface: {LAN_IFACE}\n    wan_interface: {WAN_IFACE}\n    auto_config_kernel_parameter: false\n    disable_waiting_network: true\n    log_level: debug\n}}\n\ndns {{\n    bind: '{DNS_BIND}'\n    upstream {{\n        local_udp: '{DNS_UPSTREAM}'\n    }}\n    routing {{\n        request {{\n            fallback: local_udp\n        }}\n        response {{\n            fallback: accept\n        }}\n    }}\n}}\n\nnode {{}}\ngroup {{}}\nrouting {{\n    fallback: must_direct\n}}\n"
    )
}

fn inventory_rows() -> Vec<serde_json::Value> {
    vec![
        json!({
            "name": "dae-cli-optin",
            "status": "present-helper-not-default-daemon",
            "evidence": "rust/crates/dae-cli/src/bin/dae-cli-optin.rs exists and dispatches opt-in helper commands",
            "next_action": "keep helper explicit and do not alias it to dae run"
        }),
        json!({
            "name": "dae-engine",
            "status": "present-runtime-facade",
            "evidence": "dae-engine provides dry runtime, RuntimeOverview, and route-aware target helpers used by previous stages",
            "next_action": "connect candidate lifecycle only after isolated selector and baseline records exist"
        }),
        json!({
            "name": "dae-control dae-datapath dae-dns",
            "status": "present-partial-owner-building-blocks",
            "evidence": "workspace contains control, datapath, and DNS crates, but Stage 25 still blocks owner swap and default traffic",
            "next_action": "admit owner, TCP, UDP, DNS, and kernel rows separately"
        }),
        json!({
            "name": "dae-outbound",
            "status": "present-not-fully-true-default-dataplane",
            "evidence": "protocol and transport helpers exist, but outbound true dataplane admission remains a Stage 25 blocker",
            "next_action": "finish protocol live traffic, reload cleanup, benchmark, and rollback rows before daemon admission"
        }),
        json!({
            "name": "Makefile dae release systemd",
            "status": "go-default-preserved",
            "evidence": "make dae, release workflows, and install/dae.service still target the Go-backed dae run path",
            "next_action": "leave packaging and service defaults untouched until true Rust daemon admission passes"
        }),
    ]
}

fn go_baseline_commands(layout: &CandidatePlanLayout) -> Vec<serde_json::Value> {
    vec![
        json!({
            "name": "build-go-default-artifact",
            "status": "planned-not-run",
            "command": "PATH=/root/.local/go1.25.9/bin:$PATH GOWORK=off OUTPUT=/tmp/dae-stage26-go-baseline/dae make dae",
            "side_effect": "writes a temporary Go baseline artifact outside install paths"
        }),
        json!({
            "name": "go-version-baseline",
            "status": "planned-not-run",
            "command": "/tmp/dae-stage26-go-baseline/dae --version",
            "side_effect": "read-only version output"
        }),
        json!({
            "name": "go-validate-baseline",
            "status": "planned-not-run",
            "command": format!("/tmp/dae-stage26-go-baseline/dae validate -c {}", layout.config_string()),
            "side_effect": "read-only config validation"
        }),
        json!({
            "name": "go-export-outline-baseline",
            "status": "planned-not-run",
            "command": "/tmp/dae-stage26-go-baseline/dae export outline",
            "side_effect": "read-only config outline export"
        }),
    ]
}

fn candidate_commands(layout: &CandidatePlanLayout) -> Vec<serde_json::Value> {
    vec![
        json!({
            "name": "write-isolated-layout",
            "status": "ready-with-write-flag",
            "command": format!("dae-cli-optin runtime stage26-candidate-plan --root {} --write", layout.root_string()),
            "side_effect": "writes only under the /tmp candidate root"
        }),
        json!({
            "name": "candidate-validate",
            "status": "planned-not-run",
            "command": format!("{DEFAULT_ARTIFACT_BINARY} validate -c {}", layout.config_string()),
            "side_effect": "read-only config validation through explicit artifact path"
        }),
        json!({
            "name": "candidate-run",
            "status": "blocked-unimplemented",
            "command": format!("{DEFAULT_ARTIFACT_BINARY} runtime stage26-run-candidate --root {} --config {} --pid-file {} --progress-file {} --logfile {}", layout.root_string(), layout.config_string(), layout.candidate_pid_file_string(), layout.candidate_progress_file_string(), layout.log_file_string()),
            "side_effect": "future candidate run must stay under the /tmp root and must not touch systemd"
        }),
        json!({
            "name": "cleanup-isolated-layout",
            "status": "planned-not-run",
            "command": format!("ip netns del {CLIENT_NETNS} 2>/dev/null || true; ip link del {LAN_IFACE} 2>/dev/null || true; ip link del {WAN_IFACE} 2>/dev/null || true; rm -rf {}", layout.root_string()),
            "side_effect": "removes temporary netns, interfaces, and files"
        }),
    ]
}

fn readme_text(layout: &CandidatePlanLayout, artifact_binary: &str) -> String {
    format!(
        "Stage 26 true Rust daemon candidate plan\n\nRoot: {}\nConfig: {}\nArtifact: {}\n\nThis helper records selector semantics and isolated paths only. It does not start dae, does not modify systemd, and does not switch dae run away from the Go-backed default.\n",
        layout.root_string(),
        layout.config_string(),
        artifact_binary
    )
}

fn path_string(path: &Path) -> String {
    path.as_os_str().to_string_lossy().into_owned()
}
