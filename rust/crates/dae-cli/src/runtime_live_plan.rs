use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::runner::RunnerOutput;
use crate::validate_config_text;

const DEFAULT_ROOT: &str = "/tmp/dae-stage22-live";
const ARTIFACT_BINARY: &str = "/tmp/dae-stage22-live-evidence";
const TPROXY_PORT: u16 = 12345;
const SO_MARK: u32 = 1234;
const MPTCP: bool = true;
const LAN_IFACE: &str = "daex22lan0";
const WAN_IFACE: &str = "daex22wan0";
const CLIENT_IFACE: &str = "daex22cli0";
const CLIENT_NETNS: &str = "dae-stage22-client";
const DNS_BIND: &str = "udp://127.0.0.1:1053";
const DNS_UPSTREAM: &str = "udp://127.0.0.1:10530";

pub(crate) fn run_stage22_live_plan(args: &[String]) -> RunnerOutput {
    let mut root = DEFAULT_ROOT.to_owned();
    let mut write = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return RunnerOutput::usage("missing runtime stage22-live-plan --root");
                };
                root = value.to_owned();
            }
            "--write" => write = true,
            _ if arg.starts_with("--root=") => {
                root = arg
                    .split_once('=')
                    .map(|(_, value)| value.to_owned())
                    .unwrap_or_default();
            }
            _ => {
                return RunnerOutput::usage(format!(
                    "unsupported runtime stage22-live-plan argument: {arg}"
                ));
            }
        }
    }

    let root_path = match temp_root(&root) {
        Ok(path) => path,
        Err(output) => return output,
    };
    let layout = LivePlanLayout::new(root_path);
    let config_text = minimal_config_text();
    if let Err(err) = validate_config_text(&config_text) {
        return RunnerOutput::stdout_error(format!("generated config is invalid: {err}"));
    }

    let mut files_written = Vec::new();
    if write {
        if let Err(err) = write_live_plan_files(&layout, &config_text, &mut files_written) {
            return RunnerOutput::stdout_error(format!("write stage22 live plan: {err}"));
        }
    }

    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "stage22-isolated-live-smoke-plan",
            "evidence_class": "isolated-live-plan-helper",
            "default_switch_allowed": false,
            "default_path_mutated": false,
            "live_daemon_started": false,
            "files_written": files_written,
            "write_requested": write,
            "config_valid": true,
            "root": layout.root_string(),
            "paths": {
                "artifact_binary": ARTIFACT_BINARY,
                "root": layout.root_string(),
                "config": layout.config_string(),
                "readme": layout.readme_string(),
                "run_dir": layout.run_dir_string(),
                "log_file": layout.log_file_string(),
                "helper_pid_file": layout.helper_pid_file_string(),
                "traffic_dir": layout.traffic_dir_string(),
                "socket_dir": layout.socket_dir_string(),
                "go_progress_file_fixed": "/var/run/dae.progress",
                "go_pid_file_disabled": true,
            },
            "minimum_config": {
                "text": config_text,
                "tproxy_port": TPROXY_PORT,
                "so_mark_from_dae": SO_MARK,
                "mptcp": MPTCP,
                "lan_interface": LAN_IFACE,
                "wan_interface": WAN_IFACE,
                "auto_config_kernel_parameter": false,
                "disable_waiting_network": true,
                "dns_bind": DNS_BIND,
                "dns_upstream": DNS_UPSTREAM,
                "routing_fallback": "must_direct",
            },
            "production_safety": {
                "no_systemd_mutation": true,
                "use_tmp_artifact_binary": true,
                "disable_pidfile": true,
                "logfile_under_root": true,
                "progress_file_fixed_path_blocker": true,
                "requires_exclusive_host_or_progress_override_before_live_run": true,
            },
            "commands": live_plan_commands(&layout),
            "traffic_matrix": [
                {
                    "name": "tcp-mark-mptcp",
                    "status": "planned",
                    "required_observation": "active TCP dial uses MagicNetwork tcp with mark=1234 and mptcp=true"
                },
                {
                    "name": "udp-endpoint-pool",
                    "status": "planned",
                    "required_observation": "UDP flow creates endpoint state without losing mark/mptcp propagation"
                },
                {
                    "name": "dns-udp-53",
                    "status": "planned",
                    "required_observation": "transparent DNS UDP/53 follows DNS controller and routing semantics"
                },
                {
                    "name": "reload-rollback",
                    "status": "planned",
                    "required_observation": "reload failure keeps old BPF object, listener, DNS listener, and DNS cache semantics"
                }
            ],
            "remaining_blockers": [
                "helper only builds an isolated plan and optional files; it does not start a daemon",
                "Go run path still writes reload progress to /var/run/dae.progress",
                "veth/netns setup commands are listed but not executed by this helper",
                "live daemon, active TCP/UDP/DNS traffic, reload rollback, and daemon benchmark remain pending"
            ],
        })
    ))
}

struct LivePlanLayout {
    root: PathBuf,
    config: PathBuf,
    readme: PathBuf,
    run_dir: PathBuf,
    log_file: PathBuf,
    helper_pid_file: PathBuf,
    traffic_dir: PathBuf,
    socket_dir: PathBuf,
}

impl LivePlanLayout {
    fn new(root: PathBuf) -> Self {
        let run_dir = root.join("run");
        let traffic_dir = root.join("traffic");
        let socket_dir = root.join("sockets");
        Self {
            config: root.join("config.dae"),
            readme: root.join("README.stage22-live-smoke.txt"),
            log_file: root.join("logs").join("dae.log"),
            helper_pid_file: run_dir.join("dae-stage22.pid"),
            run_dir,
            traffic_dir,
            socket_dir,
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

    fn helper_pid_file_string(&self) -> String {
        path_string(&self.helper_pid_file)
    }

    fn traffic_dir_string(&self) -> String {
        path_string(&self.traffic_dir)
    }

    fn socket_dir_string(&self) -> String {
        path_string(&self.socket_dir)
    }
}

fn temp_root(root: &str) -> Result<PathBuf, RunnerOutput> {
    let root = PathBuf::from(root);
    if !root.is_absolute() {
        return Err(RunnerOutput::stdout_error(
            "stage22 live plan root must be an absolute /tmp path",
        ));
    }
    let root_string = path_string(&root);
    if root_string == "/tmp" || !root_string.starts_with("/tmp/") {
        return Err(RunnerOutput::stdout_error(
            "stage22 live plan root must stay under /tmp to avoid production mutation",
        ));
    }
    Ok(root)
}

fn write_live_plan_files(
    layout: &LivePlanLayout,
    config_text: &str,
    files_written: &mut Vec<String>,
) -> std::io::Result<()> {
    fs::create_dir_all(&layout.run_dir)?;
    fs::create_dir_all(layout.log_file.parent().unwrap_or(&layout.root))?;
    fs::create_dir_all(&layout.traffic_dir)?;
    fs::create_dir_all(&layout.socket_dir)?;
    fs::write(&layout.config, config_text)?;
    set_private_file_mode(&layout.config)?;
    files_written.push(layout.config_string());
    fs::write(&layout.readme, readme_text(layout))?;
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

fn live_plan_commands(layout: &LivePlanLayout) -> Vec<serde_json::Value> {
    vec![
        json!({
            "name": "validate-generated-config",
            "status": "ready",
            "command": format!("{ARTIFACT_BINARY} validate -c {}", layout.config_string()),
            "side_effect": "read-only config validation"
        }),
        json!({
            "name": "preflight",
            "status": "already-passed-in-stage22-item165",
            "command": format!("rust/target/debug/dae-cli-optin active-datapath preflight --tproxy-port {TPROXY_PORT} --so-mark {SO_MARK} --mptcp {MPTCP} --lan-count 1 --wan-count 1"),
            "side_effect": "pre-side-effect environment gate only"
        }),
        json!({
            "name": "setup-veth-netns",
            "status": "planned-not-run",
            "command": format!("ip netns add {CLIENT_NETNS}; ip link add {LAN_IFACE} type veth peer name {CLIENT_IFACE}; ip link set {CLIENT_IFACE} netns {CLIENT_NETNS}; ip link add {WAN_IFACE} type dummy"),
            "side_effect": "creates temporary netns and interfaces; must be cleaned before default switch claims"
        }),
        json!({
            "name": "run-optin-daemon-candidate",
            "status": "planned-not-run",
            "command": format!("{ARTIFACT_BINARY} run --disable-sudo --disable-pidfile --disable-timestamp --logfile {} -c {} & echo $! > {}", layout.log_file_string(), layout.config_string(), layout.helper_pid_file_string()),
            "side_effect": "starts foreground candidate from /tmp artifact; does not use systemd"
        }),
        json!({
            "name": "reload-with-explicit-pid",
            "status": "planned-not-run",
            "command": format!("{ARTIFACT_BINARY} reload $(cat {})", layout.helper_pid_file_string()),
            "side_effect": "writes fixed Go progress file /var/run/dae.progress"
        }),
        json!({
            "name": "stop-candidate",
            "status": "planned-not-run",
            "command": format!("kill -TERM $(cat {})", layout.helper_pid_file_string()),
            "side_effect": "stops only the opt-in candidate process"
        }),
        json!({
            "name": "cleanup-temporary-environment",
            "status": "planned-not-run",
            "command": format!("ip netns del {CLIENT_NETNS} 2>/dev/null || true; ip link del {LAN_IFACE} 2>/dev/null || true; ip link del {WAN_IFACE} 2>/dev/null || true; rm -rf {}", layout.root_string()),
            "side_effect": "removes temporary netns, interfaces, and files"
        }),
    ]
}

fn readme_text(layout: &LivePlanLayout) -> String {
    format!(
        "Stage 22 isolated live smoke plan\n\nRoot: {}\nConfig: {}\n\nThis helper does not start dae, does not modify systemd, and does not switch the default path.\nThe current Go run path still writes reload progress to /var/run/dae.progress, so live execution requires an exclusive host or a later progress-path override.\n",
        layout.root_string(),
        layout.config_string()
    )
}

fn path_string(path: &Path) -> String {
    path.as_os_str().to_string_lossy().into_owned()
}
