use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::runner::RunnerOutput;
use crate::validate_config_file;

const DEFAULT_ROOT: &str = "/tmp/dae-stage22-live";
const DEFAULT_ARTIFACT_BINARY: &str = "/tmp/dae-stage22-live-evidence";
const DEFAULT_PROGRESS_FILE: &str = "/var/run/dae.progress";
const DEFAULT_PID_FILE: &str = "/var/run/dae.pid";
const DEFAULT_TPROXY_PORT: u16 = 12345;
const DEFAULT_LAN_IFACE: &str = "daex22lan0";
const DEFAULT_WAN_IFACE: &str = "daex22wan0";
const DEFAULT_CLIENT_NETNS: &str = "dae-stage22-client";

#[derive(Debug, Clone)]
struct HostPreflightOptions {
    root: PathBuf,
    artifact_binary: PathBuf,
    progress_file: PathBuf,
    pid_file: PathBuf,
    tproxy_port: u16,
    lan_iface: String,
    wan_iface: String,
    client_netns: String,
}

impl Default for HostPreflightOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from(DEFAULT_ROOT),
            artifact_binary: PathBuf::from(DEFAULT_ARTIFACT_BINARY),
            progress_file: PathBuf::from(DEFAULT_PROGRESS_FILE),
            pid_file: PathBuf::from(DEFAULT_PID_FILE),
            tproxy_port: DEFAULT_TPROXY_PORT,
            lan_iface: DEFAULT_LAN_IFACE.to_owned(),
            wan_iface: DEFAULT_WAN_IFACE.to_owned(),
            client_netns: DEFAULT_CLIENT_NETNS.to_owned(),
        }
    }
}

pub(crate) fn run_stage22_host_preflight(args: &[String]) -> RunnerOutput {
    let opts = match parse_args(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    RunnerOutput::ok(format!("{}\n", host_preflight_report(&opts)))
}

fn parse_args(args: &[String]) -> Result<HostPreflightOptions, RunnerOutput> {
    let mut opts = HostPreflightOptions::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                opts.root = PathBuf::from(next_value(
                    &mut iter,
                    "runtime stage22-host-preflight --root",
                )?);
            }
            "--artifact-binary" => {
                opts.artifact_binary = PathBuf::from(next_value(
                    &mut iter,
                    "runtime stage22-host-preflight --artifact-binary",
                )?);
            }
            "--progress-file" => {
                opts.progress_file = PathBuf::from(next_value(
                    &mut iter,
                    "runtime stage22-host-preflight --progress-file",
                )?);
            }
            "--pid-file" => {
                opts.pid_file = PathBuf::from(next_value(
                    &mut iter,
                    "runtime stage22-host-preflight --pid-file",
                )?);
            }
            "--tproxy-port" => {
                opts.tproxy_port =
                    parse_next(&mut iter, "runtime stage22-host-preflight --tproxy-port")?;
            }
            "--lan-iface" => {
                opts.lan_iface =
                    next_value(&mut iter, "runtime stage22-host-preflight --lan-iface")?;
            }
            "--wan-iface" => {
                opts.wan_iface =
                    next_value(&mut iter, "runtime stage22-host-preflight --wan-iface")?;
            }
            "--client-netns" => {
                opts.client_netns =
                    next_value(&mut iter, "runtime stage22-host-preflight --client-netns")?;
            }
            _ if arg.starts_with("--root=") => {
                opts.root = PathBuf::from(value_after_equals(
                    arg,
                    "runtime stage22-host-preflight --root",
                )?);
            }
            _ if arg.starts_with("--artifact-binary=") => {
                opts.artifact_binary = PathBuf::from(value_after_equals(
                    arg,
                    "runtime stage22-host-preflight --artifact-binary",
                )?);
            }
            _ if arg.starts_with("--progress-file=") => {
                opts.progress_file = PathBuf::from(value_after_equals(
                    arg,
                    "runtime stage22-host-preflight --progress-file",
                )?);
            }
            _ if arg.starts_with("--pid-file=") => {
                opts.pid_file = PathBuf::from(value_after_equals(
                    arg,
                    "runtime stage22-host-preflight --pid-file",
                )?);
            }
            _ if arg.starts_with("--tproxy-port=") => {
                opts.tproxy_port =
                    parse_value(arg, "runtime stage22-host-preflight --tproxy-port")?;
            }
            _ if arg.starts_with("--lan-iface=") => {
                opts.lan_iface =
                    value_after_equals(arg, "runtime stage22-host-preflight --lan-iface")?;
            }
            _ if arg.starts_with("--wan-iface=") => {
                opts.wan_iface =
                    value_after_equals(arg, "runtime stage22-host-preflight --wan-iface")?;
            }
            _ if arg.starts_with("--client-netns=") => {
                opts.client_netns =
                    value_after_equals(arg, "runtime stage22-host-preflight --client-netns")?;
            }
            _ => {
                return Err(RunnerOutput::usage(format!(
                    "unsupported runtime stage22-host-preflight argument: {arg}"
                )));
            }
        }
    }
    Ok(opts)
}

fn host_preflight_report(opts: &HostPreflightOptions) -> Value {
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    let mut checks = Vec::new();

    let root_safe = tmp_root_allowed(&opts.root);
    push_check(
        &mut checks,
        "isolated-root-under-tmp",
        root_safe,
        json!({"path": path_string(&opts.root)}),
        &mut blockers,
        "stage22 live root must be an absolute /tmp child path",
    );

    let artifact_exists = opts.artifact_binary.is_file();
    push_check(
        &mut checks,
        "artifact-binary-exists",
        artifact_exists,
        json!({"path": path_string(&opts.artifact_binary)}),
        &mut blockers,
        "candidate artifact binary is missing",
    );

    let config_path = opts.root.join("config.dae");
    let config_exists = config_path.is_file();
    let config_valid = config_exists && validate_config_file(&config_path).is_ok();
    push_check(
        &mut checks,
        "isolated-config-valid",
        config_valid,
        json!({
            "path": path_string(&config_path),
            "exists": config_exists,
        }),
        &mut blockers,
        "isolated config is missing or invalid",
    );

    let progress_exists = opts.progress_file.exists();
    let progress_content = if progress_exists {
        fs::read_to_string(&opts.progress_file).unwrap_or_default()
    } else {
        String::new()
    };
    push_check(
        &mut checks,
        "fixed-progress-file-clear",
        !progress_exists,
        json!({
            "path": path_string(&opts.progress_file),
            "exists": progress_exists,
            "content_prefix": progress_content.chars().take(32).collect::<String>(),
            "fixed_go_path": true,
        }),
        &mut blockers,
        "fixed reload progress file already exists; live run needs exclusive host or progress-path override",
    );

    let pid = read_pid_file(&opts.pid_file);
    let pid_file_exists = opts.pid_file.exists();
    let pid_alive = pid.map(process_alive).unwrap_or(false);
    push_check(
        &mut checks,
        "production-pid-file-clear",
        !pid_file_exists && !pid_alive,
        json!({
            "path": path_string(&opts.pid_file),
            "exists": pid_file_exists,
            "pid": pid,
            "pid_alive": pid_alive,
        }),
        &mut blockers,
        "production pid file exists or points to a live process",
    );

    let dae_processes = scan_dae_processes();
    push_check(
        &mut checks,
        "no-existing-dae-process",
        dae_processes.is_empty(),
        json!({"processes": dae_processes}),
        &mut blockers,
        "existing dae process detected",
    );

    let tcp_listeners =
        socket_entries_for_port(&["/proc/net/tcp", "/proc/net/tcp6"], opts.tproxy_port, true);
    push_check(
        &mut checks,
        "tproxy-tcp-port-free",
        tcp_listeners.is_empty(),
        json!({
            "port": opts.tproxy_port,
            "listeners": tcp_listeners,
        }),
        &mut blockers,
        "tproxy TCP port already has a listener",
    );

    let udp_sockets = socket_entries_for_port(
        &["/proc/net/udp", "/proc/net/udp6"],
        opts.tproxy_port,
        false,
    );
    push_check(
        &mut checks,
        "tproxy-udp-port-free",
        udp_sockets.is_empty(),
        json!({
            "port": opts.tproxy_port,
            "sockets": udp_sockets,
        }),
        &mut blockers,
        "tproxy UDP port already has a socket",
    );

    let lan_exists = iface_exists(&opts.lan_iface);
    let lan_name_valid = iface_name_valid(&opts.lan_iface);
    push_check(
        &mut checks,
        "lan-interface-name-valid",
        lan_name_valid,
        json!({
            "name": opts.lan_iface,
            "max_linux_ifname_len": 15,
            "len": opts.lan_iface.len(),
        }),
        &mut blockers,
        "planned LAN interface name is too long or empty",
    );
    push_check(
        &mut checks,
        "lan-interface-name-free",
        lan_name_valid && !lan_exists,
        json!({
            "name": opts.lan_iface,
            "path": format!("/sys/class/net/{}", opts.lan_iface),
            "exists": lan_exists,
        }),
        &mut blockers,
        "planned LAN interface name already exists",
    );

    let wan_exists = iface_exists(&opts.wan_iface);
    let wan_name_valid = iface_name_valid(&opts.wan_iface);
    push_check(
        &mut checks,
        "wan-interface-name-valid",
        wan_name_valid,
        json!({
            "name": opts.wan_iface,
            "max_linux_ifname_len": 15,
            "len": opts.wan_iface.len(),
        }),
        &mut blockers,
        "planned WAN interface name is too long or empty",
    );
    push_check(
        &mut checks,
        "wan-interface-name-free",
        wan_name_valid && !wan_exists,
        json!({
            "name": opts.wan_iface,
            "path": format!("/sys/class/net/{}", opts.wan_iface),
            "exists": wan_exists,
        }),
        &mut blockers,
        "planned WAN interface name already exists",
    );

    let netns_paths = [
        PathBuf::from("/var/run/netns").join(&opts.client_netns),
        PathBuf::from("/run/netns").join(&opts.client_netns),
    ];
    let netns_existing_paths = netns_paths
        .iter()
        .filter(|path| path.exists())
        .map(|path| path_string(path))
        .collect::<Vec<_>>();
    push_check(
        &mut checks,
        "client-netns-name-free",
        netns_existing_paths.is_empty(),
        json!({
            "name": opts.client_netns,
            "existing_paths": netns_existing_paths,
        }),
        &mut blockers,
        "planned client netns name already exists",
    );

    warnings.push("Go run still uses fixed /var/run/dae.progress; absence of the file does not remove the need for exclusive-host discipline".to_owned());

    json!({
        "name": "stage22-host-conflict-preflight",
        "evidence_class": "read-only-host-conflict-preflight",
        "default_switch_allowed": false,
        "default_path_mutated": false,
        "live_daemon_started": false,
        "read_only": true,
        "allowed_to_start_candidate": blockers.is_empty(),
        "blockers": blockers,
        "warnings": warnings,
        "paths": {
            "root": path_string(&opts.root),
            "artifact_binary": path_string(&opts.artifact_binary),
            "config": path_string(&config_path),
            "progress_file": path_string(&opts.progress_file),
            "pid_file": path_string(&opts.pid_file),
        },
        "inputs": {
            "tproxy_port": opts.tproxy_port,
            "lan_iface": opts.lan_iface,
            "wan_iface": opts.wan_iface,
            "client_netns": opts.client_netns,
        },
        "checks": checks,
        "production_safety": {
            "no_systemd_mutation": true,
            "no_daemon_start": true,
            "no_reload_signal": true,
            "no_interface_mutation": true,
            "no_netns_mutation": true,
            "no_ebpf_attach": true,
            "fixed_progress_file_checked": true,
        },
        "next_if_clear": [
            "run setup-veth-netns command from stage22-live-plan",
            "start opt-in candidate with --disable-pidfile and explicit temporary config",
            "record /var/run/dae.progress before and after candidate run",
            "run active TCP/UDP/DNS traffic matrix",
            "stop candidate and cleanup temporary interfaces/netns/files",
        ],
    })
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

fn tmp_root_allowed(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let value = path_string(path);
    value != "/tmp" && value.starts_with("/tmp/")
}

fn read_pid_file(path: &Path) -> Option<u32> {
    let content = fs::read_to_string(path).ok()?;
    content.trim().parse::<u32>().ok()
}

fn process_alive(pid: u32) -> bool {
    PathBuf::from("/proc").join(pid.to_string()).exists()
}

fn scan_dae_processes() -> Vec<Value> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let current_pid = std::process::id();
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid_text) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_text.parse::<u32>() else {
            continue;
        };
        if pid == current_pid {
            continue;
        }
        let Ok(raw) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        if raw.is_empty() {
            continue;
        }
        let parts = raw
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect::<Vec<_>>();
        let Some(first) = parts.first() else {
            continue;
        };
        let basename = Path::new(first)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| first.clone());
        if basename == "dae" || basename == "dae-stage22-live-evidence" {
            out.push(json!({
                "pid": pid,
                "binary": basename,
                "cmdline": parts.join(" "),
            }));
        }
    }
    out
}

fn socket_entries_for_port(paths: &[&str], port: u16, tcp: bool) -> Vec<Value> {
    let mut out = Vec::new();
    let port_hex = format!("{port:04X}");
    for path in paths {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for line in content.lines().skip(1) {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 4 {
                continue;
            }
            let local = fields[1];
            let state = fields[3];
            let Some((addr, local_port)) = local.rsplit_once(':') else {
                continue;
            };
            if !local_port.eq_ignore_ascii_case(&port_hex) {
                continue;
            }
            if tcp && state != "0A" {
                continue;
            }
            out.push(json!({
                "table": *path,
                "local_address_hex": addr,
                "local_port_hex": local_port,
                "state": state,
            }));
        }
    }
    out
}

fn iface_exists(name: &str) -> bool {
    PathBuf::from("/sys/class/net").join(name).exists()
}

fn iface_name_valid(name: &str) -> bool {
    !name.is_empty() && name.len() <= 15
}

fn next_value(
    iter: &mut std::slice::Iter<'_, String>,
    name: &'static str,
) -> Result<String, RunnerOutput> {
    iter.next()
        .cloned()
        .ok_or_else(|| RunnerOutput::usage(format!("missing {name}")))
}

fn parse_next<T: std::str::FromStr>(
    iter: &mut std::slice::Iter<'_, String>,
    name: &'static str,
) -> Result<T, RunnerOutput>
where
    T::Err: std::fmt::Display,
{
    let value = next_value(iter, name)?;
    value
        .parse::<T>()
        .map_err(|err| RunnerOutput::stdout_error(err.to_string()))
}

fn value_after_equals(arg: &str, name: &'static str) -> Result<String, RunnerOutput> {
    arg.split_once('=')
        .map(|(_, value)| value.to_owned())
        .ok_or_else(|| RunnerOutput::usage(format!("missing {name}")))
}

fn parse_value<T: std::str::FromStr>(arg: &str, name: &'static str) -> Result<T, RunnerOutput>
where
    T::Err: std::fmt::Display,
{
    let value = value_after_equals(arg, name)?;
    value
        .parse::<T>()
        .map_err(|err| RunnerOutput::stdout_error(err.to_string()))
}

fn path_string(path: &Path) -> String {
    path.as_os_str().to_string_lossy().into_owned()
}
