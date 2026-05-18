use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::runner::RunnerOutput;
use crate::{validate_config_file, validate_config_text};

const DEFAULT_ROOT: &str = "/tmp/dae-stage29-candidate";
const DEFAULT_ARTIFACT_BINARY: &str = "rust/target/debug/dae-cli-optin";
const DEFAULT_TPROXY_PORT: u16 = 12346;
const DEFAULT_LAN_IFACE: &str = "daex29lan0";
const DEFAULT_WAN_IFACE: &str = "daex29wan0";
const DEFAULT_CLIENT_NETNS: &str = "dae-stage29-client";
const SO_MARK: u32 = 2234;
const MPTCP: bool = true;
const DNS_BIND: &str = "udp://127.0.0.1:1153";
const DNS_UPSTREAM: &str = "udp://127.0.0.1:11530";

#[derive(Debug, Clone)]
struct Stage29PreflightOptions {
    root: PathBuf,
    config: Option<PathBuf>,
    artifact_binary: PathBuf,
    pid_file: Option<PathBuf>,
    progress_file: Option<PathBuf>,
    log_file: Option<PathBuf>,
    tproxy_port: u16,
    lan_iface: String,
    wan_iface: String,
    client_netns: String,
    probe_host: bool,
    require_existing_config: bool,
}

impl Default for Stage29PreflightOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from(DEFAULT_ROOT),
            config: None,
            artifact_binary: PathBuf::from(DEFAULT_ARTIFACT_BINARY),
            pid_file: None,
            progress_file: None,
            log_file: None,
            tproxy_port: DEFAULT_TPROXY_PORT,
            lan_iface: DEFAULT_LAN_IFACE.to_owned(),
            wan_iface: DEFAULT_WAN_IFACE.to_owned(),
            client_netns: DEFAULT_CLIENT_NETNS.to_owned(),
            probe_host: false,
            require_existing_config: false,
        }
    }
}

struct Stage29PreflightLayout {
    root: PathBuf,
    config: PathBuf,
    pid_file: PathBuf,
    progress_file: PathBuf,
    log_file: PathBuf,
    run_dir: PathBuf,
    traffic_dir: PathBuf,
    socket_dir: PathBuf,
    asset_dir: PathBuf,
    cache_dir: PathBuf,
}

impl Stage29PreflightLayout {
    fn new(opts: &Stage29PreflightOptions) -> Self {
        let root = opts.root.clone();
        let run_dir = root.join("run");
        Self {
            config: opts
                .config
                .clone()
                .unwrap_or_else(|| root.join("config.dae")),
            pid_file: opts
                .pid_file
                .clone()
                .unwrap_or_else(|| run_dir.join("dae-stage29.pid")),
            progress_file: opts
                .progress_file
                .clone()
                .unwrap_or_else(|| run_dir.join("dae-stage29.progress")),
            log_file: opts
                .log_file
                .clone()
                .unwrap_or_else(|| root.join("logs").join("dae-stage29.log")),
            traffic_dir: root.join("traffic"),
            socket_dir: root.join("sockets"),
            asset_dir: root.join("assets"),
            cache_dir: root.join("cache"),
            run_dir,
            root,
        }
    }
}

pub(crate) fn run_stage29_host_preflight(args: &[String]) -> RunnerOutput {
    let opts = match parse_args(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage29_host_preflight_report(&opts);
    RunnerOutput::ok(format!("{report}\n"))
}

fn parse_args(args: &[String]) -> Result<Stage29PreflightOptions, RunnerOutput> {
    let mut opts = Stage29PreflightOptions::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => opts.root = PathBuf::from(next_value(&mut iter, "stage29 --root")?),
            "--config" => {
                opts.config = Some(PathBuf::from(next_value(&mut iter, "stage29 --config")?));
            }
            "--artifact-binary" => {
                opts.artifact_binary =
                    PathBuf::from(next_value(&mut iter, "stage29 --artifact-binary")?);
            }
            "--pid-file" => {
                opts.pid_file = Some(PathBuf::from(next_value(&mut iter, "stage29 --pid-file")?));
            }
            "--progress-file" => {
                opts.progress_file = Some(PathBuf::from(next_value(
                    &mut iter,
                    "stage29 --progress-file",
                )?));
            }
            "--logfile" => {
                opts.log_file = Some(PathBuf::from(next_value(&mut iter, "stage29 --logfile")?));
            }
            "--tproxy-port" => {
                opts.tproxy_port = parse_next(&mut iter, "stage29 --tproxy-port")?;
            }
            "--lan-iface" => {
                opts.lan_iface = next_value(&mut iter, "stage29 --lan-iface")?;
            }
            "--wan-iface" => {
                opts.wan_iface = next_value(&mut iter, "stage29 --wan-iface")?;
            }
            "--client-netns" => {
                opts.client_netns = next_value(&mut iter, "stage29 --client-netns")?;
            }
            "--probe-host" => opts.probe_host = true,
            "--require-existing-config" => opts.require_existing_config = true,
            _ if arg.starts_with("--root=") => {
                opts.root = PathBuf::from(value_after_equals(arg, "stage29 --root")?);
            }
            _ if arg.starts_with("--config=") => {
                opts.config = Some(PathBuf::from(value_after_equals(arg, "stage29 --config")?));
            }
            _ if arg.starts_with("--artifact-binary=") => {
                opts.artifact_binary =
                    PathBuf::from(value_after_equals(arg, "stage29 --artifact-binary")?);
            }
            _ if arg.starts_with("--pid-file=") => {
                opts.pid_file = Some(PathBuf::from(value_after_equals(
                    arg,
                    "stage29 --pid-file",
                )?));
            }
            _ if arg.starts_with("--progress-file=") => {
                opts.progress_file = Some(PathBuf::from(value_after_equals(
                    arg,
                    "stage29 --progress-file",
                )?));
            }
            _ if arg.starts_with("--logfile=") => {
                opts.log_file = Some(PathBuf::from(value_after_equals(arg, "stage29 --logfile")?));
            }
            _ if arg.starts_with("--tproxy-port=") => {
                opts.tproxy_port = parse_value(arg, "stage29 --tproxy-port")?;
            }
            _ if arg.starts_with("--lan-iface=") => {
                opts.lan_iface = value_after_equals(arg, "stage29 --lan-iface")?;
            }
            _ if arg.starts_with("--wan-iface=") => {
                opts.wan_iface = value_after_equals(arg, "stage29 --wan-iface")?;
            }
            _ if arg.starts_with("--client-netns=") => {
                opts.client_netns = value_after_equals(arg, "stage29 --client-netns")?;
            }
            _ => {
                return Err(RunnerOutput::usage(format!(
                    "unsupported runtime stage29-host-preflight argument: {arg}"
                )));
            }
        }
    }
    Ok(opts)
}

fn stage29_host_preflight_report(opts: &Stage29PreflightOptions) -> Value {
    let layout = Stage29PreflightLayout::new(opts);
    let mut blockers = Vec::new();
    let mut path_checks = Vec::new();

    push_check(
        &mut path_checks,
        "isolated-root-under-tmp",
        tmp_root_allowed(&layout.root),
        json!({"path": path_string(&layout.root)}),
        &mut blockers,
        "stage29 candidate root must be an absolute /tmp child path",
    );
    for (name, path) in [
        ("config-under-root", &layout.config),
        ("pid-file-under-root", &layout.pid_file),
        ("progress-file-under-root", &layout.progress_file),
        ("log-file-under-root", &layout.log_file),
        ("run-dir-under-root", &layout.run_dir),
        ("traffic-dir-under-root", &layout.traffic_dir),
        ("socket-dir-under-root", &layout.socket_dir),
        ("asset-dir-under-root", &layout.asset_dir),
        ("cache-dir-under-root", &layout.cache_dir),
    ] {
        push_check(
            &mut path_checks,
            name,
            path_under_root(&layout.root, path),
            json!({"root": path_string(&layout.root), "path": path_string(path)}),
            &mut blockers,
            "candidate state path must stay under the isolated root",
        );
    }

    let generated_config_valid = validate_config_text(&minimal_config_text()).is_ok();
    push_check(
        &mut path_checks,
        "generated-minimum-config-valid",
        generated_config_valid,
        json!({"tproxy_port": DEFAULT_TPROXY_PORT, "so_mark_from_dae": SO_MARK, "mptcp": MPTCP}),
        &mut blockers,
        "stage29 generated minimum config is invalid",
    );

    if opts.require_existing_config {
        let config_exists = layout.config.is_file();
        let config_valid = config_exists && validate_config_file(&layout.config).is_ok();
        push_check(
            &mut path_checks,
            "existing-isolated-config-valid",
            config_valid,
            json!({"path": path_string(&layout.config), "exists": config_exists}),
            &mut blockers,
            "isolated candidate config is missing or invalid",
        );
    } else {
        path_checks.push(json!({
            "name": "existing-isolated-config-valid",
            "status": "not-run",
            "detail": {
                "path": path_string(&layout.config),
                "requires_flag": "--require-existing-config",
            },
            "blocker": Value::Null,
        }));
    }

    let host_checks = if opts.probe_host {
        probed_host_checks(opts, &mut blockers)
    } else {
        planned_host_checks()
    };
    let preflight_passed = opts.probe_host && blockers.is_empty();

    json!({
        "name": "stage29-host-root-bpf-netns-preflight",
        "stage": "stage29",
        "evidence_class": "read-only-host-root-bpf-netns-preflight",
        "root": path_string(&layout.root),
        "host_probe_executed": opts.probe_host,
        "require_existing_config": opts.require_existing_config,
        "read_only": true,
        "preflight_passed": preflight_passed,
        "live_candidate_run_allowed": false,
        "default_switch_allowed": false,
        "default_path_mutated": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "blockers": blockers,
        "paths": {
            "root": path_string(&layout.root),
            "config": path_string(&layout.config),
            "artifact_binary": path_string(&opts.artifact_binary),
            "pid_file": path_string(&layout.pid_file),
            "progress_file": path_string(&layout.progress_file),
            "log_file": path_string(&layout.log_file),
            "run_dir": path_string(&layout.run_dir),
            "traffic_dir": path_string(&layout.traffic_dir),
            "socket_dir": path_string(&layout.socket_dir),
            "asset_dir": path_string(&layout.asset_dir),
            "cache_dir": path_string(&layout.cache_dir),
            "production_pid_file_checked_when_probe_host": "/var/run/dae.pid",
            "production_progress_file_checked_when_probe_host": "/var/run/dae.progress",
        },
        "inputs": {
            "tproxy_port": opts.tproxy_port,
            "lan_iface": opts.lan_iface,
            "wan_iface": opts.wan_iface,
            "client_netns": opts.client_netns,
            "so_mark_from_dae": SO_MARK,
            "mptcp": MPTCP,
            "dns_bind": DNS_BIND,
            "dns_upstream": DNS_UPSTREAM,
        },
        "path_checks": path_checks,
        "host_checks": host_checks,
        "production_safety": {
            "no_daemon_start": true,
            "no_reload_signal": true,
            "no_systemd_mutation": true,
            "no_install_mutation": true,
            "no_release_label_mutation": true,
            "no_daewing_daed_default_mutation": true,
            "no_interface_mutation": true,
            "no_netns_mutation": true,
            "no_ebpf_attach": true,
            "no_var_run_mutation": true,
            "host_probe_requires_explicit_flag": true,
        },
        "next_if_clear": [
            "record --probe-host output in the local plan for the exact candidate root",
            "only in a later stage, prepare root-gated eBPF/netns/sysctl attach cleanup smoke",
            "only after attach cleanup evidence, run active TCP tproxy traffic with MagicNetwork mark and mptcp observations",
            "keep live candidate start denied until Stage 28 admission rows have recorded evidence",
        ],
    })
}

fn planned_host_checks() -> Vec<Value> {
    [
        "effective-root-permission",
        "bpffs-mounted",
        "netns-parent-available",
        "memlock-nonzero",
        "kernel-release-readable",
        "artifact-binary-exists",
        "production-progress-file-clear",
        "production-pid-file-clear",
        "no-existing-dae-process",
        "tproxy-tcp-port-free",
        "tproxy-udp-port-free",
        "lan-interface-name-free",
        "wan-interface-name-free",
        "client-netns-name-free",
    ]
    .into_iter()
    .map(|name| {
        json!({
            "name": name,
            "status": "not-run",
            "detail": {"requires_flag": "--probe-host"},
            "blocker": Value::Null,
        })
    })
    .collect()
}

fn probed_host_checks(opts: &Stage29PreflightOptions, blockers: &mut Vec<String>) -> Vec<Value> {
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "effective-root-permission",
        effective_uid_is_root(),
        json!({"source": "/proc/self/status"}),
        blockers,
        "effective uid is not root",
    );
    push_check(
        &mut checks,
        "bpffs-mounted",
        bpffs_mounted(),
        json!({"mountpoint": "/sys/fs/bpf", "source": "/proc/mounts"}),
        blockers,
        "bpffs is not mounted at /sys/fs/bpf",
    );
    push_check(
        &mut checks,
        "netns-parent-available",
        netns_parent_available(),
        json!({"candidate_parents": ["/var/run/netns", "/run/netns"]}),
        blockers,
        "netns parent directory is missing",
    );
    push_check(
        &mut checks,
        "memlock-nonzero",
        memlock_nonzero(),
        json!({"source": "/proc/self/limits"}),
        blockers,
        "memlock limit appears to be zero",
    );
    let kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    push_check(
        &mut checks,
        "kernel-release-readable",
        !kernel_release.trim().is_empty(),
        json!({"osrelease": kernel_release.trim()}),
        blockers,
        "kernel release is not readable",
    );
    push_check(
        &mut checks,
        "artifact-binary-exists",
        opts.artifact_binary.is_file(),
        json!({"path": path_string(&opts.artifact_binary)}),
        blockers,
        "candidate artifact binary is missing",
    );

    let production_progress = PathBuf::from("/var/run/dae.progress");
    let progress_exists = production_progress.exists();
    let progress_prefix = if progress_exists {
        fs::read_to_string(&production_progress)
            .unwrap_or_default()
            .chars()
            .take(32)
            .collect::<String>()
    } else {
        String::new()
    };
    push_check(
        &mut checks,
        "production-progress-file-clear",
        !progress_exists,
        json!({"path": path_string(&production_progress), "exists": progress_exists, "content_prefix": progress_prefix}),
        blockers,
        "production progress file exists",
    );

    let production_pid = PathBuf::from("/var/run/dae.pid");
    let pid = read_pid_file(&production_pid);
    let pid_file_exists = production_pid.exists();
    let pid_alive = pid.map(process_alive).unwrap_or(false);
    push_check(
        &mut checks,
        "production-pid-file-clear",
        !pid_file_exists && !pid_alive,
        json!({"path": path_string(&production_pid), "exists": pid_file_exists, "pid": pid, "pid_alive": pid_alive}),
        blockers,
        "production pid file exists or points to a live process",
    );

    let dae_processes = scan_dae_processes();
    push_check(
        &mut checks,
        "no-existing-dae-process",
        dae_processes.is_empty(),
        json!({"processes": dae_processes}),
        blockers,
        "existing dae process detected",
    );

    let tcp_listeners =
        socket_entries_for_port(&["/proc/net/tcp", "/proc/net/tcp6"], opts.tproxy_port, true);
    push_check(
        &mut checks,
        "tproxy-tcp-port-free",
        tcp_listeners.is_empty(),
        json!({"port": opts.tproxy_port, "listeners": tcp_listeners}),
        blockers,
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
        json!({"port": opts.tproxy_port, "sockets": udp_sockets}),
        blockers,
        "tproxy UDP port already has a socket",
    );

    for (check, name) in [
        ("lan-interface-name-free", opts.lan_iface.as_str()),
        ("wan-interface-name-free", opts.wan_iface.as_str()),
    ] {
        let valid = iface_name_valid(name);
        let exists = iface_exists(name);
        push_check(
            &mut checks,
            check,
            valid && !exists,
            json!({"name": name, "valid": valid, "exists": exists, "path": format!("/sys/class/net/{name}")}),
            blockers,
            "planned interface name is invalid or already exists",
        );
    }

    let netns_existing_paths = [
        PathBuf::from("/var/run/netns").join(&opts.client_netns),
        PathBuf::from("/run/netns").join(&opts.client_netns),
    ]
    .into_iter()
    .filter(|path| path.exists())
    .map(|path| path_string(&path))
    .collect::<Vec<_>>();
    push_check(
        &mut checks,
        "client-netns-name-free",
        netns_existing_paths.is_empty(),
        json!({"name": opts.client_netns, "existing_paths": netns_existing_paths}),
        blockers,
        "planned client netns name already exists",
    );

    checks
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

fn minimal_config_text() -> String {
    format!(
        "global {{\n    tproxy_port: {DEFAULT_TPROXY_PORT}\n    so_mark_from_dae: {SO_MARK}\n    mptcp: {MPTCP}\n    lan_interface: {DEFAULT_LAN_IFACE}\n    wan_interface: {DEFAULT_WAN_IFACE}\n    auto_config_kernel_parameter: false\n    disable_waiting_network: true\n    log_level: debug\n}}\n\ndns {{\n    bind: '{DNS_BIND}'\n    upstream {{\n        local_udp: '{DNS_UPSTREAM}'\n    }}\n    routing {{\n        request {{\n            fallback: local_udp\n        }}\n        response {{\n            fallback: accept\n        }}\n    }}\n}}\n\nnode {{}}\ngroup {{}}\nrouting {{\n    fallback: must_direct\n}}\n"
    )
}

fn tmp_root_allowed(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let value = path_string(path);
    value != "/tmp" && value.starts_with("/tmp/")
}

fn path_under_root(root: &Path, path: &Path) -> bool {
    root.is_absolute() && path.is_absolute() && path.starts_with(root)
}

fn effective_uid_is_root() -> bool {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return false;
    };
    status.lines().any(|line| {
        if !line.starts_with("Uid:") {
            return false;
        }
        line.split_whitespace().nth(2) == Some("0")
    })
}

fn bpffs_mounted() -> bool {
    let Ok(mounts) = fs::read_to_string("/proc/mounts") else {
        return false;
    };
    mounts.lines().any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields.get(1) == Some(&"/sys/fs/bpf") && fields.get(2) == Some(&"bpf")
    })
}

fn netns_parent_available() -> bool {
    ["/var/run/netns", "/run/netns"]
        .into_iter()
        .any(|path| PathBuf::from(path).is_dir())
}

fn memlock_nonzero() -> bool {
    let Ok(limits) = fs::read_to_string("/proc/self/limits") else {
        return false;
    };
    limits.lines().any(|line| {
        if !line.starts_with("Max locked memory") {
            return false;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields.get(3) == Some(&"unlimited")
            || fields
                .get(3)
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|value| value > 0)
    })
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
        if basename == "dae" || basename.starts_with("dae-stage") {
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
        .ok_or_else(|| RunnerOutput::usage(format!("missing runtime {name}")))
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
        .ok_or_else(|| RunnerOutput::usage(format!("missing runtime {name}")))
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
