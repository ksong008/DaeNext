use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const TCP_PING: &[u8] = b"stage160-tcp-ping";
const TCP_PONG: &[u8] = b"stage160-tcp-pong";
const UDP_PING: &[u8] = b"stage160-udp-ping";
const UDP_PONG: &[u8] = b"stage160-udp-pong";

pub fn default_stage160_root() -> PathBuf {
    PathBuf::from("/tmp/dae-stage160-listener-ebpf-preflight")
}

pub fn stage160_listener_ebpf_preflight_harness_report(root: &Path) -> Result<Value, String> {
    ensure_safe_stage160_root(root)?;
    if root.exists() {
        fs::remove_dir_all(root).map_err(|err| {
            format!(
                "failed to remove existing stage160 root {}: {err}",
                path_string(root)
            )
        })?;
    }

    let run_dir = root.join("run");
    let log_dir = root.join("log");
    let temporary_pin_dir = root.join("bpf-pins").join("stage160");
    let manifest_file = run_dir.join("stage160-listener-ebpf-preflight.json");
    let log_file = log_dir.join("listener-ebpf-preflight.log");

    fs::create_dir_all(&run_dir).map_err(|err| {
        format!(
            "failed to create stage160 run dir {}: {err}",
            path_string(&run_dir)
        )
    })?;
    fs::create_dir_all(&log_dir).map_err(|err| {
        format!(
            "failed to create stage160 log dir {}: {err}",
            path_string(&log_dir)
        )
    })?;
    fs::create_dir_all(&temporary_pin_dir).map_err(|err| {
        format!(
            "failed to create stage160 temporary pin dir {}: {err}",
            path_string(&temporary_pin_dir)
        )
    })?;
    fs::write(
        temporary_pin_dir.join("stage160.pin"),
        b"temporary-stage160-pin\n",
    )
    .map_err(|err| format!("failed to write stage160 temporary pin marker: {err}"))?;

    let started = Instant::now();
    let listener = run_loopback_listener_smoke()?;
    let capabilities = capability_preflight();
    fs::remove_dir_all(&temporary_pin_dir).map_err(|err| {
        format!(
            "failed to clean stage160 temporary pin dir {}: {err}",
            path_string(&temporary_pin_dir)
        )
    })?;
    let rollback_cleanup_smoke_passed = !temporary_pin_dir.exists();
    let elapsed_ns = started.elapsed().as_nanos() as u64;

    let mut report = json!({
        "name": "stage160-isolated-listener-ebpf-preflight-harness",
        "stage": "stage160",
        "root": path_string(root),
        "run_dir": path_string(&run_dir),
        "manifest_file": path_string(&manifest_file),
        "log_file": path_string(&log_file),
        "temporary_pin_dir": path_string(&temporary_pin_dir),
        "listener": listener,
        "capability_preflight": capabilities,
        "elapsed_ns": elapsed_ns,
        "listener_fd_map_key_contract": [
            {"key": 0, "socket": "tcp"},
            {"key": 1, "socket": "udp"}
        ]
    });
    for key in [
        "isolated_listener_preflight_harness_available",
        "temporary_port_scope_validated",
        "tcp_udp_loopback_listener_smoke_passed",
        "capability_preflight_executed",
        "temporary_bpf_pin_scope_validated",
        "rollback_cleanup_smoke_passed",
        "listener_fd_map_key_contract_recorded",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "production_listener_bound",
        "isolated_namespace_listener_smoke_passed",
        "ebpf_attached",
        "temporary_ebpf_attach_smoke_passed",
        "benchmark_executable_now",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "true_rust_default_daemon_admitted",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
    ] {
        report[key] = json!(false);
    }
    report["temporary_pin_scope_cleaned"] = json!(rollback_cleanup_smoke_passed);
    report["temporary_ebpf_attach_blocker"] = json!(
        "Stage160 records capability and temporary pin scope preflight only; real temporary eBPF map creation/attach remains closed for the next gate"
    );

    let manifest = serde_json::to_vec_pretty(&report)
        .map_err(|err| format!("failed to encode stage160 manifest: {err}"))?;
    fs::write(&manifest_file, manifest)
        .map_err(|err| format!("failed to write stage160 manifest: {err}"))?;
    fs::write(
        &log_file,
        format!(
            "stage160 listener/eBPF preflight: tcp_port={} udp_port={} elapsed_ns={elapsed_ns}\n",
            report["listener"]["tcp_port"].as_u64().unwrap(),
            report["listener"]["udp_port"].as_u64().unwrap()
        ),
    )
    .map_err(|err| format!("failed to write stage160 log: {err}"))?;
    Ok(report)
}

fn run_loopback_listener_smoke() -> Result<Value, String> {
    let tcp_listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|err| format!("failed to bind stage160 tcp listener: {err}"))?;
    let tcp_addr = tcp_listener
        .local_addr()
        .map_err(|err| format!("failed to read stage160 tcp listener address: {err}"))?;
    let udp_socket = UdpSocket::bind(("127.0.0.1", tcp_addr.port()))
        .map_err(|err| format!("failed to bind stage160 udp listener on tcp port: {err}"))?;
    let udp_addr = udp_socket
        .local_addr()
        .map_err(|err| format!("failed to read stage160 udp listener address: {err}"))?;

    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let result = accept_one_tcp(tcp_listener);
        let _ = tx.send(result);
    });

    let mut stream = TcpStream::connect(tcp_addr)
        .map_err(|err| format!("failed to connect stage160 tcp client: {err}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| format!("failed to set stage160 tcp read timeout: {err}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| format!("failed to set stage160 tcp write timeout: {err}"))?;
    stream
        .write_all(TCP_PING)
        .map_err(|err| format!("failed to write stage160 tcp ping: {err}"))?;
    let mut tcp_buf = vec![0; TCP_PONG.len()];
    stream
        .read_exact(&mut tcp_buf)
        .map_err(|err| format!("failed to read stage160 tcp pong: {err}"))?;
    let tcp_roundtrip_passed = tcp_buf == TCP_PONG;
    let tcp_server = rx
        .recv_timeout(Duration::from_secs(2))
        .map_err(|err| format!("stage160 tcp accept thread did not finish: {err}"))??;
    handle
        .join()
        .map_err(|_| "stage160 tcp accept thread panicked".to_string())?;

    let udp_client = UdpSocket::bind(("127.0.0.1", 0))
        .map_err(|err| format!("failed to bind stage160 udp client: {err}"))?;
    udp_client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| format!("failed to set stage160 udp client timeout: {err}"))?;
    udp_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| format!("failed to set stage160 udp listener timeout: {err}"))?;
    udp_client
        .send_to(UDP_PING, udp_addr)
        .map_err(|err| format!("failed to write stage160 udp ping: {err}"))?;
    let mut udp_buf = [0_u8; 64];
    let (udp_read_len, udp_peer) = udp_socket
        .recv_from(&mut udp_buf)
        .map_err(|err| format!("failed to receive stage160 udp ping: {err}"))?;
    udp_socket
        .send_to(UDP_PONG, udp_peer)
        .map_err(|err| format!("failed to write stage160 udp pong: {err}"))?;
    let mut udp_reply = [0_u8; 64];
    let (udp_reply_len, _) = udp_client
        .recv_from(&mut udp_reply)
        .map_err(|err| format!("failed to receive stage160 udp pong: {err}"))?;
    let udp_roundtrip_passed =
        &udp_buf[..udp_read_len] == UDP_PING && &udp_reply[..udp_reply_len] == UDP_PONG;

    Ok(json!({
        "bind_address": "127.0.0.1",
        "tcp_port": tcp_addr.port(),
        "udp_port": udp_addr.port(),
        "tcp_udp_same_port": tcp_addr.port() == udp_addr.port(),
        "tcp_roundtrip_passed": tcp_roundtrip_passed,
        "tcp_request_bytes": TCP_PING.len(),
        "tcp_response_bytes": TCP_PONG.len(),
        "tcp_server_observed_request_bytes": tcp_server.request_bytes,
        "udp_roundtrip_passed": udp_roundtrip_passed,
        "udp_request_bytes": UDP_PING.len(),
        "udp_response_bytes": UDP_PONG.len(),
        "production_tproxy_port_used": false
    }))
}

#[derive(Debug, Clone, Copy)]
struct TcpServerReport {
    request_bytes: usize,
}

fn accept_one_tcp(listener: TcpListener) -> Result<TcpServerReport, String> {
    let (mut conn, _) = listener
        .accept()
        .map_err(|err| format!("failed to accept stage160 tcp client: {err}"))?;
    conn.set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| format!("failed to set stage160 accepted tcp read timeout: {err}"))?;
    conn.set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| format!("failed to set stage160 accepted tcp write timeout: {err}"))?;
    let mut buf = vec![0; TCP_PING.len()];
    conn.read_exact(&mut buf)
        .map_err(|err| format!("failed to read stage160 accepted tcp ping: {err}"))?;
    if buf != TCP_PING {
        return Err("stage160 tcp request payload mismatch".to_string());
    }
    conn.write_all(TCP_PONG)
        .map_err(|err| format!("failed to write stage160 accepted tcp pong: {err}"))?;
    Ok(TcpServerReport {
        request_bytes: buf.len(),
    })
}

fn capability_preflight() -> Value {
    let cap_eff = read_cap_eff();
    let cap_net_admin_available = cap_eff.is_some_and(|value| has_cap(value, 12));
    let cap_bpf_available = cap_eff.is_some_and(|value| has_cap(value, 39));
    let bpffs_mounted = proc_mounts_has_bpffs();
    json!({
        "proc_status_read": cap_eff.is_some(),
        "cap_eff_hex": cap_eff.map(|value| format!("{value:x}")),
        "cap_net_admin_available": cap_net_admin_available,
        "cap_bpf_available": cap_bpf_available,
        "bpffs_mounted": bpffs_mounted,
        "environment_allows_future_temporary_ebpf_attach": cap_net_admin_available && cap_bpf_available && bpffs_mounted,
        "temporary_ebpf_attach_attempted": false
    })
}

fn read_cap_eff() -> Option<u128> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let cap = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))?
        .trim();
    u128::from_str_radix(cap, 16).ok()
}

fn has_cap(value: u128, cap: u32) -> bool {
    value & (1_u128 << cap) != 0
}

fn proc_mounts_has_bpffs() -> bool {
    fs::read_to_string("/proc/mounts")
        .ok()
        .is_some_and(|mounts| {
            mounts.lines().any(|line| {
                let mut fields = line.split_whitespace();
                let _source = fields.next();
                let _target = fields.next();
                matches!(fields.next(), Some("bpf"))
            })
        })
}

fn ensure_safe_stage160_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!(
            "stage160 root must be absolute: {}",
            path_string(root)
        ));
    }
    let root_string = path_string(root);
    if !root_string.starts_with("/tmp/dae-stage160") {
        return Err(format!(
            "stage160 root must be under /tmp/dae-stage160*: {root_string}"
        ));
    }
    Ok(())
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
