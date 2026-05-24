use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use dae_core_types::reload::{RELOAD_DONE, RELOAD_ERROR};
use serde_json::Value;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_dae-daemon-optin")
}

#[test]
fn candidate_reports_resident_service_and_dataplane_capabilities() {
    let output = Command::new(binary())
        .arg("service-contract")
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["resident_run_service_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["reload_command_service_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["resident_production_dataplane_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["resident_default_daemon_switch_ready"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn resident_service_notifies_reloads_rejects_bad_config_and_cleans_pid() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-service-contract-integration-{}",
        std::process::id()
    ));
    let config = root.join("config.dae");
    let pid_file = root.join("dae.pid");
    let progress_file = root.join("dae.progress");
    let abort_file = root.join("dae.abort");
    let ready_file = root.join("ready.record");
    let notify_socket_path = root.join("notify.sock");
    fs::create_dir_all(&root).unwrap();
    write_valid_config(&config);

    let notify_socket = UnixDatagram::bind(&notify_socket_path).unwrap();
    notify_socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let child = Command::new(binary())
        .args(["run", "--disable-timestamp", "--disable-sudo", "-c"])
        .arg(&config)
        .arg("--service-pid-file")
        .arg(&pid_file)
        .arg("--service-progress-file")
        .arg(&progress_file)
        .arg("--service-abort-file")
        .arg(&abort_file)
        .arg("--service-ready-file")
        .arg(&ready_file)
        .env("NOTIFY_SOCKET", &notify_socket_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = ChildGuard::new(child);

    assert_eq!(recv_notify(&notify_socket), "READY=1");
    wait_for_file(&ready_file);
    assert_eq!(
        fs::read_to_string(&pid_file).unwrap(),
        child.inner.id().to_string()
    );
    assert_eq!(fs::read(&progress_file).unwrap()[0], RELOAD_DONE);

    let successful_reload = reload_child(child.inner.id(), &progress_file, &abort_file);
    assert!(successful_reload.status.success());
    assert_eq!(
        String::from_utf8_lossy(&successful_reload.stdout).trim(),
        "OK"
    );
    assert_eq!(recv_notify(&notify_socket), "RELOADING=1");
    assert_eq!(recv_notify(&notify_socket), "READY=1");
    assert!(fs::read(&progress_file).unwrap().starts_with(b"2\nOK"));

    fs::write(&config, "global {\n  log_level: info\n").unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let failed_reload = reload_child(child.inner.id(), &progress_file, &abort_file);
    assert!(failed_reload.status.success());
    assert!(
        !String::from_utf8_lossy(&failed_reload.stdout)
            .trim()
            .is_empty()
    );
    assert_eq!(recv_notify(&notify_socket), "RELOADING=1");
    assert_eq!(recv_notify(&notify_socket), "READY=1");
    assert_eq!(fs::read(&progress_file).unwrap()[0], RELOAD_ERROR);
    assert!(child.inner.try_wait().unwrap().is_none());

    unsafe {
        libc::kill(child.inner.id() as i32, libc::SIGTERM);
    }
    assert_eq!(recv_notify(&notify_socket), "STOPPING=1");
    assert!(child.inner.wait().unwrap().success());
    child.reaped = true;
    assert!(!pid_file.exists());

    let _ = fs::remove_dir_all(&root);
}

fn reload_child(pid: u32, progress_file: &Path, abort_file: &Path) -> std::process::Output {
    Command::new(binary())
        .arg("reload")
        .arg(pid.to_string())
        .arg("--service-progress-file")
        .arg(progress_file)
        .arg("--service-abort-file")
        .arg(abort_file)
        .arg("--timeout-ms=5000")
        .output()
        .unwrap()
}

fn write_valid_config(path: &Path) {
    fs::write(
        path,
        "global {\n  log_level: info\n}\n\nrouting {\n  pname(NetworkManager, systemd-resolved, dnsmasq) -> must_direct\n}\n",
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn wait_for_file(path: &PathBuf) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(path.exists(), "{} was not written", path.display());
}

fn recv_notify(socket: &UnixDatagram) -> String {
    let mut bytes = [0_u8; 128];
    let size = socket.recv(&mut bytes).unwrap();
    String::from_utf8_lossy(&bytes[..size]).to_string()
}

struct ChildGuard {
    inner: Child,
    reaped: bool,
}

impl ChildGuard {
    fn new(inner: Child) -> Self {
        Self {
            inner,
            reaped: false,
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.inner.kill();
            let _ = self.inner.wait();
        }
    }
}
