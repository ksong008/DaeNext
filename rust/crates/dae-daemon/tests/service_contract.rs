use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use std::{fs, io};

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
    assert_eq!(
        report["primary_state_store"].as_str().unwrap(),
        "/etc/daed/daed.db"
    );
    assert_eq!(
        report["protected_rollback_state_store"].as_str().unwrap(),
        "/etc/daed/wing.db"
    );
    assert!(
        !report["rust_daed_writes_wing_db_by_default"]
            .as_bool()
            .unwrap()
    );
    assert!(report["wing_db_import_supported"].as_bool().unwrap());
    assert!(
        !report["wing_db_import_destructive_by_default"]
            .as_bool()
            .unwrap()
    );
    assert!(report["daed_db_primary_required"].as_bool().unwrap());
    assert!(
        !report["var_lib_daed_required_by_default"]
            .as_bool()
            .unwrap()
    );
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
        report["resident_dataplane_default_switch_required"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["resident_runtime_platform_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["resident_runtime_typed_report_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["resident_runtime_resource_gate_ready"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        report["resident_runtime_report_schema"].as_str().unwrap(),
        "resident-runtime-platform-report-v1"
    );
    assert!(
        report["resident_runtime_resource_limits"]["max_rss_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        report["resident_runtime_resource_limits"]["max_thread_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        report["resident_runtime_resource_limits"]["max_fd_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        report["resident_runtime_resource_limits"]["max_report_size_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        report["resident_runtime_lifecycle_contract"]["ready_record_file_supported"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["control_plane_owner_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["control_plane_runtime_state_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(report["routing_map_owner_ready"].as_bool().unwrap());
    assert!(report["domain_routing_owner_ready"].as_bool().unwrap());
    assert!(
        report["outbound_connectivity_owner_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["runtime_overview_cache_stats_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["control_plane_reload_parity_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["control_plane_cleanup_leftovers_gate_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["matched_go_rust_default_daemon_benchmark_gate_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["control_plane_typed_report_ready"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        report["control_plane_typed_report"]["schema"]
            .as_str()
            .unwrap(),
        "control-api-typed-report-v1"
    );
    assert!(
        report["control_plane_runtime_state_report"]["ready_for_default_control_plane"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["control_plane_c_tproxy_oracle_retained_until_datapath_core"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["go_control_plane_fallback_retirement_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["go_control_plane_fallback_retired_candidate"]
            .as_bool()
            .unwrap()
    );
    assert!(report["datapath_core_contract_ready"].as_bool().unwrap());
    assert!(
        report["datapath_core_runtime_state_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(report["tcp_tproxy_datapath_ready"].as_bool().unwrap());
    assert!(
        report["tcp_route_sniff_direct_block_proxy_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(report["udp_tproxy_datapath_ready"].as_bool().unwrap());
    assert!(report["udp_endpoint_pool_ready"].as_bool().unwrap());
    assert!(report["dns_tproxy_datapath_ready"].as_bool().unwrap());
    assert!(
        report["dns_cache_route_integration_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(report["sniff_result_contract_ready"].as_bool().unwrap());
    assert!(report["route_result_contract_ready"].as_bool().unwrap());
    assert!(
        report["direct_block_proxy_action_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["datapath_core_benchmark_gate_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["datapath_core_typed_report_ready"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        report["datapath_core_report_schema"].as_str().unwrap(),
        "datapath-core-v1"
    );
    assert_eq!(
        report["datapath_core_typed_report"]["schema"]
            .as_str()
            .unwrap(),
        "datapath-core-typed-report-v1"
    );
    assert!(
        report["no_go_userspace_datapath_fallback_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["c_tproxy_oracle_retired_after_datapath_core"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["go_datapath_core_fallback_retirement_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["go_datapath_core_fallback_retired_candidate"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["outbound_fingerprint_underlay_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["standard_tls_underlay_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["fingerprint_aware_tls_underlay_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(report["link_fingerprint_plan_ready"].as_bool().unwrap());
    assert!(report["global_fingerprint_plan_ready"].as_bool().unwrap());
    assert!(
        report["unknown_fingerprint_fail_closed_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["boring_fingerprint_underlay_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["no_silent_fingerprint_rustls_fallback_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["full_utls_parity_not_declared_without_wire_oracle"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        report["outbound_fingerprint_underlay_report_schema"]
            .as_str()
            .unwrap(),
        "outbound-fingerprint-underlay-v1"
    );
    assert!(
        report["go_fingerprint_underlay_fallback_retired_candidate"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["outbound_production_matrix_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(report["outbound_matrix_entries_ready"].as_bool().unwrap());
    assert!(
        report["parser_export_metadata_matrix_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(report["tcp_udp_dataplane_matrix_ready"].as_bool().unwrap());
    assert!(report["transport_underlay_matrix_ready"].as_bool().unwrap());
    assert!(
        report["route_group_connectivity_matrix_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(report["reload_behavior_matrix_ready"].as_bool().unwrap());
    assert!(report["live_smoke_matrix_ready"].as_bool().unwrap());
    assert!(
        report["go_outbound_fallback_retirement_matrix_ready"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        report["outbound_production_matrix_report_schema"]
            .as_str()
            .unwrap(),
        "outbound-production-matrix-v1"
    );
    assert!(
        report["outbound_production_matrix_entries"]
            .as_array()
            .unwrap()
            .len()
            >= 10
    );
    assert!(
        report["go_outbound_fallback_retired_candidate"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["resident_live_adapter_matrix_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["resident_live_adapter_matrix_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["resident_live_adapter_matrix_runtime_state_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["resident_live_adapter_entries_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["resident_live_adapter_wired_matrix_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["resident_live_adapter_remote_live_matrix_ready"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        report["resident_live_adapter_wired_handler_count"]
            .as_u64()
            .unwrap(),
        1
    );
    assert_eq!(
        report["resident_live_adapter_live_ready_handler_count"]
            .as_u64()
            .unwrap(),
        1
    );
    assert_eq!(
        report["resident_live_adapter_matrix_report_schema"]
            .as_str()
            .unwrap(),
        "resident-live-adapter-matrix-v1"
    );
    assert!(
        report["resident_live_adapter_matrix_entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |entry| entry["handler"].as_str().unwrap() == "vless-vision-tcp-tls"
                    && entry["wired_ready"].as_bool().unwrap()
                    && entry["live_ready"].as_bool().unwrap()
            )
    );
    assert_eq!(
        report["resident_live_adapter_matrix_typed_report"]["status"]
            .as_str()
            .unwrap(),
        "blocked"
    );
    assert!(
        report["release_default_switch_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["release_default_artifact_path_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["default_runtime_selector_no_env_rust_owned_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["install_service_package_scripts_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["release_default_switch_live_evidence_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(report["backup_manifest_contract_ready"].as_bool().unwrap());
    assert!(
        report["rollback_rehearsal_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["host_write_freeze_contract_required"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["go_product_shell_allowed_until_go_free"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["release_default_switch_final_go_free_claim"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        report["release_default_switch_report_schema"]
            .as_str()
            .unwrap(),
        "release-default-switch-v1"
    );
    assert!(
        report["go_free_product_chain_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["default_product_package_go_free"].as_bool().unwrap());
    assert!(
        !report["go_product_shell_retired_from_default_package"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["go_outbound_dependency_retired_from_default_package"]
            .as_bool()
            .unwrap()
    );
    assert!(report["go_compat_oracle_boundary_ready"].as_bool().unwrap());
    assert!(
        !report["rust_product_binary_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["go_free_product_chain_ready"].as_bool().unwrap());
    assert_eq!(
        report["go_free_product_chain_report_schema"]
            .as_str()
            .unwrap(),
        "go-free-product-chain-v1"
    );
    assert_eq!(
        report["resident_dataplane_env"].as_str().unwrap(),
        "DAE_RUST_RESIDENT_DATAPLANE"
    );
    assert!(!report["resident_dataplane_env_enabled"].as_bool().unwrap());
    assert!(
        !report["resident_dataplane_default_switch_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["resident_production_dataplane_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["resident_default_daemon_switch_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["default_path_switch_blocker"]
            .as_str()
            .unwrap()
            .contains("DAE_RUST_RESIDENT_DATAPLANE=1")
    );
    let enabled_output = Command::new(binary())
        .arg("service-contract")
        .env("DAE_RUST_RESIDENT_DATAPLANE", "1")
        .output()
        .unwrap();
    assert!(enabled_output.status.success());
    let enabled_report: Value = serde_json::from_slice(&enabled_output.stdout).unwrap();
    assert!(
        enabled_report["resident_dataplane_env_enabled"]
            .as_bool()
            .unwrap()
    );
    assert!(
        enabled_report["resident_production_dataplane_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        enabled_report["resident_default_daemon_switch_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(enabled_report["default_path_switch_blocker"].is_null());
    assert!(
        enabled_report["reload_failure_rollback_supported"]
            .as_bool()
            .unwrap()
    );
    assert!(
        enabled_report["invalid_runtime_config_rejected_before_current_swap"]
            .as_bool()
            .unwrap()
    );
    assert!(
        enabled_report["reload_start_failure_attempts_previous_runtime_restore"]
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

    let successful_reload = reload_child(child.inner.id(), &progress_file, &abort_file, false);
    assert!(successful_reload.status.success());
    assert_eq!(
        String::from_utf8_lossy(&successful_reload.stdout).trim(),
        "OK"
    );
    assert_eq!(recv_notify(&notify_socket), "RELOADING=1");
    assert_eq!(recv_notify(&notify_socket), "READY=1");
    assert!(fs::read(&progress_file).unwrap().starts_with(b"2\nOK"));
    assert!(!abort_file.exists());

    let abort_reload = reload_child(child.inner.id(), &progress_file, &abort_file, true);
    assert!(abort_reload.status.success());
    assert_eq!(String::from_utf8_lossy(&abort_reload.stdout).trim(), "OK");
    assert_eq!(recv_notify(&notify_socket), "RELOADING=1");
    assert_eq!(recv_notify(&notify_socket), "READY=1");
    assert!(!abort_file.exists());

    write_missing_interface_config(&config);
    let rejected_reload = reload_child(child.inner.id(), &progress_file, &abort_file, false);
    assert!(rejected_reload.status.success());
    assert!(
        String::from_utf8_lossy(&rejected_reload.stdout)
            .contains("rejected before current runtime swap")
    );
    assert_eq!(recv_notify(&notify_socket), "RELOADING=1");
    assert_eq!(recv_notify(&notify_socket), "READY=1");
    assert_eq!(fs::read(&progress_file).unwrap()[0], RELOAD_ERROR);
    assert!(child.inner.try_wait().unwrap().is_none());

    write_valid_config(&config);
    let restored_reload = reload_child(child.inner.id(), &progress_file, &abort_file, false);
    assert!(restored_reload.status.success());
    assert_eq!(
        String::from_utf8_lossy(&restored_reload.stdout).trim(),
        "OK"
    );
    assert_eq!(recv_notify(&notify_socket), "RELOADING=1");
    assert_eq!(recv_notify(&notify_socket), "READY=1");
    assert!(fs::read(&progress_file).unwrap().starts_with(b"2\nOK"));

    fs::write(&config, "global {\n  log_level: info\n").unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let failed_reload = reload_child(child.inner.id(), &progress_file, &abort_file, false);
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

fn reload_child(
    pid: u32,
    progress_file: &Path,
    abort_file: &Path,
    abort_connections: bool,
) -> std::process::Output {
    let mut command = Command::new(binary());
    command
        .arg("reload")
        .arg(pid.to_string())
        .arg("--service-progress-file")
        .arg(progress_file)
        .arg("--service-abort-file")
        .arg(abort_file)
        .arg("--timeout-ms=5000");
    if abort_connections {
        command.arg("--abort");
    }
    command.output().unwrap()
}

fn write_valid_config(path: &Path) {
    fs::write(
        path,
        "global {\n  log_level: info\n}\n\nrouting {\n  pname(NetworkManager, systemd-resolved, dnsmasq) -> must_direct\n}\n",
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn write_missing_interface_config(path: &Path) {
    fs::write(
        path,
        "global {\n  log_level: info\n  lan_interface: dae-missing-a4-interface\n}\n\nrouting {\n  pname(NetworkManager, systemd-resolved, dnsmasq) -> must_direct\n}\n",
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn wait_for_file(path: &PathBuf) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !path.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(path.exists(), "{} was not written", path.display());
}

fn recv_notify(socket: &UnixDatagram) -> String {
    let mut bytes = [0_u8; 128];
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match socket.recv(&mut bytes) {
            Ok(size) => return String::from_utf8_lossy(&bytes[..size]).to_string(),
            Err(err)
                if (matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) || err.raw_os_error() == Some(libc::EAGAIN))
                    && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) => panic!("failed to receive notify datagram: {err}"),
        }
    }
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
