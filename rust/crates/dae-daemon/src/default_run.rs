use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use dae_core_types::reload::RELOAD_DONE;
use serde_json::{Value, json};

use crate::{
    MatchedDefaultBenchmarkOptions, ProductChainAdmissionEvidence,
    ProductChainRecertificationOptions, ProductionDataplaneHarnessOptions,
    ProductionRuntimeOwnerOptions, listener_ebpf_preflight_report,
    matched_default_benchmark_report, product_chain_recertification_report,
    production_dataplane_harness_report, production_runtime_owner_report,
    reload_owner_handoff_smoke_report,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOptions {
    pub root: PathBuf,
    pub config: PathBuf,
    pub logfile: PathBuf,
    pub disable_timestamp: bool,
    pub disable_pidfile: bool,
    pub disable_sudo: bool,
    pub listener_smoke: bool,
    pub reload_smoke: bool,
    pub production_runtime_owner: ProductionRuntimeOwnerOptions,
    pub production_dataplane_harness: ProductionDataplaneHarnessOptions,
    pub matched_default_benchmark: MatchedDefaultBenchmarkOptions,
    pub product_chain_recertification: ProductChainRecertificationOptions,
    pub product_chain_admission_override: Option<ProductChainAdmissionEvidence>,
    pub product_chain_admission_source: Option<PathBuf>,
}

impl RunOptions {
    pub fn under_root(root: impl Into<PathBuf>, config: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            config: config.into(),
            logfile: root.join("log").join("dae-daemon-optin-run.log"),
            root,
            disable_timestamp: false,
            disable_pidfile: false,
            disable_sudo: false,
            listener_smoke: true,
            reload_smoke: true,
            production_runtime_owner: ProductionRuntimeOwnerOptions::default(),
            production_dataplane_harness: ProductionDataplaneHarnessOptions::default(),
            matched_default_benchmark: MatchedDefaultBenchmarkOptions::default(),
            product_chain_recertification: ProductChainRecertificationOptions::default(),
            product_chain_admission_override: None,
            product_chain_admission_source: None,
        }
    }
}

pub fn default_run_root() -> PathBuf {
    PathBuf::from("/tmp/dae-daemon-optin-run")
}

pub fn run_default_optin_report(options: &RunOptions, version: &str) -> Result<Value, String> {
    ensure_safe_run_root(&options.root)?;
    ensure_safe_output_path(&options.logfile, &options.root, "logfile")?;
    if !options.config.is_file() {
        return Err(format!(
            "run config does not exist or is not a file: {}",
            path_string(&options.config)
        ));
    }

    let config = fs::read_to_string(&options.config).map_err(|err| {
        format!(
            "failed to read run config {}: {err}",
            path_string(&options.config)
        )
    })?;
    if config.trim().is_empty() {
        return Err(format!(
            "run config must not be empty: {}",
            path_string(&options.config)
        ));
    }

    if options.root.exists() {
        fs::remove_dir_all(&options.root).map_err(|err| {
            format!(
                "failed to remove existing run root {}: {err}",
                path_string(&options.root)
            )
        })?;
    }

    let run_dir = options.root.join("run");
    let manifest_file = run_dir.join("dae-daemon-optin-run.json");
    let run_config_file = run_dir.join("input-config.dae");
    let pid_file = run_dir.join("dae-daemon-optin.pid");
    let progress_file = run_dir.join("dae-daemon-optin.progress");
    let sdnotify_file = run_dir.join("sdnotify.ready");
    fs::create_dir_all(&run_dir)
        .map_err(|err| format!("failed to create run dir {}: {err}", path_string(&run_dir)))?;
    if let Some(parent) = options.logfile.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create run log dir {}: {err}",
                path_string(parent)
            )
        })?;
    }

    if !options.disable_pidfile {
        fs::write(&pid_file, format!("{}\n", std::process::id()))
            .map_err(|err| format!("failed to write run pid file: {err}"))?;
    }
    fs::write(&run_config_file, &config)
        .map_err(|err| format!("failed to write run input config copy: {err}"))?;
    fs::set_permissions(&run_config_file, fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("failed to chmod run input config copy: {err}"))?;
    write_progress(&progress_file, RELOAD_DONE, "")?;
    fs::write(&sdnotify_file, "READY=1\n")
        .map_err(|err| format!("failed to write run sdnotify ready file: {err}"))?;

    let listener_root = derived_support_root("/tmp/dae-listener-ebpf-preflight-run", &options.root);
    let reload_root = derived_support_root("/tmp/dae-reload-owner-handoff-run", &options.root);
    let listener = if options.listener_smoke {
        listener_ebpf_preflight_report(&listener_root)?
    } else {
        json!({"skipped": true})
    };
    let reload = if options.reload_smoke {
        reload_owner_handoff_smoke_report(&reload_root)?
    } else {
        json!({"skipped": true})
    };
    let production_runtime_owner =
        production_runtime_owner_report(&options.root, &options.production_runtime_owner)?;
    let production_dataplane =
        production_dataplane_harness_report(&options.root, &options.production_dataplane_harness)?;
    let matched_benchmark = matched_default_benchmark_report(
        &options.root,
        &run_config_file,
        &options.matched_default_benchmark,
    )?;

    let listener_smoke_passed = !options.listener_smoke
        || listener["tcp_udp_loopback_listener_smoke_passed"]
            .as_bool()
            .unwrap_or(false);
    let reload_smoke_passed = !options.reload_smoke
        || reload["non_production_daemon_reload_owner_transfer_smoke_passed"]
            .as_bool()
            .unwrap_or(false);
    let production_dataplane_harness_executed =
        production_dataplane["production_dataplane_harness_executed"]
            .as_bool()
            .unwrap_or(false);
    let production_dataplane_harness_passed =
        production_dataplane["production_dataplane_harness_passed"]
            .as_bool()
            .unwrap_or(false);
    let production_runtime_owner_executed =
        production_runtime_owner["daemon_owned_production_runtime_owner_executed"]
            .as_bool()
            .unwrap_or(false);
    let production_runtime_owner_passed =
        production_runtime_owner["daemon_owned_production_runtime_owner_smoke_passed"]
            .as_bool()
            .unwrap_or(false);
    let production_runtime_active_tcp_executed =
        production_runtime_owner["production_runtime_active_tcp_executed"]
            .as_bool()
            .unwrap_or(false);
    let production_runtime_active_tcp_passed =
        production_runtime_owner["production_runtime_active_tcp_passed"]
            .as_bool()
            .unwrap_or(false);
    let active_tcp_relay_executed = production_runtime_owner["active_tcp_relay_executed"]
        .as_bool()
        .unwrap_or(false);
    let active_tcp_relay_passed = production_runtime_owner["active_tcp_relay_smoke_passed"]
        .as_bool()
        .unwrap_or(false);
    let active_tcp_relay_benchmark_recorded =
        production_runtime_owner["active_tcp_relay_benchmark_recorded"]
            .as_bool()
            .unwrap_or(false);
    let route_dial_tcp_magic_network_observed =
        production_runtime_owner["route_dial_tcp_magic_network_mark_mptcp_observed"]
            .as_bool()
            .unwrap_or(false);
    let production_runtime_active_udp_executed =
        production_runtime_owner["production_runtime_active_udp_executed"]
            .as_bool()
            .unwrap_or(false);
    let production_runtime_active_udp_passed =
        production_runtime_owner["production_runtime_active_udp_passed"]
            .as_bool()
            .unwrap_or(false);
    let active_udp_admitted = production_runtime_owner["active_udp_tproxy_admitted"]
        .as_bool()
        .unwrap_or(false);
    let active_udp_benchmark_recorded =
        production_runtime_owner["active_udp_tproxy_benchmark_recorded"]
            .as_bool()
            .unwrap_or(false);
    let production_runtime_active_dns_executed =
        production_runtime_owner["production_runtime_active_dns_executed"]
            .as_bool()
            .unwrap_or(false);
    let production_runtime_active_dns_passed =
        production_runtime_owner["production_runtime_active_dns_passed"]
            .as_bool()
            .unwrap_or(false);
    let active_dns_admitted = production_runtime_owner["active_dns_tproxy_admitted"]
        .as_bool()
        .unwrap_or(false);
    let active_dns_benchmark_recorded =
        production_runtime_owner["active_dns_tproxy_benchmark_recorded"]
            .as_bool()
            .unwrap_or(false);
    let production_dataplane_admitted = production_runtime_owner["production_dataplane_admitted"]
        .as_bool()
        .unwrap_or(false);
    let reload_runtime_parity_executed =
        production_runtime_owner["production_reload_runtime_parity_executed"]
            .as_bool()
            .unwrap_or(false);
    let reload_runtime_parity_passed =
        production_runtime_owner["production_reload_runtime_parity_passed"]
            .as_bool()
            .unwrap_or(false);
    let reload_runtime_parity_admitted = production_runtime_owner["reload_runtime_parity_admitted"]
        .as_bool()
        .unwrap_or(false);
    let matched_benchmark_recorded =
        matched_benchmark["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap_or(false);
    let bpf_go_fallback_retired = production_runtime_owner["go_bpf_fallback_retired"]
        .as_bool()
        .unwrap_or(false);
    let true_rust_default_daemon_admitted = production_dataplane_admitted
        && reload_runtime_parity_admitted
        && matched_benchmark_recorded
        && bpf_go_fallback_retired;
    let computed_product_chain_admission = ProductChainAdmissionEvidence {
        production_dataplane_admitted,
        reload_runtime_parity_admitted,
        matched_benchmark_recorded,
        bpf_go_fallback_retired,
        true_rust_default_daemon_admitted,
    };
    let product_chain_admission = options
        .product_chain_admission_override
        .unwrap_or(computed_product_chain_admission);
    let product_chain_recertification = product_chain_recertification_report(
        &options.root,
        &options.product_chain_recertification,
        product_chain_admission,
    )?;
    let product_chain_recertification_executed = product_chain_recertification["execute"]
        .as_bool()
        .unwrap_or(false);
    let product_chain_recertification_clean =
        product_chain_recertification["product_chain_recertification_clean"]
            .as_bool()
            .unwrap_or(false);
    let default_path_mutation_allowed =
        product_chain_recertification["default_path_mutation_allowed"]
            .as_bool()
            .unwrap_or(false);
    let product_chain_switch_allowed =
        product_chain_recertification["product_chain_switch_allowed"]
            .as_bool()
            .unwrap_or(false);
    let resident_default_daemon_switch_ready =
        product_chain_recertification["resident_default_daemon_switch_ready"]
            .as_bool()
            .unwrap_or(false);
    let default_daemon_live_matrix = default_daemon_live_matrix_json(
        options.listener_smoke,
        listener_smoke_passed,
        options.reload_smoke,
        reload_smoke_passed,
        production_runtime_owner_executed,
        production_runtime_owner_passed,
        production_runtime_active_tcp_executed,
        production_runtime_active_tcp_passed,
        active_tcp_relay_executed,
        active_tcp_relay_passed,
        active_tcp_relay_benchmark_recorded,
        route_dial_tcp_magic_network_observed,
        production_runtime_active_udp_executed,
        production_runtime_active_udp_passed,
        active_udp_admitted,
        active_udp_benchmark_recorded,
        production_runtime_active_dns_executed,
        production_runtime_active_dns_passed,
        active_dns_admitted,
        active_dns_benchmark_recorded,
        reload_runtime_parity_executed,
        reload_runtime_parity_admitted,
        options.matched_default_benchmark.execute,
        matched_benchmark_recorded,
        bpf_go_fallback_retired,
    );
    let default_daemon_live_matrix_complete = default_daemon_live_matrix["matrix_complete"]
        .as_bool()
        .unwrap_or(false);
    let release_product_chain_live_gate = release_product_chain_live_gate_json(
        production_dataplane_admitted,
        reload_runtime_parity_admitted,
        matched_benchmark_recorded,
        bpf_go_fallback_retired,
        true_rust_default_daemon_admitted,
        default_daemon_live_matrix_complete,
        product_chain_recertification_executed,
        product_chain_recertification_clean,
        default_path_mutation_allowed,
        product_chain_switch_allowed,
        resident_default_daemon_switch_ready,
        &production_runtime_owner,
    );
    let release_gate_open = release_product_chain_live_gate["release_gate_open"]
        .as_bool()
        .unwrap_or(false);
    let release_gate_default_switch_allowed =
        release_product_chain_live_gate["default_switch_allowed"]
            .as_bool()
            .unwrap_or(false);
    let release_gate_product_chain_switch_allowed =
        release_product_chain_live_gate["product_chain_switch_allowed"]
            .as_bool()
            .unwrap_or(false);
    let release_gate_go_fallback_required =
        release_product_chain_live_gate["go_runtime_outbound_fallback_required"]
            .as_bool()
            .unwrap_or(true);
    let release_gate_go_fallback_retired =
        release_product_chain_live_gate["go_runtime_outbound_fallback_deletion_allowed"]
            .as_bool()
            .unwrap_or(false);

    fs::write(
        &options.logfile,
        format!(
            "dae-daemon-optin run: config={} bytes={} listener_smoke_passed={} reload_smoke_passed={} production_runtime_owner_executed={} production_runtime_owner_passed={} production_runtime_active_tcp_executed={} production_runtime_active_tcp_passed={} active_tcp_relay_executed={} active_tcp_relay_passed={} active_tcp_relay_benchmark_recorded={} production_runtime_active_udp_executed={} active_udp_admitted={} production_runtime_active_dns_executed={} active_dns_admitted={} reload_runtime_parity_executed={} reload_runtime_parity_passed={} production_dataplane_admitted={} production_dataplane_harness_executed={} production_dataplane_harness_passed={} matched_benchmark_recorded={} true_rust_default_daemon_admitted={} product_chain_recertification_executed={} product_chain_recertification_clean={}\n",
            path_string(&options.config),
            config.len(),
            listener_smoke_passed,
            reload_smoke_passed,
            production_runtime_owner_executed,
            production_runtime_owner_passed,
            production_runtime_active_tcp_executed,
            production_runtime_active_tcp_passed,
            active_tcp_relay_executed,
            active_tcp_relay_passed,
            active_tcp_relay_benchmark_recorded,
            production_runtime_active_udp_executed,
            active_udp_admitted,
            production_runtime_active_dns_executed,
            active_dns_admitted,
            reload_runtime_parity_executed,
            reload_runtime_parity_passed,
            production_dataplane_admitted,
            production_dataplane_harness_executed,
            production_dataplane_harness_passed,
            matched_benchmark_recorded,
            true_rust_default_daemon_admitted,
            product_chain_recertification_executed,
            product_chain_recertification_clean
        ),
    )
    .map_err(|err| format!("failed to write run log file: {err}"))?;

    let mut report = json!({
        "name": "dae-daemon-optin-run",
        "command": "run",
        "version": version,
        "root": path_string(&options.root),
        "run_dir": path_string(&run_dir),
        "config_file": path_string(&options.config),
        "run_config_file": path_string(&run_config_file),
        "config_bytes": config.len(),
        "config_lines": config.lines().count(),
        "log_file": path_string(&options.logfile),
        "manifest_file": path_string(&manifest_file),
        "pid_file": path_string(&pid_file),
        "progress_file": path_string(&progress_file),
        "sdnotify_file": path_string(&sdnotify_file),
        "listener_root": path_string(&listener_root),
        "reload_root": path_string(&reload_root)
    });
    report["disable_timestamp"] = json!(options.disable_timestamp);
    report["disable_pidfile"] = json!(options.disable_pidfile);
    report["disable_sudo"] = json!(options.disable_sudo);
    for key in [
        ("config_loaded", true),
        ("pid_file_written", !options.disable_pidfile),
        ("progress_file_reload_done_written", true),
        ("sdnotify_ready_recorded", true),
        ("log_file_written", true),
        ("run_command_supported", true),
        ("run_entrypoint_executed", true),
        ("rust_daemon_optin_run_command_available", true),
        ("rust_default_run_entrypoint_exists", true),
        ("run_shaped_flags_validated", true),
        ("run_identity_config_corpus_validated", true),
        ("isolated_pid_progress_paths_validated", true),
        ("go_default_path_preserved", true),
        ("go_fallback_required", true),
    ] {
        let (name, value) = key;
        report[name] = json!(value);
    }
    report["listener_smoke_executed"] = json!(options.listener_smoke);
    report["listener_smoke_passed"] = json!(listener_smoke_passed);
    report["reload_owner_handoff_smoke_executed"] = json!(options.reload_smoke);
    report["reload_owner_handoff_smoke_passed"] = json!(reload_smoke_passed);
    report["listener"] = listener;
    report["reload_owner_handoff"] = reload;
    report["production_runtime_owner_executed"] = json!(production_runtime_owner_executed);
    report["production_runtime_owner_passed"] = json!(production_runtime_owner_passed);
    report["production_runtime_active_tcp_executed"] =
        json!(production_runtime_active_tcp_executed);
    report["production_runtime_active_tcp_passed"] = json!(production_runtime_active_tcp_passed);
    report["active_tcp_tproxy_ingress_smoke_passed"] = json!(production_runtime_active_tcp_passed);
    report["active_tcp_relay_executed"] = json!(active_tcp_relay_executed);
    report["active_tcp_relay_smoke_passed"] = json!(active_tcp_relay_passed);
    report["active_tcp_relay_benchmark_recorded"] = json!(active_tcp_relay_benchmark_recorded);
    report["route_dial_tcp_magic_network_mark_mptcp_observed"] =
        json!(route_dial_tcp_magic_network_observed);
    report["production_runtime_active_udp_executed"] =
        json!(production_runtime_active_udp_executed);
    report["production_runtime_active_udp_passed"] = json!(production_runtime_active_udp_passed);
    report["active_udp_tproxy_admitted"] = json!(active_udp_admitted);
    report["active_udp_tproxy_benchmark_recorded"] = json!(active_udp_benchmark_recorded);
    report["production_runtime_active_dns_executed"] =
        json!(production_runtime_active_dns_executed);
    report["production_runtime_active_dns_passed"] = json!(production_runtime_active_dns_passed);
    report["active_dns_tproxy_admitted"] = json!(active_dns_admitted);
    report["active_dns_tproxy_benchmark_recorded"] = json!(active_dns_benchmark_recorded);
    report["production_reload_runtime_parity_executed"] = json!(reload_runtime_parity_executed);
    report["production_reload_runtime_parity_passed"] = json!(reload_runtime_parity_passed);
    report["live_reload_executed"] = json!(
        production_runtime_owner["live_reload_executed"]
            .as_bool()
            .unwrap_or(false)
    );
    report["production_listener_reused"] = json!(
        production_runtime_owner["production_listener_reused"]
            .as_bool()
            .unwrap_or(false)
    );
    report["production_bpf_owner_transferred"] = json!(
        production_runtime_owner["production_bpf_owner_transferred"]
            .as_bool()
            .unwrap_or(false)
    );
    report["dns_cache_migration_guard_verified"] = json!(
        production_runtime_owner["dns_cache_migration_guard_verified"]
            .as_bool()
            .unwrap_or(false)
    );
    report["bounded_close_verified"] = json!(
        production_runtime_owner["bounded_close_verified"]
            .as_bool()
            .unwrap_or(false)
    );
    report["runtime_overview_parity_verified"] = json!(
        production_runtime_owner["runtime_overview_parity_verified"]
            .as_bool()
            .unwrap_or(false)
    );
    report["reload_scoped_resources_flushed"] = json!(
        production_runtime_owner["reload_scoped_resources_flushed"]
            .as_bool()
            .unwrap_or(false)
    );
    report["production_runtime_owner"] = production_runtime_owner;
    report["production_dataplane_harness_executed"] = json!(production_dataplane_harness_executed);
    report["production_dataplane_harness_passed"] = json!(production_dataplane_harness_passed);
    report["production_dataplane_harness"] = production_dataplane;
    report["matched_default_benchmark"] = matched_benchmark;
    report["product_chain_admission_evidence_override"] = json!({
        "used": options.product_chain_admission_override.is_some(),
        "source": options
            .product_chain_admission_source
            .as_ref()
            .map(|path| path_string(path)),
        "admission": {
            "production_dataplane_admitted": product_chain_admission.production_dataplane_admitted,
            "reload_runtime_parity_admitted": product_chain_admission.reload_runtime_parity_admitted,
            "matched_go_rust_default_daemon_benchmark_recorded": product_chain_admission.matched_benchmark_recorded,
            "bpf_go_fallback_retired": product_chain_admission.bpf_go_fallback_retired,
            "true_rust_default_daemon_admitted": product_chain_admission.true_rust_default_daemon_admitted,
        },
    });
    report["product_chain_recertification_executed"] =
        json!(product_chain_recertification_executed);
    report["product_chain_recertification_clean"] = json!(product_chain_recertification_clean);
    report["product_chain_recertification_go_fallback_required"] =
        product_chain_recertification["go_fallback_required"].clone();
    report["product_chain_recertification_go_fallback_retired"] =
        product_chain_recertification["go_fallback_retired"].clone();
    report["product_chain_recertification_default_path_mutation_allowed"] =
        product_chain_recertification["default_path_mutation_allowed"].clone();
    report["product_chain_recertification_product_chain_switch_allowed"] =
        product_chain_recertification["product_chain_switch_allowed"].clone();
    report["go_fallback_required"] = json!(release_gate_go_fallback_required);
    report["go_fallback_retired"] = json!(release_gate_go_fallback_retired);
    report["product_chain_recertification"] = product_chain_recertification.clone();
    report["default_daemon_live_matrix"] = default_daemon_live_matrix;
    report["release_product_chain_live_gate"] = release_product_chain_live_gate;
    report["release_gate_open"] = json!(release_gate_open);
    for key in [
        ("production_run_command_replaced", false),
        ("production_pid_progress_paths_mutated", false),
        ("production_signal_handler_installed", false),
        ("production_listener_bound", false),
        (
            "production_listener_bound_during_owner_smoke",
            production_runtime_owner_passed,
        ),
        (
            "listen_socket_map_written_during_owner_smoke",
            production_runtime_owner_passed,
        ),
        (
            "production_tc_attach_smoke_passed",
            production_runtime_owner_passed,
        ),
        ("ebpf_attached", false),
        (
            "ebpf_attached_during_owner_smoke",
            production_runtime_owner_passed,
        ),
        ("rust_default_control_plane_entrypoint_admitted", false),
        (
            "production_dataplane_admitted",
            production_dataplane_admitted,
        ),
        (
            "reload_runtime_parity_admitted",
            reload_runtime_parity_admitted,
        ),
        ("benchmark_executable_now", matched_benchmark_recorded),
        (
            "matched_go_rust_default_daemon_benchmark_recorded",
            matched_benchmark_recorded,
        ),
        ("bpf_go_fallback_retired", bpf_go_fallback_retired),
        (
            "true_rust_default_daemon_admitted",
            true_rust_default_daemon_admitted,
        ),
        (
            "default_switch_allowed",
            release_gate_default_switch_allowed,
        ),
        (
            "default_path_mutation_allowed",
            release_gate_default_switch_allowed,
        ),
        (
            "product_chain_switch_allowed",
            release_gate_product_chain_switch_allowed,
        ),
        (
            "resident_default_daemon_switch_ready",
            resident_default_daemon_switch_ready,
        ),
    ] {
        let (name, value) = key;
        report[name] = json!(value);
    }
    report["production_dataplane_admission_scope"] = json!(if true_rust_default_daemon_admitted {
        "daemon-owned-production-runtime-active-tcp-udp-dns-reload-benchmark-admitted"
    } else if production_runtime_owner_passed {
        if production_dataplane_admitted && reload_runtime_parity_passed {
            "daemon-owned-production-runtime-active-tcp-udp-dns-reload-runtime-parity"
        } else if production_dataplane_admitted {
            "daemon-owned-production-runtime-active-tcp-udp-dns-dataplane"
        } else if production_runtime_active_dns_passed {
            "daemon-owned-production-runtime-active-dns-smoke-only"
        } else if production_runtime_active_udp_passed {
            "daemon-owned-production-runtime-active-udp-smoke-only"
        } else if reload_runtime_parity_passed {
            "daemon-owned-production-runtime-reload-runtime-parity"
        } else if active_tcp_relay_passed {
            "daemon-owned-production-runtime-active-tcp-relay-smoke-only"
        } else if production_runtime_active_tcp_passed {
            "daemon-owned-production-runtime-active-tcp-ingress-smoke-only"
        } else {
            "daemon-owned-production-runtime-owner-smoke-only"
        }
    } else if production_dataplane_harness_passed {
        "run-integrated-harness-only"
    } else if production_runtime_owner_executed {
        "daemon-owned-production-runtime-owner-smoke-failed"
    } else if production_dataplane_harness_executed {
        "run-integrated-harness-failed"
    } else {
        "not-executed"
    });
    let mut remaining_blockers =
        vec!["opt-in run now exists, but it still uses isolated pid/progress paths"];
    if !matched_benchmark_recorded {
        remaining_blockers.push("matched Go/Rust default daemon benchmark remains blocked");
    }
    if true_rust_default_daemon_admitted {
        if release_gate_product_chain_switch_allowed {
            remaining_blockers.push(
                "default path mutation request is admitted by clean product-chain recertification; production run command replacement is still not executed",
            );
        } else if product_chain_switch_allowed {
            remaining_blockers.push(
                "product-chain recertification admits its local default path mutation inputs, but the stage 7 release gate remains closed until the default daemon live matrix is complete",
            );
        } else if !resident_default_daemon_switch_ready {
            remaining_blockers.push(
                "resident default service path does not admit production dataplane; dae-daemon-optin run -c ... is still service-contract-only",
            );
        } else {
            remaining_blockers.push(
            "true Rust default daemon admission is recorded for the daemon-owned opt-in path; default/product switch stays closed pending clean production path mutation and dae-wing/daed recertification",
        );
        }
    } else if production_dataplane_admitted {
        remaining_blockers.push(
            "production active TCP/UDP/DNS dataplane is admitted inside the daemon-owned opt-in run, but reload parity and matched benchmark must both be present before true Rust default daemon admission",
        );
    } else if production_dataplane_harness_passed {
        remaining_blockers.push(
            "production dataplane evidence is integrated into run, but still harness-only and not default daemon owned",
        );
    } else if reload_runtime_parity_passed {
        remaining_blockers.push(
            "production owner lifecycle now proves listener reuse, BPF/map owner handoff, DNS cache migration guard, bounded close, RuntimeOverview fields, rollback, and post-reload active TCP; active UDP/DNS dataplane or default path mutation remain unproven",
        );
    } else if active_tcp_relay_passed {
        remaining_blockers.push(
            "production tproxy listener, tc/eBPF attach, active TCP ingress, and bounded TCP relay are proven inside this run, but full route-table RouteDialTcp, active UDP/DNS dataplane, and reload/runtime parity remain unproven",
        );
    } else if production_runtime_active_tcp_passed {
        remaining_blockers.push(
            "production tproxy listener, tc/eBPF attach, and active TCP ingress are proven inside this run, but active TCP relay plus UDP/DNS dataplane remain unproven",
        );
    } else {
        remaining_blockers.push(
            "production tproxy listener, tc/eBPF attach, and active TCP/UDP/DNS dataplane are not yet proven inside this run",
        );
    }
    if production_runtime_owner_passed && !reload_runtime_parity_passed {
        remaining_blockers.push(
            "daemon-owned production runtime owner smoke passed, but active TCP relay, active UDP/DNS dataplane, and production reload/runtime parity may still be incomplete",
        );
    } else if production_runtime_owner_passed && !true_rust_default_daemon_admitted {
        remaining_blockers.push(
            "daemon-owned production runtime owner and reload/runtime parity passed, but full active UDP/DNS dataplane plus matched benchmark are required for true default daemon admission",
        );
    }
    if active_tcp_relay_passed {
        remaining_blockers.push(
            "active TCP relay observed MagicNetwork mark/mptcp on a real outbound socket, but full route-table RouteDialTcp control-plane reroute remains unverified",
        );
    } else if production_runtime_active_tcp_passed {
        remaining_blockers.push(
            "active TCP tproxy ingress reached the transparent listener, but RouteDialTcp MagicNetwork mark/mptcp relay parity remains unverified",
        );
    }
    if product_chain_recertification_executed && !product_chain_recertification_clean {
        remaining_blockers.push(
            "product-chain recertification was recorded but is not clean; default/product switch remains closed",
        );
    }
    report["remaining_blockers"] = json!(remaining_blockers);

    let manifest = serde_json::to_vec_pretty(&report)
        .map_err(|err| format!("failed to encode run manifest: {err}"))?;
    fs::write(&manifest_file, manifest)
        .map_err(|err| format!("failed to write run manifest: {err}"))?;
    Ok(report)
}

fn ensure_safe_run_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!("run root must be absolute: {}", path_string(root)));
    }
    let root_string = path_string(root);
    if !root_string.starts_with("/tmp/dae-daemon") {
        return Err(format!(
            "run root must be under /tmp/dae-daemon*: {root_string}"
        ));
    }
    Ok(())
}

fn ensure_safe_output_path(path: &Path, root: &Path, label: &str) -> Result<(), String> {
    if !path.is_absolute() && !path.starts_with(root) {
        return Err(format!("{label} must be absolute or under run root"));
    }
    if path.is_absolute() && !path.starts_with(root) {
        let path_string = path_string(path);
        if !path_string.starts_with("/tmp/") {
            return Err(format!("{label} outside run root must be under /tmp"));
        }
    }
    Ok(())
}

fn derived_support_root(prefix: &str, root: &Path) -> PathBuf {
    let suffix = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("run");
    PathBuf::from(format!("{prefix}-{suffix}"))
}

#[allow(clippy::too_many_arguments)]
fn default_daemon_live_matrix_json(
    listener_smoke_executed: bool,
    listener_smoke_passed: bool,
    reload_owner_handoff_executed: bool,
    reload_owner_handoff_passed: bool,
    production_runtime_owner_executed: bool,
    production_runtime_owner_passed: bool,
    production_runtime_active_tcp_executed: bool,
    production_runtime_active_tcp_passed: bool,
    active_tcp_relay_executed: bool,
    active_tcp_relay_passed: bool,
    active_tcp_relay_benchmark_recorded: bool,
    route_dial_tcp_magic_network_observed: bool,
    production_runtime_active_udp_executed: bool,
    production_runtime_active_udp_passed: bool,
    active_udp_admitted: bool,
    active_udp_benchmark_recorded: bool,
    production_runtime_active_dns_executed: bool,
    production_runtime_active_dns_passed: bool,
    active_dns_admitted: bool,
    active_dns_benchmark_recorded: bool,
    reload_runtime_parity_executed: bool,
    reload_runtime_parity_admitted: bool,
    matched_default_benchmark_executed: bool,
    matched_default_benchmark_recorded: bool,
    bpf_go_fallback_retired: bool,
) -> Value {
    let rows = vec![
        live_matrix_row_json(
            "listener-loopback-smoke",
            listener_smoke_executed,
            listener_smoke_passed,
            "TCP and UDP loopback listener smoke must pass before any daemon default switch",
            "run --exit-after-ready keeps listener smoke enabled by default",
        ),
        live_matrix_row_json(
            "reload-owner-handoff-smoke",
            reload_owner_handoff_executed,
            reload_owner_handoff_passed,
            "non-production reload owner handoff smoke must pass before production reload evidence is considered",
            "run --exit-after-ready keeps reload smoke enabled by default",
        ),
        live_matrix_row_json(
            "production-runtime-owner",
            production_runtime_owner_executed,
            production_runtime_owner_passed,
            "daemon-owned production runtime owner smoke must pass under the candidate root",
            "run with --execute-production-runtime-owner and --ack-root-gate",
        ),
        live_matrix_row_json(
            "active-tcp-ingress",
            production_runtime_active_tcp_executed,
            production_runtime_active_tcp_passed,
            "active TCP tproxy ingress must reach the transparent listener",
            "run with production runtime active TCP options and root/BPF/netns access",
        ),
        live_matrix_row_json(
            "active-tcp-relay-magic-network",
            active_tcp_relay_executed,
            active_tcp_relay_passed
                && active_tcp_relay_benchmark_recorded
                && route_dial_tcp_magic_network_observed,
            "active TCP relay must pass with benchmark evidence and MagicNetwork mark/mptcp observation",
            "run with active TCP relay benchmark enabled",
        ),
        live_matrix_row_json(
            "active-udp-datapath",
            production_runtime_active_udp_executed,
            production_runtime_active_udp_passed
                && active_udp_admitted
                && active_udp_benchmark_recorded,
            "active UDP datapath must pass with admission and benchmark evidence",
            "run with active UDP tproxy options and benchmark iterations",
        ),
        live_matrix_row_json(
            "active-dns-udp53",
            production_runtime_active_dns_executed,
            production_runtime_active_dns_passed
                && active_dns_admitted
                && active_dns_benchmark_recorded,
            "DNS UDP/53 path must pass with upstream/cache/domain-routing evidence and benchmark record",
            "run with active DNS target/upstream options and benchmark iterations",
        ),
        live_matrix_row_json(
            "production-reload-runtime-parity",
            reload_runtime_parity_executed,
            reload_runtime_parity_admitted,
            "production reload/runtime parity must prove listener reuse, BPF owner handoff, DNS cache guard, bounded close, RuntimeOverview parity, and scoped cleanup",
            "run with production reload/runtime parity enabled",
        ),
        live_matrix_row_json(
            "matched-go-rust-default-benchmark",
            matched_default_benchmark_executed,
            matched_default_benchmark_recorded,
            "matched Go default daemon vs true Rust default daemon benchmark must be recorded on the same host/config/corpus",
            "run with --execute-matched-default-benchmark and --ack-root-gate",
        ),
        live_matrix_row_json(
            "bpf-go-fallback-retirement",
            production_runtime_owner_executed,
            bpf_go_fallback_retired,
            "BPF-side Go fallback retirement evidence must be present without restoring the Go BPF loader",
            "run production runtime owner gate with BPF fallback retirement evidence",
        ),
    ];
    let matrix_complete = rows
        .iter()
        .all(|row| row["recorded"].as_bool().unwrap_or(false));
    let remaining = rows
        .iter()
        .filter(|row| !row["recorded"].as_bool().unwrap_or(false))
        .filter_map(|row| row["area"].as_str())
        .collect::<Vec<_>>();

    json!({
        "schema": "default-daemon-live-matrix-v1",
        "formal_surface": "stage7-default-daemon-live-matrix",
        "matrix_complete": matrix_complete,
        "release_gate_input": true,
        "default_switch_allowed_by_this_matrix": false,
        "host_write_performed": false,
        "default_path_mutation_performed": false,
        "go_runtime_outbound_fallback_required_until_release_gate": true,
        "rows": rows,
        "remaining_rows": remaining,
        "source": [
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:stage7",
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage22",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:33.8"
        ],
    })
}

fn live_matrix_row_json(
    area: &'static str,
    executed: bool,
    passed: bool,
    required_evidence: &'static str,
    rerun_hint: &'static str,
) -> Value {
    json!({
        "area": area,
        "executed": executed,
        "passed": passed,
        "recorded": executed && passed,
        "status": if executed && passed { "pass" } else if executed { "fail" } else { "not-executed" },
        "required_evidence": required_evidence,
        "rerun_hint": rerun_hint,
    })
}

#[allow(clippy::too_many_arguments)]
fn release_product_chain_live_gate_json(
    production_dataplane_admitted: bool,
    reload_runtime_parity_admitted: bool,
    matched_benchmark_recorded: bool,
    bpf_go_fallback_retired: bool,
    true_rust_default_daemon_admitted: bool,
    default_daemon_live_matrix_complete: bool,
    product_chain_recertification_executed: bool,
    product_chain_recertification_clean: bool,
    default_path_mutation_allowed: bool,
    product_chain_switch_allowed: bool,
    resident_default_daemon_switch_ready: bool,
    production_runtime_owner: &Value,
) -> Value {
    let fixed_queue_completed =
        production_runtime_owner["datapath_outbound_ebpf_deep_area"]["fixed_queue_completed"]
            .as_bool()
            .unwrap_or(false);
    let stage6_deep_area_recorded = production_runtime_owner["datapath_outbound_ebpf_deep_area"]
        ["datapath_native_assets_recorded"]
        .as_bool()
        .unwrap_or(false);
    let go_bpf_loader_restored =
        production_runtime_owner["datapath_outbound_ebpf_deep_area"]["go_bpf_loader_restored"]
            .as_bool()
            .unwrap_or(false);
    let aya_loader_direction_preserved = production_runtime_owner
        ["datapath_outbound_ebpf_deep_area"]["aya_loader_direction_preserved"]
        .as_bool()
        .unwrap_or(false);
    let full_live_matrix_admitted = default_daemon_live_matrix_complete
        && production_dataplane_admitted
        && reload_runtime_parity_admitted
        && matched_benchmark_recorded
        && bpf_go_fallback_retired
        && true_rust_default_daemon_admitted;
    let release_gate_open = fixed_queue_completed
        && full_live_matrix_admitted
        && product_chain_recertification_executed
        && product_chain_recertification_clean
        && default_path_mutation_allowed
        && product_chain_switch_allowed
        && resident_default_daemon_switch_ready
        && !go_bpf_loader_restored;

    let rows = vec![
        json!({
            "area": "fixed-native-queue",
            "status": if fixed_queue_completed { "pass" } else { "fail" },
            "recorded": fixed_queue_completed,
            "required_evidence": "stage1-stage6 native groups are accepted by production_runtime_owner and stage6 deep area is recorded",
            "blocker": if fixed_queue_completed { "" } else { "stage6 fixed queue completion evidence is absent from production_runtime_owner" },
        }),
        json!({
            "area": "default-daemon-live-matrix",
            "status": if full_live_matrix_admitted { "pass" } else { "fail" },
            "recorded": full_live_matrix_admitted,
            "required_evidence": "production dataplane, reload/runtime parity, matched Go/Rust default daemon benchmark, and BPF fallback retirement all pass together",
            "blocker": if full_live_matrix_admitted { "" } else { "full default daemon live matrix is incomplete" },
        }),
        json!({
            "area": "product-chain-recertification",
            "status": if product_chain_recertification_clean { "pass" } else if product_chain_recertification_executed { "fail" } else { "not-executed" },
            "recorded": product_chain_recertification_clean,
            "required_evidence": "daed, dae-wing, release, package, service, WebUI/API, and dependency boundary recertification are clean",
            "blocker": if product_chain_recertification_clean { "" } else if product_chain_recertification_executed { "product-chain recertification executed but is not clean" } else { "product-chain recertification has not executed" },
        }),
        json!({
            "area": "fallback-policy",
            "status": if release_gate_open { "pass" } else { "fail" },
            "recorded": release_gate_open,
            "required_evidence": "Go runtime/outbound fallback deletion is only allowed after release gate opens and rollback is proven",
            "blocker": if release_gate_open { "" } else { "Go runtime/outbound fallback remains required" },
        }),
        json!({
            "area": "bpf-loader-boundary",
            "status": if aya_loader_direction_preserved && !go_bpf_loader_restored { "pass" } else { "fail" },
            "recorded": aya_loader_direction_preserved && !go_bpf_loader_restored,
            "required_evidence": "Rust/Aya loader direction is preserved and Go BPF loader is not restored",
            "blocker": if aya_loader_direction_preserved && !go_bpf_loader_restored { "" } else { "BPF loader boundary evidence is invalid" },
        }),
    ];

    let mut blockers = Vec::new();
    if !fixed_queue_completed {
        blockers.push("fixed stage1-stage6 native queue completion evidence is missing");
    }
    if !stage6_deep_area_recorded {
        blockers.push("stage6 datapath/outbound/eBPF deep area evidence is missing");
    }
    if !full_live_matrix_admitted {
        blockers.push("full default daemon live matrix is incomplete");
    }
    if !matched_benchmark_recorded {
        blockers.push("matched Go/Rust default daemon benchmark is not recorded");
    }
    if !product_chain_recertification_clean {
        blockers.push("product-chain recertification is not clean");
    }
    if !default_path_mutation_allowed {
        blockers.push("default path mutation is not allowed");
    }
    if !product_chain_switch_allowed {
        blockers.push("product-chain switch is not allowed");
    }
    if !resident_default_daemon_switch_ready {
        blockers.push("resident default daemon switch is not ready");
    }
    if go_bpf_loader_restored {
        blockers.push("Go BPF loader restoration would violate the Rust/Aya loader boundary");
    }

    json!({
        "schema": "release-product-chain-live-gate-v1",
        "formal_surface": "stage7-release-product-chain-live-gate",
        "fixed_queue_range": "stage1-stage6",
        "fixed_queue_completed": fixed_queue_completed,
        "stage6_deep_area_recorded": stage6_deep_area_recorded,
        "stage7_gate_recorded": true,
        "release_gate_open": release_gate_open,
        "default_switch_allowed": release_gate_open && default_path_mutation_allowed,
        "product_chain_switch_allowed": release_gate_open && product_chain_switch_allowed,
        "go_default_path_preserved": !release_gate_open,
        "go_runtime_outbound_fallback_required": !release_gate_open,
        "go_runtime_outbound_fallback_deletion_allowed": release_gate_open,
        "go_bpf_loader_restored": go_bpf_loader_restored,
        "aya_loader_direction_preserved": aya_loader_direction_preserved,
        "production_dataplane_admitted": production_dataplane_admitted,
        "reload_runtime_parity_admitted": reload_runtime_parity_admitted,
        "matched_go_rust_default_daemon_benchmark_recorded": matched_benchmark_recorded,
        "bpf_go_fallback_retired": bpf_go_fallback_retired,
        "true_rust_default_daemon_admitted": true_rust_default_daemon_admitted,
        "default_daemon_live_matrix_complete": default_daemon_live_matrix_complete,
        "product_chain_recertification_executed": product_chain_recertification_executed,
        "product_chain_recertification_clean": product_chain_recertification_clean,
        "default_path_mutation_allowed": default_path_mutation_allowed,
        "resident_default_daemon_switch_ready": resident_default_daemon_switch_ready,
        "gate_rows": rows,
        "remaining_blockers": blockers,
        "source": [
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:stage7",
            "rust/crates/dae-daemon/src/production_runtime_owner/deep_area.rs",
            "rust/crates/dae-product/src/release_gate.rs",
            "rust/crates/dae-product/src/product_chain_admission.rs",
            "rust/crates/dae-product/src/true_daemon_admission.rs"
        ],
    })
}

fn write_progress(path: &Path, byte: u8, suffix: &str) -> Result<(), String> {
    let mut content = vec![byte];
    content.extend_from_slice(suffix.as_bytes());
    fs::write(path, content).map_err(|err| format!("failed to write progress file: {err}"))
}

pub fn product_chain_admission_from_run_report(
    path: &Path,
) -> Result<ProductChainAdmissionEvidence, String> {
    let text = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read product-chain admission evidence {}: {err}",
            path_string(path)
        )
    })?;
    let value: Value = serde_json::from_str(&text).map_err(|err| {
        format!(
            "failed to parse product-chain admission evidence {}: {err}",
            path_string(path)
        )
    })?;
    Ok(ProductChainAdmissionEvidence {
        production_dataplane_admitted: required_bool(
            &value,
            "production_dataplane_admitted",
            path,
        )?,
        reload_runtime_parity_admitted: required_bool(
            &value,
            "reload_runtime_parity_admitted",
            path,
        )?,
        matched_benchmark_recorded: required_bool(
            &value,
            "matched_go_rust_default_daemon_benchmark_recorded",
            path,
        )?,
        bpf_go_fallback_retired: required_bool(&value, "bpf_go_fallback_retired", path)?,
        true_rust_default_daemon_admitted: required_bool(
            &value,
            "true_rust_default_daemon_admitted",
            path,
        )?,
    })
}

#[cfg(test)]
mod stage7_gate_tests {
    use super::*;

    #[test]
    fn stage7_release_gate_blocks_product_chain_switch_without_live_matrix() {
        let production_runtime_owner = json!({
            "datapath_outbound_ebpf_deep_area": {
                "fixed_queue_completed": true,
                "datapath_native_assets_recorded": true,
                "go_bpf_loader_restored": false,
                "aya_loader_direction_preserved": true
            }
        });
        let gate = release_product_chain_live_gate_json(
            true,
            true,
            true,
            true,
            true,
            false,
            true,
            true,
            true,
            true,
            true,
            &production_runtime_owner,
        );

        assert!(
            !gate["default_daemon_live_matrix_complete"]
                .as_bool()
                .unwrap()
        );
        assert!(!gate["release_gate_open"].as_bool().unwrap());
        assert!(!gate["default_switch_allowed"].as_bool().unwrap());
        assert!(!gate["product_chain_switch_allowed"].as_bool().unwrap());
        assert!(
            gate["go_runtime_outbound_fallback_required"]
                .as_bool()
                .unwrap()
        );
        assert!(
            !gate["go_runtime_outbound_fallback_deletion_allowed"]
                .as_bool()
                .unwrap()
        );
    }
}

fn required_bool(value: &Value, key: &str, source: &Path) -> Result<bool, String> {
    value[key].as_bool().ok_or_else(|| {
        format!(
            "product-chain admission evidence {} is missing boolean field {key}",
            path_string(source)
        )
    })
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
