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
    let resident_dataplane_default_switch_required = true;
    let resident_dataplane_default_switch_ready =
        resident_dataplane_default_switch_ready_from_env();
    let true_rust_default_daemon_admitted = production_dataplane_admitted
        && reload_runtime_parity_admitted
        && matched_benchmark_recorded
        && bpf_go_fallback_retired
        && resident_dataplane_default_switch_ready;
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
    let product_chain_structural_baseline_clean =
        product_chain_recertification["product_chain_structural_baseline_clean"]
            .as_bool()
            .unwrap_or(false);
    let product_chain_default_switch_admission_clean =
        product_chain_recertification["product_chain_default_switch_admission_clean"]
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
        resident_dataplane_default_switch_required,
        resident_dataplane_default_switch_ready,
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
        resident_dataplane_default_switch_ready,
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
    report["resident_dataplane_default_switch_gate"] = json!({
        "required": resident_dataplane_default_switch_required,
        "env": RESIDENT_DATAPLANE_ENV,
        "env_enabled": resident_dataplane_default_switch_ready,
        "ready": resident_dataplane_default_switch_ready,
        "blocker": if resident_dataplane_default_switch_ready {
            Value::Null
        } else {
            json!(format!(
                "{RESIDENT_DATAPLANE_ENV}=1 is required before true Rust default daemon admission"
            ))
        },
        "source": [
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:stage7-resident-dns-udp53-hostwrite",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:DNS/tproxy control-plane routing"
        ],
    });
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
    report["product_chain_structural_baseline_clean"] =
        json!(product_chain_structural_baseline_clean);
    report["product_chain_default_switch_admission_clean"] =
        json!(product_chain_default_switch_admission_clean);
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
            "resident_dataplane_default_switch_required",
            resident_dataplane_default_switch_required,
        ),
        (
            "resident_dataplane_default_switch_ready",
            resident_dataplane_default_switch_ready,
        ),
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
    if !resident_dataplane_default_switch_ready {
        remaining_blockers.push(
            "resident userspace dataplane is not enabled; default switch would redirect tproxy TCP/UDP payloads without the required Rust worker",
        );
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
