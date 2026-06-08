use super::*;
pub fn production_runtime_owner_report(
    run_root: &Path,
    options: &ProductionRuntimeOwnerOptions,
) -> Result<Value, String> {
    validate_options(options)?;
    ensure_safe_run_root(run_root)?;
    if options.execute && !options.source_object.is_file() {
        return Err(format!(
            "production runtime owner source object does not exist: {}",
            path_string(&options.source_object)
        ));
    }

    let artifact_dir = run_root.join("run").join("production-runtime-owner");
    let manifest_file = artifact_dir.join("production-runtime-owner.json");
    let param_object = artifact_dir.join("bpf_bpfel.param.o");
    let mut checks = preflight_checks(options);
    push_active_tcp_preflight_checks(&mut checks, options);
    push_active_udp_preflight_checks(&mut checks, options);
    push_active_dns_preflight_checks(&mut checks, options);

    if !options.execute {
        return Ok(report_value(
            options,
            &artifact_dir,
            &manifest_file,
            &param_object,
            checks,
            ExecutionEvidence::default(),
        ));
    }

    let blockers = checks
        .iter()
        .filter(|check| check["status"].as_str() != Some("pass"))
        .filter_map(|check| check["blocker"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    if !blockers.is_empty() {
        return Err(format!(
            "production runtime owner preflight failed: {}",
            blockers.join("; ")
        ));
    }

    fs::create_dir_all(&artifact_dir).map_err(|err| {
        format!(
            "failed to create production runtime owner artifact dir {}: {err}",
            path_string(&artifact_dir)
        )
    })?;
    let evidence = execute_owner_smoke(options, &param_object)?;
    let report = report_value(
        options,
        &artifact_dir,
        &manifest_file,
        &param_object,
        checks,
        evidence,
    );
    let encoded = serde_json::to_vec_pretty(&report)
        .map_err(|err| format!("failed to encode production runtime owner report: {err}"))?;
    fs::write(&manifest_file, encoded).map_err(|err| {
        format!(
            "failed to write production runtime owner manifest {}: {err}",
            path_string(&manifest_file)
        )
    })?;
    if report["daemon_owned_production_runtime_owner_smoke_passed"]
        .as_bool()
        .unwrap_or(false)
    {
        Ok(report)
    } else {
        Err(format!(
            "production runtime owner smoke failed; manifest={}",
            path_string(&manifest_file)
        ))
    }
}

pub fn daemon_runtime_native_owner_summary_json() -> Value {
    native_assets::daemon_runtime_native_owner_summary_json()
}

pub fn datapath_outbound_ebpf_deep_area_summary_json() -> Value {
    deep_area::datapath_outbound_ebpf_deep_area_summary_json()
}

pub(super) fn validate_options(options: &ProductionRuntimeOwnerOptions) -> Result<(), String> {
    if options.tproxy_port == 0 {
        return Err("production runtime owner tproxy port must be non-zero".to_owned());
    }
    if options.dae_netns_id == 0 {
        return Err("production runtime owner dae netns id must be non-zero".to_owned());
    }
    if options.execute_active_tcp && !options.execute {
        return Err(
            "production runtime active TCP requires --execute-production-runtime-owner".to_owned(),
        );
    }
    if options.execute_active_tcp_relay && !options.execute_active_tcp {
        return Err(
            "production runtime active TCP relay requires --execute-production-runtime-active-tcp"
                .to_owned(),
        );
    }
    if options.execute_active_udp && !options.execute_active_tcp {
        return Err(
            "production runtime active UDP requires --execute-production-runtime-active-tcp"
                .to_owned(),
        );
    }
    if options.execute_active_dns && !options.execute_active_udp {
        return Err(
            "production runtime active DNS requires --execute-production-runtime-active-udp"
                .to_owned(),
        );
    }
    if options.execute_reload_runtime_parity && !options.execute_active_tcp {
        return Err(
            "production reload/runtime parity requires --execute-production-runtime-active-tcp"
                .to_owned(),
        );
    }
    if options.active_tcp_target_port == 0 {
        return Err("production runtime active TCP target port must be non-zero".to_owned());
    }
    if options.active_tcp_benchmark_iters == 0 {
        return Err(
            "production runtime active TCP benchmark iterations must be non-zero".to_owned(),
        );
    }
    if options.active_udp_target_port == 0 {
        return Err("production runtime active UDP target port must be non-zero".to_owned());
    }
    if options.active_udp_benchmark_iters == 0 {
        return Err(
            "production runtime active UDP benchmark iterations must be non-zero".to_owned(),
        );
    }
    if options.active_dns_target_port != 53 {
        return Err("production runtime active DNS target port must be UDP/53".to_owned());
    }
    if options.active_dns_upstream_port == 0 {
        return Err("production runtime active DNS upstream port must be non-zero".to_owned());
    }
    if options.active_dns_benchmark_iters == 0 {
        return Err(
            "production runtime active DNS benchmark iterations must be non-zero".to_owned(),
        );
    }
    if options.execute && !options.ack_root_gate {
        return Err(
            "production runtime owner requires --ack-root-gate with --execute-production-runtime-owner"
                .to_owned(),
        );
    }
    Ok(())
}
