use super::*;
pub(super) fn run_admission(
    spec: DataplaneAdmissionSpec,
    root: &Path,
    options: &ProductionDataplaneHarnessOptions,
    artifact_dir: &Path,
) -> Result<Value, String> {
    let owner_options = owner_options_for_admission(spec, options);
    let owner_report = production_runtime_owner_report(root, &owner_options).map_err(|err| {
        format!(
            "production dataplane admission {} failed through daemon-owned production runtime owner: {err}",
            spec.check_id
        )
    })?;
    let owner_report_file = artifact_dir.join(format!("{}.owner-report.json", spec.check_id));
    let owner_report_encoded = serde_json::to_vec_pretty(&owner_report).map_err(|err| {
        format!(
            "failed to encode production dataplane owner report for {}: {err}",
            spec.check_id
        )
    })?;
    fs::write(&owner_report_file, owner_report_encoded).map_err(|err| {
        format!(
            "failed to write production dataplane owner report artifact {}: {err}",
            path_string(&owner_report_file)
        )
    })?;

    let blocked = false;
    let pass_value = owner_report[spec.pass_key].as_bool().unwrap_or(false);
    let passed = pass_value;
    let benchmark_recorded = spec
        .benchmark_recorded_key
        .and_then(|key| owner_report[key].as_bool())
        .unwrap_or(false);
    let benchmark = if benchmark_recorded {
        benchmark_value(spec.check_id, &owner_report)
    } else {
        Value::Null
    };

    let summary = json!({
        "check_id": spec.check_id,
        "profile": spec.profile,
        "root": path_string(root),
        "passed": passed,
        "blocked": blocked,
        "pass_key": spec.pass_key,
        "pass_value": pass_value,
        "benchmark_recorded_key": spec.benchmark_recorded_key,
        "benchmark_recorded": benchmark_recorded,
        "benchmark": benchmark,
        "owner_report_file": path_string(&owner_report_file),
        "owner_scope": owner_report["production_runtime_owner_scope"].clone(),
        "cleanup": cleanup_summary(&owner_report),
        "selected_evidence": selected_evidence(spec.check_id, &owner_report),
    });
    let summary_file = artifact_dir.join(format!("{}.summary.json", spec.check_id));
    let encoded = serde_json::to_vec_pretty(&summary).map_err(|err| {
        format!(
            "failed to encode production dataplane summary for {}: {err}",
            spec.check_id
        )
    })?;
    fs::write(&summary_file, encoded).map_err(|err| {
        format!(
            "failed to write production dataplane summary artifact {}: {err}",
            path_string(&summary_file)
        )
    })?;

    if !passed {
        return Err(format!(
            "production dataplane admission {} failed; summary={}",
            spec.check_id, summary
        ));
    }
    Ok(summary)
}

pub(super) fn owner_options_for_admission(
    spec: DataplaneAdmissionSpec,
    options: &ProductionDataplaneHarnessOptions,
) -> ProductionRuntimeOwnerOptions {
    let mut owner_options = ProductionRuntimeOwnerOptions {
        execute: true,
        ack_root_gate: options.ack_root_gate,
        active_tcp_benchmark_iters: options.benchmark_iters,
        active_udp_benchmark_iters: options.benchmark_iters,
        active_dns_benchmark_iters: options.benchmark_iters,
        ..ProductionRuntimeOwnerOptions::default()
    };

    match spec.check_id {
        "production-param-listener" => {}
        "active-tcp-tproxy-ingress" => {
            owner_options.execute_active_tcp = true;
        }
        "active-tcp-route-dial-relay" => {
            owner_options.execute_active_tcp = true;
            owner_options.execute_active_tcp_relay = true;
        }
        "active-udp-tproxy-endpoint" => {
            owner_options.execute_active_tcp = true;
            owner_options.execute_active_udp = true;
        }
        "active-dns-tproxy-cache" => {
            owner_options.execute_active_tcp = true;
            owner_options.execute_active_udp = true;
            owner_options.execute_active_dns = true;
            owner_options.active_dns_target_ip = options.active_dns_target_ip.clone();
            owner_options.active_dns_target_port = options.active_dns_target_port;
        }
        _ => {}
    }
    owner_options
}

pub(super) fn dataplane_admission_specs() -> [DataplaneAdmissionSpec; 5] {
    [
        DataplaneAdmissionSpec {
            check_id: "production-param-listener",
            profile: "daemon-owned-production-param-listener",
            root_prefix: "/tmp/dae-daemon-production-param-listener",
            pass_key: "daemon_owned_production_runtime_owner_smoke_passed",
            benchmark_recorded_key: None,
        },
        DataplaneAdmissionSpec {
            check_id: "active-tcp-tproxy-ingress",
            profile: "daemon-owned-active-tcp-tproxy-ingress",
            root_prefix: "/tmp/dae-daemon-active-tcp-tproxy",
            pass_key: "active_tcp_tproxy_ingress_smoke_passed",
            benchmark_recorded_key: None,
        },
        DataplaneAdmissionSpec {
            check_id: "active-tcp-route-dial-relay",
            profile: "daemon-owned-active-tcp-route-dial-relay",
            root_prefix: "/tmp/dae-daemon-active-tcp-relay",
            pass_key: "active_tcp_relay_smoke_passed",
            benchmark_recorded_key: Some("active_tcp_relay_benchmark_recorded"),
        },
        DataplaneAdmissionSpec {
            check_id: "active-udp-tproxy-endpoint",
            profile: "daemon-owned-active-udp-tproxy-endpoint",
            root_prefix: "/tmp/dae-daemon-active-udp-tproxy",
            pass_key: "active_udp_tproxy_smoke_passed",
            benchmark_recorded_key: Some("active_udp_tproxy_benchmark_recorded"),
        },
        DataplaneAdmissionSpec {
            check_id: "active-dns-tproxy-cache",
            profile: "daemon-owned-active-dns-tproxy-cache",
            root_prefix: "/tmp/dae-daemon-active-dns-tproxy",
            pass_key: "active_dns_tproxy_smoke_passed",
            benchmark_recorded_key: Some("active_dns_tproxy_benchmark_recorded"),
        },
    ]
}

pub(super) fn admission_root(spec: DataplaneAdmissionSpec, run_root: &Path) -> PathBuf {
    let suffix = run_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(sanitize_suffix)
        .filter(|suffix| !suffix.is_empty())
        .unwrap_or_else(|| "run".to_owned());
    PathBuf::from(format!("{}-{suffix}", spec.root_prefix))
}

pub(super) fn ensure_tmp_admission_root(root: &Path, prefix: &str) -> Result<(), String> {
    if !root.is_absolute() || root.parent() != Some(Path::new("/tmp")) {
        return Err(format!(
            "production dataplane admission root must be an absolute /tmp child: {}",
            path_string(root)
        ));
    }
    let root = path_string(root);
    if !root.starts_with(prefix) {
        return Err(format!(
            "production dataplane admission root {root} must start with {prefix}"
        ));
    }
    Ok(())
}
