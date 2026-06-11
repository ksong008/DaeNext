use super::*;
pub fn production_dataplane_harness_report(
    run_root: &Path,
    options: &ProductionDataplaneHarnessOptions,
) -> Result<Value, String> {
    if options.benchmark_iters == 0 {
        return Err("production dataplane --dataplane-benchmark-iters must be non-zero".to_owned());
    }
    if options.execute && !options.ack_root_gate {
        return Err(
            "production dataplane smoke requires --ack-root-gate with --execute-production-dataplane-smoke"
                .to_owned(),
        );
    }
    let artifact_dir = run_root.join("run").join("production-dataplane");
    let admission_plan = dataplane_admission_specs()
        .into_iter()
        .map(|spec| {
            json!({
                "check_id": spec.check_id,
                "profile": spec.profile,
                "root": path_string(&admission_root(spec, run_root)),
                "pass_key": spec.pass_key,
                "benchmark_recorded_key": spec.benchmark_recorded_key,
            })
        })
        .collect::<Vec<_>>();

    if !options.execute {
        return Ok(base_report(
            options,
            &artifact_dir,
            admission_plan,
            Vec::new(),
            false,
        ));
    }

    fs::create_dir_all(&artifact_dir).map_err(|err| {
        format!(
            "failed to create production dataplane artifact dir {}: {err}",
            path_string(&artifact_dir)
        )
    })?;

    let mut admissions = Vec::new();
    for spec in dataplane_admission_specs() {
        let root = admission_root(spec, run_root);
        ensure_tmp_admission_root(&root, spec.root_prefix)?;
        if root.exists() {
            fs::remove_dir_all(&root).map_err(|err| {
                format!(
                    "failed to remove existing production dataplane admission root {}: {err}",
                    path_string(&root)
                )
            })?;
        }
        let result = run_admission(spec, &root, options, &artifact_dir)?;
        admissions.push(result);
    }

    let passed = admissions
        .iter()
        .all(|admission| admission["passed"].as_bool().unwrap_or(false));
    Ok(base_report(
        options,
        &artifact_dir,
        admission_plan,
        admissions,
        passed,
    ))
}

pub(super) fn base_report(
    options: &ProductionDataplaneHarnessOptions,
    artifact_dir: &Path,
    admission_plan: Vec<Value>,
    admissions: Vec<Value>,
    passed: bool,
) -> Value {
    let admission_pass = |check_id: &str| -> bool {
        admissions
            .iter()
            .find(|entry| entry["check_id"].as_str() == Some(check_id))
            .and_then(|entry| entry["passed"].as_bool())
            .unwrap_or(false)
    };
    let production_param_listener_passed = admission_pass("production-param-listener");
    let active_tcp_tproxy_ingress_passed = admission_pass("active-tcp-tproxy-ingress");
    let active_tcp_route_dial_relay_passed = admission_pass("active-tcp-route-dial-relay");
    let active_udp_tproxy_endpoint_passed = admission_pass("active-udp-tproxy-endpoint");
    let active_dns_tproxy_cache_passed = admission_pass("active-dns-tproxy-cache");
    let benchmark_records = benchmark_records(&admissions);
    let mut report = Map::new();
    report.insert(
        "name".to_owned(),
        json!("daemon-run-production-dataplane-harness"),
    );
    report.insert(
        "evidence_class".to_owned(),
        json!("run-integrated-root-gated-active-dataplane-harness"),
    );
    report.insert("execute_smoke".to_owned(), json!(options.execute));
    report.insert(
        "root_gate_acknowledged".to_owned(),
        json!(options.ack_root_gate),
    );
    report.insert("read_only".to_owned(), json!(!options.execute));
    report.insert("blocked".to_owned(), json!(options.execute && !passed));
    report.insert("artifact_dir".to_owned(), json!(path_string(artifact_dir)));
    report.insert("benchmark_iters".to_owned(), json!(options.benchmark_iters));
    report.insert("admission_plan".to_owned(), json!(admission_plan));
    report.insert("admissions".to_owned(), json!(admissions));
    report.insert(
        "production_dataplane_harness_integrated_in_run".to_owned(),
        json!(true),
    );
    report.insert(
        "production_dataplane_harness_executed".to_owned(),
        json!(options.execute),
    );
    report.insert(
        "production_dataplane_harness_passed".to_owned(),
        json!(options.execute && passed),
    );
    for (key, value) in [
        (
            "production_param_listener_passed",
            production_param_listener_passed,
        ),
        (
            "active_tcp_tproxy_ingress_passed",
            active_tcp_tproxy_ingress_passed,
        ),
        (
            "active_tcp_route_dial_relay_passed",
            active_tcp_route_dial_relay_passed,
        ),
        (
            "active_udp_tproxy_endpoint_passed",
            active_udp_tproxy_endpoint_passed,
        ),
        (
            "active_dns_tproxy_cache_passed",
            active_dns_tproxy_cache_passed,
        ),
    ] {
        report.insert(key.to_owned(), json!(value));
    }
    report.insert("benchmark_records".to_owned(), json!(benchmark_records));
    for key in [
        "production_listener_bound",
        "production_tc_attach_smoke_passed",
        "ebpf_attached",
        "production_dataplane_admitted",
        "reload_runtime_parity_admitted",
        "native_daemon_benchmark_recorded",
        "true_rust_native_daemon_admitted",
        "final_native_admission_allowed",
        "host_mutation_allowed",
        "final_state_admission_allowed",
    ] {
        report.insert(key.to_owned(), json!(false));
    }
    report.insert(
        "production_dataplane_admission_scope".to_owned(),
        json!(if options.execute && passed {
            "run-integrated-harness-only"
        } else if options.execute {
            "run-integrated-harness-failed"
        } else {
            "not-executed"
        }),
    );
    report.insert("native_runtime_path_preserved".to_owned(), json!(true));
    report.insert("final_native_evidence_required".to_owned(), json!(true));
    Value::Object(report)
}
