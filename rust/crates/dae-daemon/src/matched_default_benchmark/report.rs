use super::*;
pub fn matched_default_benchmark_report(
    run_root: &Path,
    config: &Path,
    options: &MatchedDefaultBenchmarkOptions,
) -> Result<Value, String> {
    if options.iterations == 0 {
        return Err("matched benchmark --matched-benchmark-iterations must be non-zero".to_owned());
    }
    if options.execute && !options.ack_root_gate {
        return Err(
            "matched Go/Rust default daemon benchmark requires --ack-root-gate with --execute-matched-default-benchmark"
                .to_owned(),
        );
    }
    if options.execute && !config.is_file() {
        return Err(format!(
            "matched benchmark config does not exist: {}",
            path_string(config)
        ));
    }

    let artifact_dir = run_root.join("run").join("matched-default-benchmark");
    if !options.execute {
        return Ok(base_report(options, config, &artifact_dir, None));
    }

    fs::create_dir_all(&artifact_dir).map_err(|err| {
        format!(
            "failed to create matched benchmark artifact dir {}: {err}",
            path_string(&artifact_dir)
        )
    })?;
    let corpus_config = artifact_dir.join("corpus").join("benchmark.dae");
    materialize_secure_config(config, &corpus_config)?;
    let var_run_snapshot = VarRunSnapshot::capture()?;
    var_run_snapshot.reject_live_daemon()?;

    let benchmark_result = (|| {
        let go_binary = resolve_go_binary(options, &artifact_dir)?;
        let rust_binary = resolve_rust_binary(options)?;
        let mut iterations = Vec::new();
        for index in 0..options.iterations {
            let go = run_go_iteration(index, &artifact_dir, &corpus_config, &go_binary, options)?;
            let rust =
                run_rust_iteration(index, run_root, &artifact_dir, &corpus_config, &rust_binary)?;
            iterations.push(json!({
                "iteration": index + 1,
                "go": go,
                "rust": rust,
            }));
        }

        Ok((go_binary, rust_binary, iterations))
    })();
    let restore_result = var_run_snapshot.restore();
    let (go_binary, rust_binary, iterations) = match (benchmark_result, restore_result) {
        (Ok(result), Ok(())) => result,
        (Err(err), Ok(())) => return Err(err),
        (Ok(_), Err(err)) => return Err(err),
        (Err(bench_err), Err(restore_err)) => {
            return Err(format!(
                "{bench_err}; additionally failed to restore /var/run state: {restore_err}"
            ));
        }
    };

    let summary = json!({
        "artifact_dir": path_string(&artifact_dir),
        "corpus_config_file": path_string(&corpus_config),
        "go_binary": path_string(&go_binary),
        "rust_binary": path_string(&rust_binary),
        "var_run_snapshot": var_run_snapshot.to_json(),
        "iterations": iterations,
        "aggregate": aggregate(&iterations),
    });
    let summary_file = artifact_dir.join("matched-default-daemon-benchmark.json");
    write_json(&summary_file, &summary)?;

    Ok(base_report(
        options,
        config,
        &artifact_dir,
        Some(json!({
            "summary_file": path_string(&summary_file),
            "result": summary,
        })),
    ))
}

pub(super) fn base_report(
    options: &MatchedDefaultBenchmarkOptions,
    config: &Path,
    artifact_dir: &Path,
    execution: Option<Value>,
) -> Value {
    let executed = execution.is_some();
    let aggregate = execution
        .as_ref()
        .map(|value| value["result"]["aggregate"].clone())
        .unwrap_or(Value::Null);
    let mut report = Map::new();
    report.insert(
        "name".to_owned(),
        json!("matched-go-rust-default-daemon-benchmark"),
    );
    report.insert(
        "evidence_class".to_owned(),
        json!("root-gated-same-corpus-go-default-vs-rust-optin-daemon-startup-benchmark"),
    );
    report.insert("execute_benchmark".to_owned(), json!(options.execute));
    report.insert(
        "root_gate_acknowledged".to_owned(),
        json!(options.ack_root_gate),
    );
    report.insert("read_only".to_owned(), json!(!options.execute));
    report.insert("blocked".to_owned(), json!(options.execute && !executed));
    report.insert("config_file".to_owned(), json!(path_string(config)));
    report.insert("artifact_dir".to_owned(), json!(path_string(artifact_dir)));
    report.insert("iterations_requested".to_owned(), json!(options.iterations));
    report.insert(
        "ready_timeout_ms".to_owned(),
        json!(options.ready_timeout_ms),
    );
    report.insert(
        "benchmark_scope".to_owned(),
        json!("same-corpus daemon start-to-ready wall time plus Rust opt-in run manifest; active TCP/UDP/DNS dataplane metrics remain recorded by the run-integrated Stage51/53/54 harness"),
    );
    report.insert("go_default_daemon_executed".to_owned(), json!(executed));
    report.insert("rust_optin_daemon_executed".to_owned(), json!(executed));
    report.insert("benchmark_executable_now".to_owned(), json!(executed));
    report.insert(
        "matched_go_rust_default_daemon_benchmark_recorded".to_owned(),
        json!(executed),
    );
    report.insert("aggregate".to_owned(), aggregate);
    if let Some(execution) = execution {
        report.insert("execution".to_owned(), execution);
    }
    for key in [
        "production_run_command_replaced",
        "production_dataplane_admitted",
        "reload_runtime_parity_admitted",
        "true_rust_default_daemon_admitted",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
    ] {
        report.insert(key.to_owned(), json!(false));
    }
    report.insert("go_default_path_preserved".to_owned(), json!(true));
    report.insert("go_fallback_required".to_owned(), json!(true));
    report.insert(
        "source".to_owned(),
        json!([
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:18.1",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.2",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.8"
        ]),
    );
    Value::Object(report)
}
