use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedDefaultBenchmarkOptions {
    pub execute: bool,
    pub ack_root_gate: bool,
    pub iterations: u32,
    pub ready_timeout_ms: u64,
    pub source_dir: PathBuf,
    pub go_tool: PathBuf,
    pub go_work: Option<PathBuf>,
    pub go_binary: Option<PathBuf>,
    pub rust_binary: Option<PathBuf>,
}

impl Default for MatchedDefaultBenchmarkOptions {
    fn default() -> Self {
        Self {
            execute: false,
            ack_root_gate: false,
            iterations: 3,
            ready_timeout_ms: 15_000,
            source_dir: PathBuf::from("."),
            go_tool: PathBuf::from("go"),
            go_work: None,
            go_binary: None,
            rust_binary: None,
        }
    }
}

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

fn base_report(
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

fn resolve_go_binary(
    options: &MatchedDefaultBenchmarkOptions,
    artifact_dir: &Path,
) -> Result<PathBuf, String> {
    if let Some(path) = &options.go_binary {
        if path.is_file() {
            return Ok(path.clone());
        }
        return Err(format!(
            "matched benchmark --go-binary does not exist: {}",
            path_string(path)
        ));
    }

    let output = artifact_dir.join("go").join("bin").join("dae");
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create Go binary dir {}: {err}",
                path_string(parent)
            )
        })?;
    }
    let build_tags = read_build_tags(&options.source_dir)?;
    let started = Instant::now();
    let mut command = Command::new(&options.go_tool);
    command
        .current_dir(&options.source_dir)
        .arg("build")
        .arg(format!("-tags={build_tags}"))
        .arg("-o")
        .arg(&output)
        .arg(".");
    if let Some(go_work) = &options.go_work {
        command.env("GOWORK", go_work);
    }
    let command_output = command
        .output()
        .map_err(|err| format!("failed to run Go build command: {err}"))?;
    let build_elapsed_ns = started.elapsed().as_nanos();
    let build_artifact = artifact_dir.join("go").join("build-output.json");
    write_json(
        &build_artifact,
        &json!({
            "go_tool": path_string(&options.go_tool),
            "source_dir": path_string(&options.source_dir),
            "go_work": options.go_work.as_ref().map(|path| path_string(path)),
            "build_tags": build_tags,
            "output": path_string(&output),
            "elapsed_ns": build_elapsed_ns,
            "exit_code": command_output.status.code(),
            "stdout": cap_text(&String::from_utf8_lossy(&command_output.stdout)),
            "stderr": cap_text(&String::from_utf8_lossy(&command_output.stderr)),
        }),
    )?;
    if !command_output.status.success() {
        return Err(format!(
            "Go default daemon build failed; artifact={}",
            path_string(&build_artifact)
        ));
    }
    Ok(output)
}

fn resolve_rust_binary(options: &MatchedDefaultBenchmarkOptions) -> Result<PathBuf, String> {
    if let Some(path) = &options.rust_binary {
        if path.is_file() {
            return Ok(path.clone());
        }
        return Err(format!(
            "matched benchmark --rust-binary does not exist: {}",
            path_string(path)
        ));
    }
    let current = std::env::current_exe()
        .map_err(|err| format!("failed to resolve current Rust binary: {err}"))?;
    if current
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "dae-daemon-optin")
    {
        return Ok(current);
    }
    let fallback = PathBuf::from("rust/target/debug/dae-daemon-optin");
    if fallback.is_file() {
        return Ok(fallback);
    }
    Err("matched benchmark cannot resolve dae-daemon-optin binary; pass --rust-binary".to_owned())
}

fn run_go_iteration(
    index: u32,
    artifact_dir: &Path,
    config: &Path,
    go_binary: &Path,
    options: &MatchedDefaultBenchmarkOptions,
) -> Result<Value, String> {
    let iteration_dir = artifact_dir
        .join("go")
        .join(format!("iter-{:03}", index + 1));
    fs::create_dir_all(&iteration_dir).map_err(|err| {
        format!(
            "failed to create Go iteration dir {}: {err}",
            path_string(&iteration_dir)
        )
    })?;
    remove_var_run_files()?;
    let stdout = File::create(iteration_dir.join("stdout.log"))
        .map_err(|err| format!("create Go stdout failed: {err}"))?;
    let stderr = File::create(iteration_dir.join("stderr.log"))
        .map_err(|err| format!("create Go stderr failed: {err}"))?;
    let log_file = iteration_dir.join("dae-go.log");
    let started = Instant::now();
    let mut child = Command::new(go_binary)
        .arg("run")
        .arg("--config")
        .arg(config)
        .arg("--logfile")
        .arg(&log_file)
        .arg("--disable-timestamp")
        .arg("--disable-sudo")
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|err| format!("failed to start Go default daemon: {err}"))?;

    let ready = wait_go_ready(&mut child, Duration::from_millis(options.ready_timeout_ms))?;
    terminate_child_gracefully(&mut child)?;
    let cleanup = host_cleanup_snapshot();
    let report = json!({
        "owner": "go-default-daemon",
        "iteration": index + 1,
        "pid": child.id(),
        "ready": ready.ready,
        "ready_elapsed_ns": ready.elapsed_ns,
        "exit_code": ready.exit_code,
        "log_file": path_string(&log_file),
        "stdout_file": path_string(&iteration_dir.join("stdout.log")),
        "stderr_file": path_string(&iteration_dir.join("stderr.log")),
        "progress_file": "/var/run/dae.progress",
        "pid_file": "/var/run/dae.pid",
        "total_elapsed_ns": started.elapsed().as_nanos(),
        "cleanup": cleanup,
    });
    write_json(&iteration_dir.join("summary.json"), &report)?;
    if !ready.ready {
        return Err(format!("Go default daemon did not reach ready: {report}"));
    }
    Ok(report)
}

fn run_rust_iteration(
    index: u32,
    run_root: &Path,
    artifact_dir: &Path,
    config: &Path,
    rust_binary: &Path,
) -> Result<Value, String> {
    let iteration_dir = artifact_dir
        .join("rust")
        .join(format!("iter-{:03}", index + 1));
    fs::create_dir_all(&iteration_dir).map_err(|err| {
        format!(
            "failed to create Rust iteration dir {}: {err}",
            path_string(&iteration_dir)
        )
    })?;
    let rust_root = rust_iteration_root(run_root, index);
    if rust_root.exists() {
        fs::remove_dir_all(&rust_root).map_err(|err| {
            format!(
                "failed to remove previous Rust iteration root {}: {err}",
                path_string(&rust_root)
            )
        })?;
    }
    let started = Instant::now();
    let output = Command::new(rust_binary)
        .arg("run")
        .arg("--config")
        .arg(config)
        .arg("--root")
        .arg(&rust_root)
        .arg("--disable-timestamp")
        .arg("--disable-sudo")
        .arg("--exit-after-ready")
        .output()
        .map_err(|err| format!("failed to start Rust opt-in daemon run: {err}"))?;
    let elapsed_ns = started.elapsed().as_nanos();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    fs::write(iteration_dir.join("stdout.json"), &stdout)
        .map_err(|err| format!("write Rust stdout failed: {err}"))?;
    fs::write(iteration_dir.join("stderr.log"), &stderr)
        .map_err(|err| format!("write Rust stderr failed: {err}"))?;
    let parsed = parse_json_stdout(&stdout).map_err(|err| {
        format!(
            "Rust opt-in daemon did not emit parseable JSON: {err}; stdout={}; stderr={}",
            cap_text(&stdout),
            cap_text(&stderr)
        )
    })?;
    let ready = output.status.success()
        && parsed["run_entrypoint_executed"].as_bool().unwrap_or(false)
        && parsed["listener_smoke_passed"].as_bool().unwrap_or(false)
        && parsed["reload_owner_handoff_smoke_passed"]
            .as_bool()
            .unwrap_or(false);
    let report = json!({
        "owner": "rust-optin-daemon",
        "iteration": index + 1,
        "ready": ready,
        "ready_elapsed_ns": elapsed_ns,
        "exit_code": output.status.code(),
        "root": path_string(&rust_root),
        "stdout_file": path_string(&iteration_dir.join("stdout.json")),
        "stderr_file": path_string(&iteration_dir.join("stderr.log")),
        "run_manifest": parsed["manifest_file"].clone(),
        "listener_smoke_passed": parsed["listener_smoke_passed"].clone(),
        "reload_owner_handoff_smoke_passed": parsed["reload_owner_handoff_smoke_passed"].clone(),
        "production_dataplane_harness_executed": parsed["production_dataplane_harness_executed"].clone(),
        "production_dataplane_harness_passed": parsed["production_dataplane_harness_passed"].clone(),
        "matched_go_rust_default_daemon_benchmark_recorded": parsed["matched_go_rust_default_daemon_benchmark_recorded"].clone(),
    });
    write_json(&iteration_dir.join("summary.json"), &report)?;
    if !ready {
        return Err(format!("Rust opt-in daemon did not reach ready: {report}"));
    }
    Ok(report)
}

struct ReadyResult {
    ready: bool,
    elapsed_ns: u128,
    exit_code: Option<i32>,
}

fn wait_go_ready(child: &mut Child, timeout: Duration) -> Result<ReadyResult, String> {
    let started = Instant::now();
    loop {
        if progress_done()? {
            return Ok(ReadyResult {
                ready: true,
                elapsed_ns: started.elapsed().as_nanos(),
                exit_code: None,
            });
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("wait Go daemon failed: {err}"))?
        {
            return Ok(ReadyResult {
                ready: false,
                elapsed_ns: started.elapsed().as_nanos(),
                exit_code: status.code(),
            });
        }
        if started.elapsed() > timeout {
            return Ok(ReadyResult {
                ready: false,
                elapsed_ns: started.elapsed().as_nanos(),
                exit_code: None,
            });
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn progress_done() -> Result<bool, String> {
    let path = Path::new("/var/run/dae.progress");
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(format!("read /var/run/dae.progress failed: {err}")),
    };
    let mut byte = [0_u8; 1];
    match file.read(&mut byte) {
        Ok(0) => Ok(false),
        Ok(_) => Ok(byte[0] == b'2'),
        Err(err) => Err(format!("read /var/run/dae.progress byte failed: {err}")),
    }
}

fn terminate_child_gracefully(child: &mut Child) -> Result<(), String> {
    let pid = child.id().to_string();
    let _ = Command::new("kill").args(["-TERM", &pid]).status();
    let started = Instant::now();
    loop {
        if child
            .try_wait()
            .map_err(|err| format!("wait daemon after SIGTERM failed: {err}"))?
            .is_some()
        {
            return Ok(());
        }
        if started.elapsed() > Duration::from_secs(5) {
            child
                .kill()
                .map_err(|err| format!("kill daemon after SIGTERM timeout failed: {err}"))?;
            let _ = child.wait();
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[derive(Debug, Clone)]
struct VarRunSnapshot {
    pid: Option<Vec<u8>>,
    progress: Option<Vec<u8>>,
}

impl VarRunSnapshot {
    fn capture() -> Result<Self, String> {
        Ok(Self {
            pid: read_optional_file(Path::new("/var/run/dae.pid"))?,
            progress: read_optional_file(Path::new("/var/run/dae.progress"))?,
        })
    }

    fn reject_live_daemon(&self) -> Result<(), String> {
        let Some(pid_bytes) = &self.pid else {
            return Ok(());
        };
        let pid = String::from_utf8_lossy(pid_bytes).trim().to_owned();
        if pid.is_empty() {
            return Ok(());
        }
        let status = Command::new("kill").args(["-0", &pid]).status();
        if status.map(|status| status.success()).unwrap_or(false) {
            return Err(format!(
                "existing /var/run/dae.pid points to a live process ({pid}); stop it before running matched benchmark"
            ));
        }
        Ok(())
    }

    fn restore(&self) -> Result<(), String> {
        restore_optional_file(Path::new("/var/run/dae.pid"), self.pid.as_deref())?;
        restore_optional_file(Path::new("/var/run/dae.progress"), self.progress.as_deref())
    }

    fn to_json(&self) -> Value {
        json!({
            "pid_file_existed": self.pid.is_some(),
            "progress_file_existed": self.progress.is_some(),
            "pid_file_restored_after_benchmark": true,
            "progress_file_restored_after_benchmark": true,
        })
    }
}

fn read_optional_file(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!("read {} failed: {err}", path_string(path))),
    }
}

fn restore_optional_file(path: &Path, content: Option<&[u8]>) -> Result<(), String> {
    match content {
        Some(content) => fs::write(path, content)
            .map_err(|err| format!("restore {} failed: {err}", path_string(path))),
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!("remove {} failed: {err}", path_string(path))),
        },
    }
}

fn remove_var_run_files() -> Result<(), String> {
    for path in ["/var/run/dae.pid", "/var/run/dae.progress"] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(format!("remove {path} failed: {err}")),
        }
    }
    Ok(())
}

fn host_cleanup_snapshot() -> Value {
    json!({
        "dae0_exists": command_success("ip", &["link", "show", "dae0"]),
        "dae0peer_exists": command_success("ip", &["link", "show", "dae0peer"]),
        "daens_exists": Path::new("/run/netns/daens").exists() || Path::new("/var/run/netns/daens").exists(),
    })
}

fn command_success(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn materialize_secure_config(source: &Path, dest: &Path) -> Result<(), String> {
    let content = fs::read(source).map_err(|err| {
        format!(
            "read benchmark config {} failed: {err}",
            path_string(source)
        )
    })?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create benchmark corpus dir {} failed: {err}",
                path_string(parent)
            )
        })?;
    }
    fs::write(dest, content)
        .map_err(|err| format!("write benchmark config {} failed: {err}", path_string(dest)))?;
    fs::set_permissions(dest, fs::Permissions::from_mode(0o600)).map_err(|err| {
        format!(
            "chmod benchmark config {} to 0600 failed: {err}",
            path_string(dest)
        )
    })
}

fn read_build_tags(source_dir: &Path) -> Result<String, String> {
    let path = source_dir.join(".build_tags");
    match fs::read_to_string(&path) {
        Ok(tags) => Ok(tags.trim().to_owned()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(err) => Err(format!(
            "read build tags {} failed: {err}",
            path_string(&path)
        )),
    }
}

fn rust_iteration_root(run_root: &Path, index: u32) -> PathBuf {
    let suffix = run_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(sanitize_suffix)
        .filter(|suffix| !suffix.is_empty())
        .unwrap_or_else(|| "run".to_owned());
    PathBuf::from(format!(
        "/tmp/dae-daemon-matched-rust-{suffix}-iter{:03}",
        index + 1
    ))
}

fn aggregate(iterations: &[Value]) -> Value {
    let go_values = iterations
        .iter()
        .filter_map(|item| item["go"]["ready_elapsed_ns"].as_u64())
        .collect::<Vec<_>>();
    let rust_values = iterations
        .iter()
        .filter_map(|item| item["rust"]["ready_elapsed_ns"].as_u64())
        .collect::<Vec<_>>();
    json!({
        "iterations": iterations.len(),
        "go_ready_elapsed_ns": stats(&go_values),
        "rust_ready_elapsed_ns": stats(&rust_values),
        "rust_vs_go_ready_elapsed_ratio": ratio(avg(&rust_values), avg(&go_values)),
    })
}

fn stats(values: &[u64]) -> Value {
    json!({
        "count": values.len(),
        "min": values.iter().min().copied(),
        "max": values.iter().max().copied(),
        "avg": avg(values),
    })
}

fn avg(values: &[u64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let sum = values.iter().map(|value| *value as f64).sum::<f64>();
    Some(sum / values.len() as f64)
}

fn ratio(numerator: Option<f64>, denominator: Option<f64>) -> Option<f64> {
    let denominator = denominator?;
    if denominator == 0.0 {
        return None;
    }
    Some(numerator? / denominator)
}

fn parse_json_stdout(stdout: &str) -> Result<Value, String> {
    let trimmed = stdout.trim();
    serde_json::from_str(trimmed).or_else(|first_err| {
        stdout
            .lines()
            .rev()
            .map(str::trim)
            .find(|line| line.starts_with('{'))
            .ok_or_else(|| first_err.to_string())
            .and_then(|line| serde_json::from_str(line).map_err(|err| err.to_string()))
    })
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create parent {} failed: {err}", path_string(parent)))?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| format!("encode JSON {} failed: {err}", path_string(path)))?;
    let mut file = File::create(path)
        .map_err(|err| format!("create JSON {} failed: {err}", path_string(path)))?;
    file.write_all(&bytes)
        .map_err(|err| format!("write JSON {} failed: {err}", path_string(path)))
}

fn sanitize_suffix(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn cap_text(value: &str) -> String {
    const MAX: usize = 4000;
    if value.len() <= MAX {
        return value.to_owned();
    }
    let truncated = value.chars().take(MAX).collect::<String>();
    format!(
        "{}...[truncated {} bytes]",
        truncated,
        value.len().saturating_sub(truncated.len())
    )
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
