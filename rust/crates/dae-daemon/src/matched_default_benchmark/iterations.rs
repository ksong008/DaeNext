use super::*;
pub(super) fn run_go_iteration(
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

pub(super) fn run_rust_iteration(
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

pub(super) struct ReadyResult {
    pub(super) ready: bool,
    pub(super) elapsed_ns: u128,
    pub(super) exit_code: Option<i32>,
}

pub(super) fn wait_go_ready(child: &mut Child, timeout: Duration) -> Result<ReadyResult, String> {
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

pub(super) fn progress_done() -> Result<bool, String> {
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

pub(super) fn terminate_child_gracefully(child: &mut Child) -> Result<(), String> {
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

pub(super) fn rust_iteration_root(run_root: &Path, index: u32) -> PathBuf {
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
