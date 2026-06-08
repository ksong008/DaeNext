use super::*;
pub(super) fn resolve_go_binary(
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

pub(super) fn resolve_rust_binary(
    options: &MatchedDefaultBenchmarkOptions,
) -> Result<PathBuf, String> {
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

pub(super) fn read_build_tags(source_dir: &Path) -> Result<String, String> {
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
