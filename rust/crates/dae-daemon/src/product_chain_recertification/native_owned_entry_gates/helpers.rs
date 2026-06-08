use super::*;
pub(super) fn git_repo_brief_json(path: &Path) -> Value {
    if !path.is_dir() {
        return json!({
            "path": path_string(path),
            "exists": false,
            "git_status_available": false,
            "head": Value::Null,
            "dirty": false,
        });
    }
    let status = Command::new("git")
        .args(["status", "--short", "--branch"])
        .current_dir(path)
        .output();
    let head = git_stdout(path, &["rev-parse", "HEAD"]);
    match status {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let dirty = stdout
                .lines()
                .any(|line| !line.trim().is_empty() && !line.starts_with("##"));
            json!({
                "path": path_string(path),
                "exists": true,
                "git_status_available": output.status.success(),
                "head": head,
                "dirty": dirty,
                "branch": stdout.lines().next().unwrap_or_default(),
                "stdout": stdout,
                "stderr": String::from_utf8_lossy(&output.stderr).trim().to_string(),
            })
        }
        Err(err) => json!({
            "path": path_string(path),
            "exists": true,
            "git_status_available": false,
            "head": head,
            "dirty": false,
            "error": err.to_string(),
        }),
    }
}

pub(super) fn git_stdout(path: &Path, args: &[&str]) -> Value {
    let Ok(output) = Command::new("git").args(args).current_dir(path).output() else {
        return Value::Null;
    };
    if !output.status.success() {
        return Value::Null;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if text.is_empty() {
        Value::Null
    } else {
        json!(text)
    }
}

pub(super) fn bounded_output(bytes: &[u8]) -> String {
    const MAX_BYTES: usize = 4000;
    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_BYTES)]).into_owned()
}

pub(super) fn value_string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}
