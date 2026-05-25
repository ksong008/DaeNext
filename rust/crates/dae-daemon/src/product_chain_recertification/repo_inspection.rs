use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};

use super::path_string;

pub(super) fn repo_status_json(name: &str, path: &Path) -> Value {
    if !path.is_dir() {
        return json!({
            "name": name,
            "path": path_string(path),
            "exists": false,
            "git_status_available": false,
            "dirty": false,
        });
    }
    let output = Command::new("git")
        .args(["status", "--short", "--branch"])
        .current_dir(path)
        .output();
    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            let dirty = stdout
                .lines()
                .any(|line| !line.trim().is_empty() && !line.starts_with("##"));
            json!({
                "name": name,
                "path": path_string(path),
                "exists": true,
                "git_status_available": output.status.success(),
                "dirty": dirty,
                "status": if output.status.success() { "pass" } else { "fail" },
                "branch": stdout.lines().next().unwrap_or_default(),
                "stdout": stdout,
                "stderr": stderr,
            })
        }
        Err(err) => json!({
            "name": name,
            "path": path_string(path),
            "exists": true,
            "git_status_available": false,
            "dirty": false,
            "status": "fail",
            "error": err.to_string(),
        }),
    }
}
