use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};

use super::path_string;

pub(super) fn expected_product_chain_branch(name: &str) -> &'static str {
    match name {
        "dae" => "daex",
        "daed" => "daed2-daex-align",
        "dae-wing" | "daed-wing" => "daewing2-daex-align",
        "outbound" => "outbound-daex-align",
        "quic-go" => "quic-go-rust",
        _ => "",
    }
}

pub(super) fn repo_status_json(name: &str, path: &Path) -> Value {
    let expected_branch = expected_product_chain_branch(name);
    if !path.is_dir() {
        return json!({
            "name": name,
            "path": path_string(path),
            "exists": false,
            "git_status_available": false,
            "dirty": false,
            "expected_branch": expected_branch,
            "actual_branch": Value::Null,
            "branch_matches_expected": false,
            "branch_contract_preserved": false,
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
            let actual_branch = current_branch_from_status(&stdout);
            let branch_matches_expected =
                output.status.success() && actual_branch.as_deref() == Some(expected_branch);
            let dirty = stdout
                .lines()
                .any(|line| !line.trim().is_empty() && !line.starts_with("##"));
            json!({
                "name": name,
                "path": path_string(path),
                "exists": true,
                "git_status_available": output.status.success(),
                "dirty": dirty,
                "expected_branch": expected_branch,
                "actual_branch": actual_branch,
                "branch_matches_expected": branch_matches_expected,
                "branch_contract_preserved": branch_matches_expected,
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
            "expected_branch": expected_branch,
            "actual_branch": Value::Null,
            "branch_matches_expected": false,
            "branch_contract_preserved": false,
            "error": err.to_string(),
        }),
    }
}

fn current_branch_from_status(stdout: &str) -> Option<String> {
    let line = stdout.lines().next()?.trim();
    let branch = line.strip_prefix("## ")?;
    let branch = branch.split("...").next().unwrap_or(branch).trim();
    let branch = branch
        .strip_prefix("No commits yet on branch ")
        .or_else(|| branch.strip_prefix("No commits yet on "))
        .unwrap_or(branch)
        .trim();
    if branch.is_empty() || branch == "HEAD (no branch)" {
        None
    } else {
        Some(branch.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_chain_expected_branches_are_formal_daed2_chain() {
        assert_eq!(expected_product_chain_branch("dae"), "daex");
        assert_eq!(
            expected_product_chain_branch("daed-wing"),
            "daewing2-daex-align"
        );
        assert_eq!(expected_product_chain_branch("daed"), "daed2-daex-align");
        assert_eq!(
            expected_product_chain_branch("outbound"),
            "outbound-daex-align"
        );
        assert_eq!(expected_product_chain_branch("quic-go"), "quic-go-rust");
    }

    #[test]
    fn parses_status_branch_with_or_without_tracking() {
        assert_eq!(
            current_branch_from_status("## daex\n M file"),
            Some("daex".to_owned())
        );
        assert_eq!(
            current_branch_from_status("## daed2-daex-align...origin/daed2-daex-align\n"),
            Some("daed2-daex-align".to_owned())
        );
        assert_eq!(
            current_branch_from_status("## No commits yet on branch daed2-daex-align\n"),
            Some("daed2-daex-align".to_owned())
        );
        assert_eq!(
            current_branch_from_status("## No commits yet on daed2-daex-align\n"),
            Some("daed2-daex-align".to_owned())
        );
        assert_eq!(current_branch_from_status(""), None);
    }
}
