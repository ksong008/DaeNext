use super::*;
pub(super) fn c1_default_bundle_boundary(options: &ProductChainRecertificationOptions) -> Value {
    let makefile = options.dae_wing_repo.join("Makefile");
    let text = fs::read_to_string(&makefile).unwrap_or_default();
    let makefile_readable = !text.is_empty();
    let default_bundle_rule = makefile_rule(&text, "bundle");
    let rust_owned_bundle_rule = makefile_rule(&text, "bundle-rust-owned");
    let hybrid_bundle_shape_recorded = text.contains("BUNDLE_TAGS ?= embedallowed")
        && default_bundle_rule.contains("rust-aya-bpf-loader-asset")
        && default_bundle_rule.contains("bundle-build")
        && !default_bundle_rule.contains("rust-daemon-embed");
    let rust_owned_candidate_bundle_shape_recorded = text
        .contains("bundle-rust-owned: BUNDLE_TAGS := embedallowed,rust_owned_daemon_embed")
        && rust_owned_bundle_rule.contains("rust-daemon-embed")
        && rust_owned_bundle_rule.contains("bundle-build")
        && text.contains("rust-daemon-embed:");
    let default_bundle_embeds_rust_owned_daemon = default_bundle_rule.contains("rust-daemon-embed")
        || text.contains("BUNDLE_TAGS ?= embedallowed,rust_owned_daemon_embed");
    let bundle_dry_run = make_dry_run_json(&options.dae_wing_repo, "bundle");
    let rust_owned_bundle_dry_run = make_dry_run_json(&options.dae_wing_repo, "bundle-rust-owned");
    let dry_runs_recorded = bundle_dry_run["passed"].as_bool().unwrap_or(false)
        && rust_owned_bundle_dry_run["passed"]
            .as_bool()
            .unwrap_or(false);
    let release_target_scan = release_target_scan_json(options);
    let release_targets_recorded = release_target_scan["recorded"].as_bool().unwrap_or(false);
    let default_bundle_boundary_clean = makefile_readable
        && hybrid_bundle_shape_recorded
        && rust_owned_candidate_bundle_shape_recorded
        && !default_bundle_embeds_rust_owned_daemon
        && dry_runs_recorded
        && release_targets_recorded;

    let mut blockers = Vec::new();
    if !makefile_readable {
        blockers.push(format!(
            "C1 wing Makefile could not be read: {}",
            path_string(&makefile)
        ));
    }
    if !hybrid_bundle_shape_recorded {
        blockers.push("C1 hybrid default bundle shape is not recorded".to_owned());
    }
    if !rust_owned_candidate_bundle_shape_recorded {
        blockers.push("C1 Rust-owned candidate bundle shape is not recorded".to_owned());
    }
    if default_bundle_embeds_rust_owned_daemon {
        blockers.push(
            "C1 default bundle embeds Rust-owned daemon asset; C9 release default switch has not admitted this yet"
                .to_owned(),
        );
    }
    if !dry_runs_recorded {
        blockers.push("C1 make -n bundle and bundle-rust-owned evidence is incomplete".to_owned());
    }
    if !release_targets_recorded {
        blockers.push("C1 release/action/Docker bundle targets are not recorded".to_owned());
    }

    json!({
        "name": "default-bundle-boundary",
        "status": if default_bundle_boundary_clean { "pass" } else { "blocked" },
        "makefile": path_string(&makefile),
        "makefile_readable": makefile_readable,
        "hybrid_bundle_shape_recorded": hybrid_bundle_shape_recorded,
        "rust_owned_candidate_bundle_shape_recorded": rust_owned_candidate_bundle_shape_recorded,
        "default_bundle_embeds_rust_owned_daemon": default_bundle_embeds_rust_owned_daemon,
        "default_bundle_target": "bundle",
        "rust_owned_candidate_bundle_target": "bundle-rust-owned",
        "default_bundle_rule": default_bundle_rule,
        "rust_owned_candidate_bundle_rule": rust_owned_bundle_rule,
        "bundle_dry_run": bundle_dry_run,
        "rust_owned_bundle_dry_run": rust_owned_bundle_dry_run,
        "dry_runs_recorded": dry_runs_recorded,
        "release_target_scan": release_target_scan,
        "release_targets_recorded": release_targets_recorded,
        "default_bundle_boundary_clean": default_bundle_boundary_clean,
        "blockers": blockers,
    })
}

pub(super) fn makefile_rule(text: &str, target: &str) -> String {
    let prefix = format!("{target}:");
    text.lines()
        .filter(|line| !line.contains(":="))
        .find(|line| line.trim_start().starts_with(&prefix))
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

pub(super) fn make_dry_run_json(repo: &Path, target: &str) -> Value {
    if !repo.is_dir() {
        return json!({
            "target": target,
            "executed": false,
            "passed": false,
            "stdout": "",
            "stderr": "wing repo does not exist",
        });
    }
    match Command::new("make")
        .args(["-n", target, "WEB_DIST=webrender/web"])
        .current_dir(repo)
        .output()
    {
        Ok(output) => json!({
            "target": target,
            "executed": true,
            "passed": output.status.success(),
            "exit_code": output.status.code(),
            "stdout": bounded_output(&output.stdout),
            "stderr": bounded_output(&output.stderr),
        }),
        Err(err) => json!({
            "target": target,
            "executed": true,
            "passed": false,
            "exit_code": Value::Null,
            "stdout": "",
            "stderr": err.to_string(),
        }),
    }
}

pub(super) fn release_target_scan_json(options: &ProductChainRecertificationOptions) -> Value {
    let files = [
        options
            .daed_repo
            .join(".github/workflows/publish-packages.yml"),
        options.daed_repo.join("Dockerfile"),
        options.daed_repo.join("publish.Dockerfile"),
        options.daed_repo.join("package.json"),
        options.dae_wing_repo.join("Makefile"),
    ];
    let entries: Vec<Value> = files
        .iter()
        .map(|path| {
            let text = fs::read_to_string(path).unwrap_or_default();
            json!({
                "path": path_string(path),
                "exists": path.is_file(),
                "make_bundle": text.contains("make bundle") || text.contains(" bundle"),
                "make_bundle_rust_owned": text.contains("bundle-rust-owned"),
                "docker_daed_run_contract": text.contains("daed\", \"run\", \"-c\", \"/etc/daed") || text.contains("daed run -c /etc/daed"),
            })
        })
        .collect();
    json!({
        "recorded": entries.iter().any(|entry| entry["exists"].as_bool().unwrap_or(false)),
        "files": entries,
    })
}
