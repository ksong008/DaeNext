pub(super) fn collect_contract_name_scan_files(
    root: &std::path::Path,
    files: &mut Vec<std::path::PathBuf>,
) {
    if !root.exists() {
        return;
    }
    let entries = std::fs::read_dir(root).unwrap();
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_contract_name_scan_files(&path, files);
        } else if matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("rs" | "sh" | "json")
        ) {
            files.push(path);
        }
    }
}

#[test]
pub(super) fn resident_dataplane_events_do_not_emit_legacy_execution_fields() {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let mut files = Vec::new();
    collect_contract_name_scan_files(
        &repo_root.join("crates/dae-daemon/src/production_runtime_owner/resident_dataplane"),
        &mut files,
    );

    let forbidden = [
        format!("\"{}\":", "execution"),
        format!("\"{}\":", "proxy_execution"),
        format!("[\"{}\"] =", "execution"),
        format!("[\"{}\"] =", "proxy_execution"),
    ];
    let mut offenders = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        let relative = file.strip_prefix(&repo_root).unwrap_or(&file);
        for pattern in &forbidden {
            if text.contains(pattern) {
                offenders.push(format!(
                    "{} emits retired runtime execution field pattern {pattern}",
                    relative.display()
                ));
            }
        }
    }

    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

#[test]
pub(super) fn resident_dataplane_latency_snapshots_do_not_emit_raw_link_fields() {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let mut files = Vec::new();
    collect_contract_name_scan_files(
        &repo_root.join("crates/dae-daemon/src/production_runtime_owner/resident_dataplane"),
        &mut files,
    );

    let mut offenders = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        let relative = file.strip_prefix(&repo_root).unwrap_or(&file);
        if text.contains("\"link\":") {
            offenders.push(format!(
                "{} emits raw runtime link field",
                relative.display()
            ));
        }
    }

    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

#[test]
pub(super) fn resident_dataplane_runtime_labels_do_not_use_temporary_rollout_markers() {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let mut files = Vec::new();
    collect_contract_name_scan_files(
        &repo_root.join("crates/dae-daemon/src/production_runtime_owner/resident_dataplane"),
        &mut files,
    );

    let exact_forbidden = [
        concat!("-", "v1"),
        concat!("remote", "-", "38"),
        concat!("stage", "NN"),
        "\"stage\":",
        "\"stage\"",
        "stage_",
        "rawLink",
        "raw_link",
        "\"sourceLink\"",
    ];
    let mut offenders = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        let relative = file.strip_prefix(&repo_root).unwrap_or(&file);
        for pattern in exact_forbidden {
            if text.contains(pattern) {
                offenders.push(format!(
                    "{} contains temporary runtime marker {pattern}",
                    relative.display()
                ));
            }
        }
        if let Some(pattern) = numbered_stage_marker(&text) {
            offenders.push(format!(
                "{} contains temporary runtime marker {pattern}",
                relative.display()
            ));
        }
    }

    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

fn numbered_stage_marker(text: &str) -> Option<String> {
    let mut rest = text;
    while let Some(index) = rest.find("stage") {
        let candidate = &rest[index..];
        let suffix = candidate.strip_prefix("stage").unwrap_or_default();
        if suffix
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_digit())
        {
            let digits = suffix
                .chars()
                .take_while(|character| character.is_ascii_digit())
                .collect::<String>();
            return Some(format!("stage{digits}"));
        }
        rest = &candidate["stage".len()..];
    }
    None
}
