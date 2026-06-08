use super::*;
#[test]
pub(super) fn contract_names_do_not_use_retired_version_suffix_or_stage_ids() {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let mut files = Vec::new();
    for relative in ["rust/crates", "scripts", "testdata/rebuild-golden"] {
        collect_contract_name_scan_files(&repo_root.join(relative), &mut files);
    }

    let retired_suffix = String::from_utf8(vec![b'-', b'v', b'1']).unwrap();
    let retired_stage_ids = [
        retired_stage_id("23", "product-chain-admission"),
        retired_stage_id("22", "daemon-live-evidence-queue"),
        retired_stage_id("19", "complex-dataplane-gate"),
        retired_stage_id("17", "protocol-dataplane-admission"),
        retired_stage_id("16", "daemon-default-readiness"),
        retired_stage_id("22", "daemon-gray-switch-gate"),
        retired_stage_id("23", "true-default-daemon-admission"),
        retired_stage_id("7", "release-product-chain-live-gate"),
        retired_stage_id("6", "datapath-outbound-ebpf-deep-area"),
        retired_stage_id("7", "default-daemon-live-matrix"),
    ];

    let mut offenders = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        let relative = file.strip_prefix(&repo_root).unwrap_or(&file);
        if text.contains(&retired_suffix) {
            offenders.push(format!(
                "{} contains retired hyphen-version suffix",
                relative.display()
            ));
        }
        for retired_id in &retired_stage_ids {
            if text.contains(retired_id) {
                offenders.push(format!(
                    "{} contains retired active stage contract id {retired_id}",
                    relative.display()
                ));
            }
        }
    }

    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

#[test]
pub(super) fn userland_ffi_c_abi_is_not_in_default_control_crate_path() {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let cargo_toml =
        std::fs::read_to_string(repo_root.join("rust/crates/dae-control/Cargo.toml")).unwrap();
    let control_lib =
        std::fs::read_to_string(repo_root.join("rust/crates/dae-control/src/lib.rs")).unwrap();

    assert!(
        !cargo_toml.contains("staticlib"),
        "dae-control must not expose a default userland C ABI staticlib"
    );
    assert!(
        control_lib.contains("#[cfg(feature = \"ffi-compat\")]\npub mod ffi;"),
        "dae-control ffi module must be behind explicit ffi-compat"
    );
}

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

pub(super) fn retired_stage_id(stage: &str, name: &str) -> String {
    format!("{}{}-{}", "stage", stage, name)
}

#[test]
pub(super) fn resident_dataplane_events_do_not_emit_legacy_execution_fields() {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let mut files = Vec::new();
    collect_contract_name_scan_files(
        &repo_root.join("rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane"),
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
        &repo_root.join("rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane"),
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
