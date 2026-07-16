use std::{fs, process::Command};

use serde_json::Value;

use super::binary;

#[test]
fn service_contract_redacts_remote_live_evidence_source_and_error() {
    let source = std::env::temp_dir().join(format!(
        "private-resident-live-evidence-{}.json",
        std::process::id()
    ));
    let source_text = source.display().to_string();
    fs::write(
        &source,
        r#"{"schema":"native-current-live-resident-matrix","schemaVersion":1}"#,
    )
    .unwrap();
    let output = Command::new(binary())
        .arg("service-contract")
        .env("RESIDENT_LIVE_MATRIX_EVIDENCE", &source)
        .env_remove("DAE_RESIDENT_LIVE_MATRIX_EVIDENCE")
        .output()
        .unwrap();

    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let evidence = &report["resident_live_adapter_remote_live_matrix_evidence"];
    assert!(
        evidence["source"]
            .as_str()
            .is_some_and(|identity| identity.starts_with("sha256:"))
    );
    assert_eq!(evidence["sourceRedacted"], true);
    assert_eq!(
        evidence["error"],
        "remote live matrix evidence is invalid; source detail redacted"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&source_text));
    let _ = fs::remove_file(source);
}
