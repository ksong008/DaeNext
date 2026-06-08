use super::*;
#[test]
pub(crate) fn daed_resident_adapter_matrix_requires_config_path() {
    let output = Command::new(binary())
        .args(["resident-adapter-matrix"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("resident-adapter-matrix requires -c/--config")
    );
}
