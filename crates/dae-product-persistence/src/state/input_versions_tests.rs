use super::*;

#[test]
fn input_versions_default_to_zero_and_increment_independently() {
    let root =
        std::env::temp_dir().join(format!("dae-product-input-versions-{}", fastrand::u64(..)));
    let state = root.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    assert_eq!(current_runtime_external_input_version(&conn).unwrap(), 0);
    assert_eq!(current_runtime_geodata_input_version(&conn).unwrap(), 0);
    assert_eq!(bump_runtime_external_input_version(&state).unwrap(), 1);
    assert_eq!(
        bump_runtime_geodata_input_version_with_connection(&conn).unwrap(),
        1
    );
    assert_eq!(current_runtime_external_input_version(&conn).unwrap(), 1);
    std::fs::remove_dir_all(root).unwrap();
}
