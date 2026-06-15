use crate::juicity::build_juicity_runtime_client_config;

#[test]
fn case_juicity_runtime_client_config_admits_system_roots_without_pin_or_insecure() {
    build_juicity_runtime_client_config(false, "").unwrap();
}

#[test]
fn case_juicity_runtime_client_config_keeps_pin_and_insecure_paths() {
    build_juicity_runtime_client_config(true, "").unwrap();
    build_juicity_runtime_client_config(false, "sha256:fixture").unwrap();
}
