use super::*;
pub(super) fn c2_default_runtime_selector(options: &ProductChainRecertificationOptions) -> Value {
    let runtime_mode = options.dae_wing_repo.join("engine/runtime_mode.go");
    let runtime_mode_text = fs::read_to_string(&runtime_mode).unwrap_or_default();
    let tests = options
        .dae_wing_repo
        .join("engine/rust_owned_service_test.go");
    let tests_text = fs::read_to_string(&tests).unwrap_or_default();
    let runtime_mode_readable = !runtime_mode_text.is_empty();
    let runtime_mode_default_rust_owned = runtime_mode_text.contains("runtimeModeDefault")
        && runtime_mode_text.contains("= runtimeModeRustOwned")
        && runtime_mode_text.contains("return runtimeModeDefault");
    let auto_selects_rust_owned = runtime_mode_text.contains("case \"auto\":")
        && runtime_mode_text.contains("return runtimeModeDefault");
    let explicit_go_rollback_only = runtime_mode_text.contains("runtimeModeGo")
        && runtime_mode_text.contains("case \"go\", \"native\", \"dae-go\", \"go-native\":")
        && runtime_mode_text.contains("return runtimeModeGo");
    let runtime_selector_matrix_recorded = tests_text
        .contains("TestNewDefaultServiceUsesRustOwnedRuntimeByDefault")
        && tests_text.contains("TestNewDefaultServiceUsesRustOwnedRuntimeForAuto")
        && tests_text.contains("TestNewDefaultServiceAllowsExplicitRustOwnedRuntime")
        && tests_text.contains("TestNewDefaultServiceAllowsExplicitGoRollback")
        && tests_text.contains("DAED_RUNTIME_MODE");
    let default_runtime_selector_rust_owned =
        runtime_mode_readable && runtime_mode_default_rust_owned && auto_selects_rust_owned;
    let ready = default_runtime_selector_rust_owned
        && explicit_go_rollback_only
        && runtime_selector_matrix_recorded;

    let mut blockers = Vec::new();
    if !runtime_mode_readable {
        blockers.push(format!(
            "C2 runtime selector source could not be read: {}",
            path_string(&runtime_mode)
        ));
    }
    if !default_runtime_selector_rust_owned {
        blockers.push("C2 no-env/auto runtime selector does not default to Rust-owned".to_owned());
    }
    if !explicit_go_rollback_only {
        blockers.push("C2 Go runtime rollback is not explicit-only".to_owned());
    }
    if !runtime_selector_matrix_recorded {
        blockers.push("C2 runtime selector matrix tests are not recorded".to_owned());
    }

    json!({
        "name": "default-runtime-selector",
        "status": if ready { "pass" } else { "blocked" },
        "runtime_mode_file": path_string(&runtime_mode),
        "runtime_mode_readable": runtime_mode_readable,
        "default_runtime_selector_rust_owned": default_runtime_selector_rust_owned,
        "no_env_default_rust_owned": runtime_mode_default_rust_owned,
        "auto_selects_rust_owned": auto_selects_rust_owned,
        "explicit_go_rollback_only": explicit_go_rollback_only,
        "runtime_selector_matrix_file": path_string(&tests),
        "runtime_selector_matrix_recorded": runtime_selector_matrix_recorded,
        "matrix": [
            "no DAED_RUNTIME -> rust-owned",
            "DAED_RUNTIME=auto -> rust-owned",
            "DAED_RUNTIME=rust-owned -> rust-owned",
            "DAED_RUNTIME=go -> explicit Go rollback",
            "DAED_RUNTIME_MODE follows the same aliases"
        ],
        "blockers": blockers,
    })
}
