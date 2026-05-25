use serde_json::{Value, json};

use crate::identity::{
    DAEMON_CRATE_NAME, DEFAULT_DAEMON_MANIFEST, GO_DEFAULT_IDENTITY, OPTIN_BINARY_NAME,
};

pub fn identity_preflight_report(version: &str) -> Value {
    json!({
        "name": "rust-daemon-identity-preflight",
        "crate": DAEMON_CRATE_NAME,
        "version": version,
        "optin_binary": OPTIN_BINARY_NAME,
        "crate_manifest": DEFAULT_DAEMON_MANIFEST,
        "go_default_daemon_identity": GO_DEFAULT_IDENTITY,
        "rust_daemon_identity_scaffolded": true,
        "rust_daemon_crate_manifest_exists": true,
        "rust_daemon_optin_binary_exists": true,
        "rust_daemon_identity_command_available": true,
        "rust_default_run_entrypoint_exists": false,
        "rust_default_control_plane_entrypoint_admitted": false,
        "rust_daemon_lifecycle_smoke_passed": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "true_rust_default_daemon_admitted": false,
        "default_switch_allowed": false,
        "default_path_mutation_allowed": false,
        "product_chain_switch_allowed": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "identity_scope": [
            "crate manifest exists",
            "opt-in binary exists",
            "identity/preflight command exists",
            "no production daemon startup",
            "no Go default path mutation"
        ],
        "next_required_rows": [
            "opt-in lifecycle smoke for pid/progress/sdnotify/reload/suspend under temporary paths",
            "Rust control-plane ownership admission",
            "matched Go/Rust default daemon benchmark after lifecycle smoke"
        ]
    })
}
