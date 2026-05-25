use serde_json::{Value, json};

pub const DAEMON_CRATE_NAME: &str = "dae-daemon";
pub const OPTIN_BINARY_NAME: &str = "dae-daemon-optin";
pub const DEFAULT_DAEMON_MANIFEST: &str = "rust/crates/dae-daemon/Cargo.toml";
pub const GO_DEFAULT_IDENTITY: &str = "dae run";

pub fn daemon_identity(version: &str) -> Value {
    json!({
        "name": OPTIN_BINARY_NAME,
        "crate": DAEMON_CRATE_NAME,
        "version": version,
        "identity_class": "opt-in-rust-daemon-identity",
        "rust_daemon_identity_scaffolded": true,
        "rust_daemon_crate_manifest_exists": true,
        "rust_daemon_optin_binary_exists": true,
        "rust_daemon_identity_command_available": true,
        "rust_daemon_optin_run_command_available": true,
        "rust_default_run_entrypoint_exists": false,
        "rust_default_control_plane_entrypoint_admitted": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_daemon_identity": GO_DEFAULT_IDENTITY,
        "go_default_path_preserved": true,
        "default_path_mutation_allowed": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false,
    })
}
