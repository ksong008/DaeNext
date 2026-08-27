use serde_json::{Value, json};

pub const PRODUCT_IDENTITY_CRATE_NAME: &str = "dae-product-identity";
pub const DAEMON_CRATE_NAME: &str = "dae-daemon";
pub const PRODUCT_BINARY_NAME: &str = "daed";
pub const DAEMON_MANIFEST: &str = "crates/dae-daemon/Cargo.toml";
pub const PRODUCT_SURFACE: &str = "native-product";
pub const RUNTIME_STATE_SCHEMA: &str = "runtime-state";
pub const PRODUCTION_ADMISSION_SCHEMA: &str = "production-admission";

pub fn daemon_identity(version: &str) -> Value {
    json!({
        "name": PRODUCT_BINARY_NAME,
        "crate": DAEMON_CRATE_NAME,
        "productCrate": PRODUCT_IDENTITY_CRATE_NAME,
        "productIdentityCrate": PRODUCT_IDENTITY_CRATE_NAME,
        "version": version,
        "productSurface": PRODUCT_SURFACE,
        "runtimeState": RUNTIME_STATE_SCHEMA,
        "identity_class": "rust-native-daemon-identity",
        "rust_daemon_identity_scaffolded": true,
        "rust_daemon_crate_manifest_exists": true,
        "rust_daemon_binary_exists": true,
        "rust_daemon_identity_command_available": true,
        "rust_daemon_run_command_available": true,
        "rust_run_entrypoint_exists": true,
        "rust_control_plane_entrypoint_admitted": true,
        "true_rust_native_daemon_admitted": true,
        "host_mutation_allowed": true,
        "identity_admission_allowed": true,
        "runtime_state_admission_allowed": true,
        "production_admission_allowed": false,
        "final_state_admission_allowed": true,
    })
}
