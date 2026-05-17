#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundNativeMigrationContract {
    pub current_boundary_contains_native_direct_block: bool,
    pub current_boundary_contains_bridge_or_stub: bool,
    pub replacement_rule: &'static str,
    pub not_silent_complete: bool,
    pub minimum_before_replacing_default_path: Vec<&'static str>,
}

pub fn outbound_native_migration_contract() -> OutboundNativeMigrationContract {
    OutboundNativeMigrationContract {
        current_boundary_contains_native_direct_block: true,
        current_boundary_contains_bridge_or_stub: true,
        replacement_rule: "protocols must move one by one from bridge-or-stub to native with fixture and live connectivity evidence",
        not_silent_complete: true,
        minimum_before_replacing_default_path: vec![
            "link parser fixture",
            "protocol handshake fixture",
            "transport option fixture",
            "live connectivity smoke test",
            "Go/Rust benchmark or latency observation",
        ],
    }
}
