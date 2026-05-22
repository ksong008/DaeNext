#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage144VlessVmessRecertificationGateContract {
    pub name: &'static str,
    pub stage: &'static str,
    pub prior_gate: &'static str,
    pub stage_complete: bool,
    pub vless_vmess_fallback_aware_recertified: bool,
    pub vless_reality_go_fallback_admitted: bool,
    pub vless_vision_go_fallback_admitted: bool,
    pub vless_protocol_true_dataplane_admitted: bool,
    pub vmess_protocol_true_dataplane_admitted: bool,
    pub shared_transport_true_dataplane_admitted: bool,
    pub outbound_true_dataplane_admitted: bool,
    pub default_switch_allowed: bool,
    pub product_chain_switch_allowed: bool,
    pub gate_decision: &'static str,
    pub rows: Vec<Stage144VlessVmessRecertificationGateRow>,
    pub validation_commands: Vec<&'static str>,
    pub remaining_blockers: Vec<&'static str>,
    pub source: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage144VlessVmessRecertificationGateRow {
    pub area: &'static str,
    pub status: &'static str,
    pub evidence: &'static str,
    pub boundary: &'static str,
    pub next_action: &'static str,
}

pub fn stage144_vless_vmess_recertification_gate_contract()
-> Stage144VlessVmessRecertificationGateContract {
    Stage144VlessVmessRecertificationGateContract {
        name: "stage144-vless-vmess-fallback-aware-recertification-gate",
        stage: "stage144",
        prior_gate: "stage143-vless-vision-intrinsic-conn-fallback-gate",
        stage_complete: true,
        vless_vmess_fallback_aware_recertified: true,
        vless_reality_go_fallback_admitted: true,
        vless_vision_go_fallback_admitted: true,
        vless_protocol_true_dataplane_admitted: false,
        vmess_protocol_true_dataplane_admitted: false,
        shared_transport_true_dataplane_admitted: false,
        outbound_true_dataplane_admitted: false,
        default_switch_allowed: false,
        product_chain_switch_allowed: false,
        gate_decision: "stage144 recertifies VLESS/VMess as fallback-aware but not true Rust protocol-wide: completed Rust lifecycle/profile/synthetic rows are preserved, VLESS REALITY and Vision are explicitly Go fallback, VMess uTLS combinations remain fallback-bound, and shared/outbound/default/product switches stay closed",
        rows: vec![
            Stage144VlessVmessRecertificationGateRow {
                area: "completed Rust rows",
                status: "carried-forward",
                evidence: "Stage134-141 cover gRPC/WSS/HTTPUpgrade/xHTTP lifecycle, uTLS profile parser/builder, and synthetic REALITY raw mutation",
                boundary: "completed rows are partial and do not prove full uTLS/REALITY/Vision protocol-wide true dataplane",
                next_action: "carry these rows into shared_transport/outbound final gates as prerequisites only",
            },
            Stage144VlessVmessRecertificationGateRow {
                area: "Go fallback rows",
                status: "admitted-required",
                evidence: "Stage142 and Stage143 admit Go fallback for REALITY full handshake and Vision intrinsic conn",
                boundary: "fallback-aware recertification is not true Rust protocol-wide admission",
                next_action: "keep default switch closed until final product policy explicitly accepts fallback or true Rust replacements exist",
            },
        ],
        validation_commands: vec![
            "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage144/vless_vmess_fallback_aware_recertification_gate.json",
            "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage144_vless_vmess_fallback_aware_recertification_gate.json",
            "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage144-vless-vmess-fallback-aware-recertification-gate",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage144 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-product stage144 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage143 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
            "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
            "git diff --check",
        ],
        remaining_blockers: vec![
            "VLESS/VMess true Rust protocol-wide admission remains closed because residual uTLS/REALITY/Vision rows are fallback-bound",
            "Trojan-Go full shared transport remains blocked",
            "shared_transport_true_dataplane and outbound_true_dataplane remain closed until all protocol rows close",
            "matched Go default daemon vs true Rust candidate benchmark remains missing",
            "default daemon and product-chain switches remain closed",
        ],
        source: vec![
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage144",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.5",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.6",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
            "testdata/rebuild-golden/engine/runtime_stage142/vless_reality_full_handshake_fallback_gate.json",
            "testdata/rebuild-golden/engine/runtime_stage143/vless_vision_intrinsic_conn_fallback_gate.json",
        ],
    }
}
