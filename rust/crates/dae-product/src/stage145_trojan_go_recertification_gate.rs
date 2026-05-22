#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage145TrojanGoRecertificationGateContract {
    pub name: &'static str,
    pub stage: &'static str,
    pub prior_gate: &'static str,
    pub stage_complete: bool,
    pub trojan_go_fallback_aware_recertified: bool,
    pub trojan_go_shared_transport_go_fallback_required: bool,
    pub trojan_go_grpc_no_double_tls_guarded: bool,
    pub trojan_go_shared_transport_admitted: bool,
    pub trojan_go_utls_fingerprint_wire_admitted: bool,
    pub trojan_go_reality_mutation_admitted: bool,
    pub trojan_go_cross_combination_recertified: bool,
    pub shared_transport_true_dataplane_admitted: bool,
    pub outbound_true_dataplane_admitted: bool,
    pub default_switch_allowed: bool,
    pub product_chain_switch_allowed: bool,
    pub gate_decision: &'static str,
    pub rows: Vec<Stage145TrojanGoRecertificationGateRow>,
    pub validation_commands: Vec<&'static str>,
    pub remaining_blockers: Vec<&'static str>,
    pub source: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage145TrojanGoRecertificationGateRow {
    pub area: &'static str,
    pub status: &'static str,
    pub evidence: &'static str,
    pub boundary: &'static str,
    pub next_action: &'static str,
}

pub fn stage145_trojan_go_recertification_gate_contract()
-> Stage145TrojanGoRecertificationGateContract {
    Stage145TrojanGoRecertificationGateContract {
        name: "stage145-trojan-go-fallback-aware-recertification-gate",
        stage: "stage145",
        prior_gate: "stage144-vless-vmess-fallback-aware-recertification-gate",
        stage_complete: true,
        trojan_go_fallback_aware_recertified: true,
        trojan_go_shared_transport_go_fallback_required: true,
        trojan_go_grpc_no_double_tls_guarded: true,
        trojan_go_shared_transport_admitted: false,
        trojan_go_utls_fingerprint_wire_admitted: false,
        trojan_go_reality_mutation_admitted: false,
        trojan_go_cross_combination_recertified: false,
        shared_transport_true_dataplane_admitted: false,
        outbound_true_dataplane_admitted: false,
        default_switch_allowed: false,
        product_chain_switch_allowed: false,
        gate_decision: "stage145 recertifies Trojan-Go as fallback-aware but not full shared transport: Rust carries WSS/HTTPUpgrade/gRPC/inner-SS/TLS-fragment and one WSS+fragment+inner-SS combination, but uTLS wire, REALITY/full mutation, cross-combination protocol-wide evidence, shared/outbound true dataplane, default switch, and product-chain switch remain closed",
        rows: vec![
            Stage145TrojanGoRecertificationGateRow {
                area: "completed Trojan-Go Rust rows",
                status: "carried-forward",
                evidence: "Stage84-87 and Stage97-103 cover WSS, HTTPUpgrade, gRPC hunk/HTTP2/cache, inner Shadowsocks, TLS fragment, and one WSS+TLS-fragment+inner-SS combination",
                boundary: "completed rows are partial and do not prove every Trojan-Go shared transport combination",
                next_action: "carry these rows into shared_transport/outbound final gates as prerequisites only",
            },
            Stage145TrojanGoRecertificationGateRow {
                area: "high-risk fallback rows",
                status: "admitted-required",
                evidence: "memo 26.11 and 26.21 require grpc no double TLS, uTLS wire parity, REALITY/full mutation, and inner Shadowsocks semantics to remain guarded",
                boundary: "fallback-aware recertification is not trojan_go_shared_transport_admitted=true",
                next_action: "keep default switch closed until final policy accepts fallback or true Rust replacements exist",
            },
        ],
        validation_commands: vec![
            "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage145/trojan_go_fallback_aware_recertification_gate.json",
            "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage145_trojan_go_fallback_aware_recertification_gate.json",
            "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage145-trojan-go-fallback-aware-recertification-gate",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage145 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-product stage145 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage144 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
            "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
            "git diff --check",
        ],
        remaining_blockers: vec![
            "Trojan-Go shared transport is fallback-aware but not fully admitted",
            "Trojan-Go uTLS wire-level ClientHello fingerprint row remains closed",
            "Trojan-Go REALITY/full uTLS mutation row remains closed",
            "Trojan-Go cross-combination recertification remains closed",
            "shared_transport_true_dataplane and outbound_true_dataplane remain closed until all protocol rows close",
            "matched Go default daemon vs true Rust candidate benchmark remains missing",
            "default daemon and product-chain switches remain closed",
        ],
        source: vec![
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage145",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.11",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
            "testdata/rebuild-golden/engine/runtime_stage103/trojan_go_wss_tls_fragment_inner_ss_combination_admission.json",
            "rust/crates/dae-cli/src/runtime_stage103_trojan_go_combination_gate",
            "/root/project/outbound/dialer/trojan/trojan.go",
        ],
    }
}
