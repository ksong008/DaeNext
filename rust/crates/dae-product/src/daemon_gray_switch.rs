#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonGraySwitchGateContract {
    pub name: &'static str,
    pub stage: &'static str,
    pub prior_gate: &'static str,
    pub stage21_harness_complete: bool,
    pub default_switch_allowed: bool,
    pub go_default_path_preserved: bool,
    pub go_fallback_required: bool,
    pub gray_switch_decision: &'static str,
    pub allowed_gray_scope: Vec<&'static str>,
    pub denied_default_scope: Vec<&'static str>,
    pub readiness_rows: Vec<DaemonGraySwitchReadinessRow>,
    pub required_runtime_evidence: Vec<&'static str>,
    pub rollback_controls: Vec<&'static str>,
    pub validation_commands: Vec<&'static str>,
    pub source: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonGraySwitchReadinessRow {
    pub area: &'static str,
    pub current_state: &'static str,
    pub gray_switch_status: &'static str,
    pub blockers: Vec<&'static str>,
}

pub fn daemon_gray_switch_gate_contract() -> DaemonGraySwitchGateContract {
    DaemonGraySwitchGateContract {
        name: "stage22-daemon-gray-switch-gate",
        stage: "stage22",
        prior_gate: "stage16-daemon-default-readiness",
        stage21_harness_complete: true,
        default_switch_allowed: false,
        go_default_path_preserved: true,
        go_fallback_required: true,
        gray_switch_decision: "blocked_for_default_path; continue opt-in evidence collection only",
        allowed_gray_scope: vec![
            "offline Rust fixture and contract tests",
            "dae-cli-optin helper smoke tests",
            "local loopback protocol dataplane harnesses",
            "product-level readiness gate evaluation",
        ],
        denied_default_scope: vec![
            "do not switch dae run default engine to Rust",
            "do not replace Go control.NewControlPlane default path",
            "do not route production outbound traffic through Rust shared transport by default",
            "do not claim daed or dae-wing product integration is complete",
        ],
        readiness_rows: vec![
            DaemonGraySwitchReadinessRow {
                area: "engine runtime facade",
                current_state: "Rust API-only and dry-runtime contracts exist; Go engine remains default daemon facade",
                gray_switch_status: "opt-in-only",
                blockers: vec![
                    "route-aware HTTP transport needs live control-plane route smoke",
                    "reload rollback must prove DNS listener/cache migration under failure",
                    "subscription persist.d cleanup and wait-for-network need daemon smoke",
                ],
            },
            DaemonGraySwitchReadinessRow {
                area: "active datapath",
                current_state: "Rust ABI, eBPF support, control, and datapath models exist; active tproxy/eBPF runtime remains Go owned",
                gray_switch_status: "blocked",
                blockers: vec![
                    "root/BPF/netns/memlock/kernel gate must pass in daemon smoke",
                    "TCP and UDP active traffic must preserve MagicNetwork mark and mptcp",
                    "DNS UDP/53 and QUIC sniff reroute behavior need runtime evidence",
                    "reload must prove BPF eject/inject rollback safety",
                ],
            },
            DaemonGraySwitchReadinessRow {
                area: "first-batch outbound dataplane",
                current_state: "SOCKS5 TCP, HTTP CONNECT, Shadowsocks AEAD TCP, HTTPUpgrade, WebSocket frame, and SimpleObfs HTTP have local loopback Rust dataplane harnesses",
                gray_switch_status: "candidate-for-opt-in-smoke",
                blockers: vec![
                    "not wired into daemon runtime dialer selection",
                    "UDP associate and active traffic mark/mptcp smoke still required",
                    "reload cleanup and fallback smoke still required",
                ],
            },
            DaemonGraySwitchReadinessRow {
                area: "deep shared transport",
                current_state: "Stage21 added REALITY mutation, xHTTP lifecycle, gRPC hunk/cache, Meek polling, Mux frame, and QUIC/H3 datagram harnesses",
                gray_switch_status: "harness-only",
                blockers: vec![
                    "REALITY still needs production uTLS handshake state mutation",
                    "xHTTP still needs real H2/H3 pool and stream lifecycle",
                    "gRPC still needs production HTTP/2 stream lifecycle",
                    "Meek still needs HTTPS RoundTripper lifecycle",
                    "QUIC/H3 still needs real crypto and H3 stack",
                ],
            },
            DaemonGraySwitchReadinessRow {
                area: "complex protocols",
                current_state: "VMess, VLESS Vision, Trojan-Go, Hysteria2, TUIC, Juicity, and AnyTLS remain partial helper/contract/harness implementations",
                gray_switch_status: "blocked",
                blockers: vec![
                    "VMess AEAD stream dataplane is not complete",
                    "VLESS Vision intrinsic TLS/REALITY conn hook is not complete",
                    "Trojan-Go shared transport and inner Shadowsocks dataplane are not complete",
                    "QUIC-family production dataplanes remain Go fallback",
                    "AnyTLS session multiplexing and packet stream remain Go fallback",
                ],
            },
            DaemonGraySwitchReadinessRow {
                area: "product integration",
                current_state: "dae-wing and daed integration remains explicitly deferred",
                gray_switch_status: "deferred",
                blockers: vec![
                    "Rust daemon default path is not approved",
                    "API and WebUI product chain must wait for daemon parity gate",
                    "release/install default artifacts must keep Go fallback behavior",
                ],
            },
        ],
        required_runtime_evidence: vec![
            "make dae artifact smoke with Go fallback preserved",
            "daemon dry-run and live run smoke",
            "TCP active traffic through Rust candidate path with mark and mptcp",
            "UDP active traffic and DNS UDP/53 behavior",
            "reload success and reload rollback under injected failure",
            "RuntimeOverview before and after control-plane init",
            "route-aware HTTP transport domain target without system DNS resolution",
            "matched Go/Rust benchmark on daemon runtime traffic, not helper-only microbenchmarks",
        ],
        rollback_controls: vec![
            "default command path remains Go",
            "unset DAE_RUST_* opt-in environment variables",
            "disable dae-cli-optin helper path",
            "keep Go outbound dependency as production fallback",
            "do not mutate installed systemd ExecStart to Rust-only mode",
        ],
        validation_commands: vec![
            "cargo test --manifest-path rust/Cargo.toml -p dae-product daemon_gray_switch_gate_contract_matches_golden_fixture -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml --workspace",
            "PATH=/root/.local/go1.25.9/bin:$PATH GOWORK=off go test ./cmd ./engine ./control ./component/outbound ./component/outbound/dialer -count=1",
            "PATH=/root/.local/go1.25.9/bin:$PATH GOWORK=off OUTPUT=/tmp/dae-stage22-gate make dae",
            "git diff --check",
        ],
        source: vec![
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage22",
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage16",
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage17",
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage21",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:29",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:33",
            "rust/crates/dae-product/src/daemon_default.rs",
            "rust/crates/dae-outbound/src/shared_transport",
        ],
    }
}
