#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplexDataplaneGateContract {
    pub name: &'static str,
    pub stage: &'static str,
    pub gate_complete: bool,
    pub default_switch_allowed: bool,
    pub go_fallback_required: bool,
    pub first_batch_completed: Vec<&'static str>,
    pub complex_rows: Vec<ComplexDataplaneGateRow>,
    pub reopen_requirements: Vec<&'static str>,
    pub validation_commands: Vec<&'static str>,
    pub source: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplexDataplaneGateRow {
    pub protocol: &'static str,
    pub blocker_class: &'static str,
    pub rust_current_state: &'static str,
    pub required_before_true_dataplane: Vec<&'static str>,
    pub next_allowed_step: &'static str,
}

pub fn complex_dataplane_gate_contract() -> ComplexDataplaneGateContract {
    ComplexDataplaneGateContract {
        name: "stage19-complex-dataplane-gate",
        stage: "stage19",
        gate_complete: true,
        default_switch_allowed: false,
        go_fallback_required: true,
        first_batch_completed: vec![
            "SOCKS5 TCP CONNECT loopback true dataplane",
            "HTTP CONNECT loopback true dataplane",
            "Shadowsocks AEAD TCP loopback true dataplane",
        ],
        complex_rows: vec![
            ComplexDataplaneGateRow {
                protocol: "Trojan-Go",
                blocker_class: "shared-transport-and-inner-shadowsocks",
                rust_current_state: "parser, trojanc framing, and inner Shadowsocks contract exist; TLS/WS/gRPC/HTTPUpgrade live data plane remains Go fallback",
                required_before_true_dataplane: vec![
                    "TLS TCP live client/server smoke",
                    "WS and HTTPUpgrade tunnel lifecycle smoke",
                    "gRPC stream lifecycle and cache cleanup smoke",
                    "inner Shadowsocks encryption smoke",
                    "reload closes shared transport clients",
                ],
                next_allowed_step: "build shared transport loopback harness before protocol default-switch work",
            },
            ComplexDataplaneGateRow {
                protocol: "VMess",
                blocker_class: "aead-and-shared-transport",
                rust_current_state: "parser, UUID, metadata, header, and transport contract exist; VMess AEAD stream remains Go fallback",
                required_before_true_dataplane: vec![
                    "VMess AEAD command/header encryption smoke",
                    "TCP stream payload roundtrip smoke",
                    "shared transport live smoke",
                    "Go vs Rust AEAD benchmark",
                    "fallback and rollback smoke",
                ],
                next_allowed_step: "implement VMess AEAD codec fixture before live transport work",
            },
            ComplexDataplaneGateRow {
                protocol: "VLESS Vision",
                blocker_class: "vision-reality-xhttp-grpc-meek",
                rust_current_state: "parser, Password2Key, request header, Vision, REALITY, xHTTP, gRPC, and Meek contracts exist; true Vision transport remains Go fallback",
                required_before_true_dataplane: vec![
                    "plain VLESS TCP roundtrip smoke",
                    "Vision TLS conn hook smoke",
                    "REALITY uTLS handshake mutation smoke",
                    "xHTTP H2/H3 stream and packet lifecycle smoke",
                    "gRPC and Meek lifecycle smoke",
                ],
                next_allowed_step: "split plain VLESS TCP from Vision/REALITY before default-switch evaluation",
            },
            ComplexDataplaneGateRow {
                protocol: "Hysteria2",
                blocker_class: "quic-udp-hop-route-cache",
                rust_current_state: "parser, auth, pinSHA256, bandwidth, UDP hop, server, underlay, and route-cache contracts exist; QUIC data plane remains Go fallback",
                required_before_true_dataplane: vec![
                    "QUIC client/server live smoke",
                    "UDP hop PacketConn smoke",
                    "route-cache and underlay smoke",
                    "throughput benchmark",
                    "fallback and rollback smoke",
                ],
                next_allowed_step: "establish shared QUIC loopback harness for Hysteria2/TUIC/Juicity",
            },
            ComplexDataplaneGateRow {
                protocol: "TUIC",
                blocker_class: "quic-stream-datagram",
                rust_current_state: "parser, UUID, QUIC config, UDP relay, and underlay contracts exist; QUIC stream/datagram data plane remains Go fallback",
                required_before_true_dataplane: vec![
                    "QUIC stream roundtrip smoke",
                    "QUIC datagram roundtrip smoke",
                    "UDP relay mode smoke",
                    "Go vs Rust QUIC benchmark",
                    "reload and fallback smoke",
                ],
                next_allowed_step: "share QUIC harness with Hysteria2 before TUIC-specific stream/datagram work",
            },
            ComplexDataplaneGateRow {
                protocol: "Juicity",
                blocker_class: "quic-h3-cert-chain-packet-conn",
                rust_current_state: "parser, UUID, pinned certchain, QUIC config, and UDP packet connection contract exist; QUIC/H3 data plane remains Go fallback",
                required_before_true_dataplane: vec![
                    "QUIC/H3 client/server live smoke",
                    "pinned certificate chain runtime verify smoke",
                    "packet connection roundtrip smoke",
                    "Go vs Rust QUIC/H3 benchmark",
                    "fallback and rollback smoke",
                ],
                next_allowed_step: "complete QUIC/H3 harness and cert-chain verifier before data-plane switch",
            },
            ComplexDataplaneGateRow {
                protocol: "AnyTLS",
                blocker_class: "tls-session-multiplexing-packet-stream",
                rust_current_state: "parser, auth key, padding, frame, session, UDP magic domain, and underlay contracts exist; session data plane remains Go fallback",
                required_before_true_dataplane: vec![
                    "TLS session live smoke",
                    "session multiplexing lifecycle smoke",
                    "packet stream roundtrip smoke",
                    "Go vs Rust session benchmark",
                    "reload cleanup and fallback smoke",
                ],
                next_allowed_step: "build AnyTLS session harness before packet stream default-switch work",
            },
            ComplexDataplaneGateRow {
                protocol: "shared transport",
                blocker_class: "foundation-blocker",
                rust_current_state: "TLS/uTLS/REALITY, WS/WSS, gRPC, HTTPUpgrade, Meek, SimpleObfs, Mux, and xHTTP IR/helper exist; true shared transport remains Go fallback",
                required_before_true_dataplane: vec![
                    "TLS and uTLS handshake live smoke",
                    "REALITY handshake mutation live smoke",
                    "xHTTP H2/H3 pool and stream lifecycle smoke",
                    "gRPC global cache isolation and cleanup smoke",
                    "Meek polling RoundTripper lifecycle smoke",
                    "Mux true multiplexing smoke",
                ],
                next_allowed_step: "make shared transport the Stage 19 foundation work item before complex protocols",
            },
        ],
        reopen_requirements: vec![
            "each complex protocol must have a live loopback or real server/client smoke",
            "reload must close or safely reuse protocol transports and global caches",
            "Go and Rust benchmarks must use matched payloads and connection lifecycle",
            "active datapath mark, mptcp, tproxy, DNS, and UDP path must be validated with protocol traffic",
            "default switch remains blocked until daemon readiness is re-opened with true data-plane evidence",
        ],
        validation_commands: vec![
            "cargo test --manifest-path rust/Cargo.toml -p dae-product complex_dataplane_gate_contract_matches_golden_fixture -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml --workspace",
            "PATH=/root/.local/go1.25.9/bin:$PATH GOWORK=off go test ./component/outbound ./component/outbound/dialer -count=1",
            "git diff --check",
        ],
        source: vec![
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage19",
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage17-item125",
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage18",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:29",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:33",
            "rust/crates/dae-outbound/src/shared_transport",
            "rust/crates/dae-product/src/protocol_dataplane.rs",
        ],
    }
}
