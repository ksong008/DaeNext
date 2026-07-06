use super::*;
pub(super) const CAPABILITY_REASON_TAXONOMY: [&str; 9] = [
    "missing-security-underlay",
    "missing-stream-wrapper",
    "missing-packet-semantics",
    "missing-chain-executor",
    "missing-reload-lifecycle",
    "missing-live-evidence",
    "missing-benchmark-evidence",
    "unsupported-source-policy",
    "materialization-mismatch",
];

pub(super) const SCOPED_EXPANDED_SOURCE_MATRIX_EVIDENCE: ScopedExpandedSourceMatrixEvidence =
    ScopedExpandedSourceMatrixEvidence {
        schema: "scoped-expanded-source-evidence",
        schema_version: 1,
        scope_id: "full-expanded-source-scope",
        source_scope: "expanded-source-closure-rows",
        excluded_stream_wrappers: &[],
        opened_rows: &[
            "secure-endpoint-capability",
            "nested-chain-shape",
            "plugin-wrapper-layer",
            "legacy-layer-shape",
            "stream-wrapper-meek",
            "stream-wrapper-xhttp",
            "secure-websocket-framed-endpoint",
            "secure-httpupgrade-framed-endpoint",
            "verified-quic-security-underlay",
            "quic-port-hopping-surface",
            "inner-encryption-stream-wrapper",
            "obfs-tls-plugin-wrapper",
            "tls-websocket-plugin-wrapper",
            "aead-2022-plugin-wrapper",
            "proxy-transport-mode",
            "insecure-secure-endpoint-underlay",
            "fingerprint-secure-endpoint-underlay",
            "insecure-frame-stream-underlay",
            "full-utls-security-underlay",
            "tls-fragment-security-underlay",
            "reality-security-underlay",
            "shared-reality-security-underlay",
            "mux-transport-wrapper",
            "passthrough-udp-transport",
            "legacy-cipher-protocol-shape",
            "xhttp-h3-wrapper",
            "xhttp-extended-settings-wrapper",
        ],
        source_formats: &[
            "https-proxy-uri",
            "chain-expression",
            "shadowsocks-uri",
            "legacy-vmess-uri",
            "vless-uri",
            "vmess-wss-uri",
            "vmess-httpupgrade-uri",
            "tuic-uri",
            "hysteria2-port-hopping-uri",
            "trojan-go-uri",
            "shadowsocks-sip003-simple-obfs-tls-uri",
            "shadowsocks-sip003-v2ray-plugin-uri",
            "shadowsocks-2022-sip003-simple-obfs-http-uri",
            "http-proxy-transport-uri",
            "https-proxy-insecure-uri",
            "https-proxy-utls-uri",
            "anytls-insecure-uri",
            "vless-tls-global-utls-uri",
            "https-proxy-tls-fragment-uri",
            "vless-reality-uri",
            "shared-vless-reality-underlay-uri",
            "vless-mux-uri",
            "resident-udp-passthrough-source-shape",
            "shadowsocksr-origin-http-simple-uri",
            "vless-xhttp-h2-uri",
            "vless-xhttp-h3-uri",
            "vless-xhttp-download-settings-uri",
        ],
        candidate_sha256: "merged-evidence:3ea6efd5022e5079de4ffc654482dbeae6194a052ff0e6b7cce7c3f513b384a5+12a1622fdff29d95e954ba80a865c01fbb17dcacb345eb7468dae0ac818bab0b+3e33e9d1d620ce21d9f76976855297d7a42d9c82a26ab4adba78370ff9b83817+544198ea15e00a2e92ec56d35c816e1e7c7a44073842b9253eca44a448806912+aae0b211392a04f23b444a7097527b0ea8dd1e96955c2ef4a0ee3a13a8dea759",
        validation_boundary: "external-client-through-resident-proxy",
        upstream_boundary: "external-proxy-server-path",
        evidence_root: "capability-live-evidence-set",
        summary_artifact: "capability-live-summary.json",
        cleanup_artifact: "capability-live-cleanup.sh",
        row_count: 27,
        pass_count: 27,
        all_pass: true,
        large_page_all_pass: true,
        proxy_evidence_all_pass: true,
        benchmark_evidence_ready: true,
        benchmark_evidence_kind: "large-page-threshold-and-body-hash",
        cleanup_evidence_ready: true,
        raw_links_retained: false,
        raw_bodies_retained: false,
        raw_state_retained: false,
        production_ready: true,
    };

pub(super) const ADMITTED_STATE: ShapeStateLedger = ShapeStateLedger {
    source_shape: "source-supported",
    parser: "covered",
    resident_graph: "admitted",
    live: "requires-expanded-live-evidence",
    production_admission: "not-ready",
    production_state: "not-ready",
};

#[allow(dead_code)]
pub(super) const BLOCKED_STATE: ShapeStateLedger = ShapeStateLedger {
    source_shape: "source-supported",
    parser: "covered",
    resident_graph: "blocked",
    live: "blocked",
    production_admission: "blocked",
    production_state: "blocked",
};

pub(super) const NOT_SOURCE_SUPPORTED_STATE: ShapeStateLedger = ShapeStateLedger {
    source_shape: "not-source-supported",
    parser: "rejected",
    resident_graph: "blocked",
    live: "blocked",
    production_admission: "blocked",
    production_state: "blocked",
};

pub(super) const ADMITTED_EXECUTOR_PROOF: ComponentExecutorProof = ComponentExecutorProof {
    underlay_factory: "proved",
    stream_wrapper_factory: "proved",
    packet_semantics_factory: "proved",
    chain_executor: "single-graph-proved",
    probe_executor: "proved",
    reload_lifecycle: "proved",
    proof_state: "runtime-executable",
};

pub(super) const CHAIN_EXECUTOR_PROOF: ComponentExecutorProof = ComponentExecutorProof {
    underlay_factory: "proved",
    stream_wrapper_factory: "proved",
    packet_semantics_factory: "proved",
    chain_executor: "parent-connect-proved",
    probe_executor: "proved",
    reload_lifecycle: "proved",
    proof_state: "runtime-executable",
};

pub(super) const BLOCKED_EXECUTOR_PROOF: ComponentExecutorProof = ComponentExecutorProof {
    underlay_factory: "pending",
    stream_wrapper_factory: "pending",
    packet_semantics_factory: "pending",
    chain_executor: "pending",
    probe_executor: "pending",
    reload_lifecycle: "pending",
    proof_state: "descriptor-only-fail-closed",
};

pub(super) const ADMITTED_RUNTIME_SELECTION: RuntimeSelectionLedger = RuntimeSelectionLedger {
    selected_runtime_scope: "current-selected-resident-graph",
    unselected_source_scope: "expanded-source-ledger",
    fixed_policy_preserved: true,
    masks_expanded_source_coverage: false,
};

pub(super) const BLOCKED_RUNTIME_SELECTION: RuntimeSelectionLedger = RuntimeSelectionLedger {
    selected_runtime_scope: "not-selected",
    unselected_source_scope: "expanded-source-ledger",
    fixed_policy_preserved: true,
    masks_expanded_source_coverage: false,
};

pub(super) const BASE_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "baseline-admitted",
    stream_wrapper: "baseline-admitted",
    packet_semantics: "baseline-admitted",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

pub(super) const PLUGIN_WRAPPER_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "baseline-admitted",
    stream_wrapper: "resident-simple-obfs-http",
    packet_semantics: "tcp-stream-wrapper",
    plugin_wrapper: "resident-simple-obfs-http",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

pub(super) const INNER_ENCRYPTION_STREAM_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "baseline-admitted",
    stream_wrapper: "websocket",
    packet_semantics: "inner-encryption-stream",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

pub(super) const PLUGIN_WRAPPER_STREAM_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "aead-or-aead-2022",
    stream_wrapper: "resident-plugin-wrapper",
    packet_semantics: "tcp-stream-wrapper",
    plugin_wrapper: "resident-plugin-wrapper",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

pub(super) const PROXY_TRANSPORT_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "plain-or-standard-tls",
    stream_wrapper: "http-proxy-transport",
    packet_semantics: "tcp-stream",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

pub(super) const FINGERPRINT_SECURITY_UNDERLAY_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "fingerprint-aware-tls",
    stream_wrapper: "baseline-or-stream-wrapper",
    packet_semantics: "tcp-stream-or-packet-wrapper",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "fingerprint-aware-underlay",
};

pub(super) const INSECURE_SECURITY_UNDERLAY_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "explicit-insecure-tls",
    stream_wrapper: "baseline-or-frame-stream",
    packet_semantics: "tcp-stream-or-packet-wrapper",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "explicit-insecure-underlay",
};

pub(super) const TLS_FRAGMENT_SECURITY_UNDERLAY_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "tls-fragment",
    stream_wrapper: "baseline-or-stream-wrapper",
    packet_semantics: "tcp-stream-or-packet-wrapper",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "standard-tls-fragment-underlay",
};

pub(super) const REALITY_SECURITY_UNDERLAY_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "reality",
    stream_wrapper: "baseline-or-stream-wrapper",
    packet_semantics: "tcp-stream-or-packet-wrapper",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "reality-underlay",
};

pub(super) const MUX_TRANSPORT_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "plain-or-standard-tls",
    stream_wrapper: "resident-shared-mux-stream",
    packet_semantics: "multiplexed-stream",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

pub(super) const PASSTHROUGH_UDP_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "plain-or-native-underlay",
    stream_wrapper: "baseline-or-stream-wrapper",
    packet_semantics: "resident-passthrough-udp",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

pub(super) const SECURE_FRAME_STREAM_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "standard-tls",
    stream_wrapper: "secure-frame-stream",
    packet_semantics: "udp-over-stream-or-datagram",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "standard-tls-underlay",
};

pub(super) const VERIFIED_QUIC_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "verified-quic-tls",
    stream_wrapper: "quic-stream",
    packet_semantics: "quic-datagram-or-stream",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "verified-quic-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

pub(super) const QUIC_PORT_HOPPING_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "quic-tls",
    stream_wrapper: "quic-port-hopping",
    packet_semantics: "quic-datagram-or-stream",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "port-hopping-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

pub(super) const CHAIN_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "parent-connect-chain-admitted",
    security_underlay: "baseline-admitted",
    stream_wrapper: "baseline-admitted",
    packet_semantics: "tcp-resident-chain",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

pub(super) const LEGACY_IMPORT_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "baseline-admitted",
    stream_wrapper: "baseline-admitted",
    packet_semantics: "baseline-admitted",
    plugin_wrapper: "none",
    legacy_layer: "legacy-import-normalizer",
    quic_option: "baseline-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

pub(super) const LEGACY_STREAM_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "legacy-cipher",
    stream_wrapper: "resident-legacy-obfs-http-simple",
    packet_semantics: "tcp-stream",
    plugin_wrapper: "none",
    legacy_layer: "resident-legacy-stream-codec",
    quic_option: "baseline-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

pub(super) const NOT_SUPPORTED_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "rejected",
    security_underlay: "rejected",
    stream_wrapper: "rejected",
    packet_semantics: "rejected",
    plugin_wrapper: "rejected",
    legacy_layer: "rejected",
    quic_option: "rejected",
    secure_endpoint: "rejected",
};

#[allow(dead_code)]
pub(super) const DEFERRED_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-blocked",
    security_underlay: "pending-or-policy-blocked",
    stream_wrapper: "pending-or-policy-blocked",
    packet_semantics: "pending-or-policy-blocked",
    plugin_wrapper: "pending-or-policy-blocked",
    legacy_layer: "pending-or-policy-blocked",
    quic_option: "pending-or-policy-blocked",
    secure_endpoint: "pending-or-policy-blocked",
};

pub(super) const PENDING_LIVE_LEDGER: ExpandedLiveMatrixLedger = ExpandedLiveMatrixLedger {
    ledger_state: "pending-live-host-evidence",
    live_host_required: true,
    cleanup_artifact_required: true,
    large_page_evidence_required: true,
    blocked_rows_reduce_pass_threshold: false,
};

pub(super) const SCOPED_READY_LIVE_LEDGER: ExpandedLiveMatrixLedger = ExpandedLiveMatrixLedger {
    ledger_state: "scoped-live-host-evidence-ready",
    live_host_required: true,
    cleanup_artifact_required: true,
    large_page_evidence_required: true,
    blocked_rows_reduce_pass_threshold: false,
};

pub(super) const REJECTED_LIVE_LEDGER: ExpandedLiveMatrixLedger = ExpandedLiveMatrixLedger {
    ledger_state: "not-source-supported",
    live_host_required: false,
    cleanup_artifact_required: false,
    large_page_evidence_required: false,
    blocked_rows_reduce_pass_threshold: false,
};

#[allow(dead_code)]
pub(super) const BLOCKED_LIVE_LEDGER: ExpandedLiveMatrixLedger = ExpandedLiveMatrixLedger {
    ledger_state: "explicit-fail-closed",
    live_host_required: true,
    cleanup_artifact_required: true,
    large_page_evidence_required: true,
    blocked_rows_reduce_pass_threshold: false,
};

pub(super) const BASE_PRODUCTION_READINESS: ProductionReadinessReconciliation =
    ProductionReadinessReconciliation {
        current_baseline_agrees: true,
        expanded_source_agrees: false,
        service_contract_agrees: false,
        product_switch_ready: false,
        final_state_ready: false,
        cleanup_evidence_ready: false,
    };

pub(super) const SCOPED_READY_PRODUCTION_READINESS: ProductionReadinessReconciliation =
    ProductionReadinessReconciliation {
        current_baseline_agrees: true,
        expanded_source_agrees: true,
        service_contract_agrees: true,
        product_switch_ready: false,
        final_state_ready: false,
        cleanup_evidence_ready: true,
    };

pub(super) const REJECTED_PRODUCTION_READINESS: ProductionReadinessReconciliation =
    ProductionReadinessReconciliation {
        current_baseline_agrees: true,
        expanded_source_agrees: true,
        service_contract_agrees: true,
        product_switch_ready: false,
        final_state_ready: false,
        cleanup_evidence_ready: false,
    };
