use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceShapeRegistryContract {
    pub schema: &'static str,
    pub schema_version: u64,
    pub rows: &'static [SourceShapeRegistryRow],
    pub source_shape_registry_open: bool,
    pub expanded_source_matrix_open: bool,
    pub expanded_source_matrix_complete: bool,
    pub release_gate_may_use_current_config_matrix_as_source_matrix: bool,
}

impl SourceShapeRegistryContract {
    pub fn to_value(self) -> Value {
        json!({
            "schema": self.schema,
            "schemaVersion": self.schema_version,
            "sourceShapeRegistryOpen": self.source_shape_registry_open,
            "expandedSourceMatrixOpen": self.expanded_source_matrix_open,
            "expandedSourceMatrixComplete": self.expanded_source_matrix_complete,
            "releaseGateMayUseCurrentConfigMatrixAsSourceMatrix": self.release_gate_may_use_current_config_matrix_as_source_matrix,
            "rowCount": self.rows.len(),
            "rows": self.rows.iter().map(|row| row.to_value()).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceShapeRegistryRow {
    pub shape_id: &'static str,
    pub source_support: &'static str,
    pub protocol_family: &'static str,
    pub link_schemes: &'static [&'static str],
    pub endpoint: &'static str,
    pub security_underlay: &'static str,
    pub stream_wrapper: &'static str,
    pub packet_semantics: &'static str,
    pub chain_shape: &'static str,
    pub policy_surface: &'static str,
    pub reload_lifecycle: &'static str,
    pub parser_coverage: &'static str,
    pub resident_status: &'static str,
    pub blocker_id: Option<&'static str>,
    pub evidence_requirements: &'static [&'static str],
    pub redacted_identity: &'static str,
    pub state_ledger: ShapeStateLedger,
    pub executor_proof: ComponentExecutorProof,
    pub runtime_selection: RuntimeSelectionLedger,
    pub capability: CapabilityLedger,
    pub expanded_live_matrix: ExpandedLiveMatrixLedger,
    pub release_gate: ReleaseGateReconciliation,
}

impl SourceShapeRegistryRow {
    pub fn to_value(self) -> Value {
        json!({
            "shapeId": self.shape_id,
            "sourceSupport": self.source_support,
            "protocolFamily": self.protocol_family,
            "linkSchemes": self.link_schemes,
            "endpoint": self.endpoint,
            "securityUnderlay": self.security_underlay,
            "streamWrapper": self.stream_wrapper,
            "packetSemantics": self.packet_semantics,
            "chainShape": self.chain_shape,
            "policySurface": self.policy_surface,
            "reloadLifecycle": self.reload_lifecycle,
            "parserCoverage": self.parser_coverage,
            "residentStatus": self.resident_status,
            "blockerId": self.blocker_id,
            "evidenceRequirements": self.evidence_requirements,
            "redactedIdentity": self.redacted_identity,
            "shapeStateLedger": self.state_ledger.to_value(),
            "componentExecutorProof": self.executor_proof.to_value(),
            "runtimeSelectionLedger": self.runtime_selection.to_value(),
            "capabilityLedger": self.capability.to_value(),
            "expandedLiveMatrixLedger": self.expanded_live_matrix.to_value(),
            "releaseGateReconciliation": self.release_gate.to_value(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShapeStateLedger {
    pub source_shape: &'static str,
    pub parser: &'static str,
    pub resident_graph: &'static str,
    pub live: &'static str,
    pub default_switch: &'static str,
    pub go_free: &'static str,
}

impl ShapeStateLedger {
    pub fn to_value(self) -> Value {
        json!({
            "sourceShape": self.source_shape,
            "parser": self.parser,
            "residentGraph": self.resident_graph,
            "live": self.live,
            "defaultSwitch": self.default_switch,
            "goFree": self.go_free,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentExecutorProof {
    pub underlay_factory: &'static str,
    pub stream_wrapper_factory: &'static str,
    pub packet_semantics_factory: &'static str,
    pub chain_executor: &'static str,
    pub probe_executor: &'static str,
    pub reload_lifecycle: &'static str,
    pub proof_state: &'static str,
}

impl ComponentExecutorProof {
    pub fn to_value(self) -> Value {
        json!({
            "underlayFactory": self.underlay_factory,
            "streamWrapperFactory": self.stream_wrapper_factory,
            "packetSemanticsFactory": self.packet_semantics_factory,
            "chainExecutor": self.chain_executor,
            "probeExecutor": self.probe_executor,
            "reloadLifecycle": self.reload_lifecycle,
            "proofState": self.proof_state,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeSelectionLedger {
    pub selected_runtime_scope: &'static str,
    pub unselected_source_scope: &'static str,
    pub fixed_policy_preserved: bool,
    pub masks_expanded_source_coverage: bool,
}

impl RuntimeSelectionLedger {
    pub fn to_value(self) -> Value {
        json!({
            "selectedRuntimeScope": self.selected_runtime_scope,
            "unselectedSourceScope": self.unselected_source_scope,
            "fixedPolicyPreserved": self.fixed_policy_preserved,
            "masksExpandedSourceCoverage": self.masks_expanded_source_coverage,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityLedger {
    pub graph_composition: &'static str,
    pub security_underlay: &'static str,
    pub stream_wrapper: &'static str,
    pub packet_semantics: &'static str,
    pub plugin_wrapper: &'static str,
    pub legacy_layer: &'static str,
    pub quic_option: &'static str,
    pub secure_endpoint: &'static str,
}

impl CapabilityLedger {
    pub fn to_value(self) -> Value {
        json!({
            "graphComposition": self.graph_composition,
            "securityUnderlay": self.security_underlay,
            "streamWrapper": self.stream_wrapper,
            "packetSemantics": self.packet_semantics,
            "pluginWrapper": self.plugin_wrapper,
            "legacyLayer": self.legacy_layer,
            "quicOption": self.quic_option,
            "secureEndpoint": self.secure_endpoint,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpandedLiveMatrixLedger {
    pub ledger_state: &'static str,
    pub live_host_required: bool,
    pub rollback_artifact_required: bool,
    pub large_page_evidence_required: bool,
    pub blocked_rows_reduce_pass_threshold: bool,
}

impl ExpandedLiveMatrixLedger {
    pub fn to_value(self) -> Value {
        json!({
            "ledgerState": self.ledger_state,
            "liveHostRequired": self.live_host_required,
            "rollbackArtifactRequired": self.rollback_artifact_required,
            "largePageEvidenceRequired": self.large_page_evidence_required,
            "blockedRowsReducePassThreshold": self.blocked_rows_reduce_pass_threshold,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseGateReconciliation {
    pub current_baseline_agrees: bool,
    pub expanded_source_agrees: bool,
    pub service_contract_agrees: bool,
    pub product_chain_agrees: bool,
    pub c9_switch_ready: bool,
    pub c10_final_ready: bool,
    pub rollback_artifact_ready: bool,
}

impl ReleaseGateReconciliation {
    pub fn to_value(self) -> Value {
        json!({
            "currentBaselineAgrees": self.current_baseline_agrees,
            "expandedSourceAgrees": self.expanded_source_agrees,
            "serviceContractAgrees": self.service_contract_agrees,
            "productChainAgrees": self.product_chain_agrees,
            "c9SwitchReady": self.c9_switch_ready,
            "c10FinalReady": self.c10_final_ready,
            "rollbackArtifactReady": self.rollback_artifact_ready,
        })
    }
}

pub fn source_shape_registry_contract() -> SourceShapeRegistryContract {
    SourceShapeRegistryContract {
        schema: "outbound-source-shape-registry",
        schema_version: 1,
        rows: source_shape_registry_rows(),
        source_shape_registry_open: true,
        expanded_source_matrix_open: true,
        expanded_source_matrix_complete: false,
        release_gate_may_use_current_config_matrix_as_source_matrix: false,
    }
}

pub fn source_shape_registry_rows() -> &'static [SourceShapeRegistryRow] {
    &SOURCE_SHAPE_REGISTRY_ROWS
}

pub fn capability_reason_taxonomy() -> &'static [&'static str] {
    &CAPABILITY_REASON_TAXONOMY
}

const CAPABILITY_REASON_TAXONOMY: [&str; 9] = [
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

const ADMITTED_STATE: ShapeStateLedger = ShapeStateLedger {
    source_shape: "source-supported",
    parser: "covered",
    resident_graph: "admitted",
    live: "requires-expanded-live-evidence",
    default_switch: "not-ready",
    go_free: "not-ready",
};

const BLOCKED_STATE: ShapeStateLedger = ShapeStateLedger {
    source_shape: "source-supported",
    parser: "covered-or-source-declared",
    resident_graph: "blocked",
    live: "blocked",
    default_switch: "blocked",
    go_free: "blocked",
};

const NOT_SOURCE_SUPPORTED_STATE: ShapeStateLedger = ShapeStateLedger {
    source_shape: "not-source-supported",
    parser: "rejected",
    resident_graph: "blocked",
    live: "blocked",
    default_switch: "blocked",
    go_free: "blocked",
};

const ADMITTED_EXECUTOR_PROOF: ComponentExecutorProof = ComponentExecutorProof {
    underlay_factory: "proved",
    stream_wrapper_factory: "proved",
    packet_semantics_factory: "proved",
    chain_executor: "single-graph-proved",
    probe_executor: "proved",
    reload_lifecycle: "proved",
    proof_state: "runtime-executable",
};

const BLOCKED_EXECUTOR_PROOF: ComponentExecutorProof = ComponentExecutorProof {
    underlay_factory: "pending",
    stream_wrapper_factory: "pending",
    packet_semantics_factory: "pending",
    chain_executor: "pending",
    probe_executor: "pending",
    reload_lifecycle: "pending",
    proof_state: "descriptor-only-fail-closed",
};

const ADMITTED_RUNTIME_SELECTION: RuntimeSelectionLedger = RuntimeSelectionLedger {
    selected_runtime_scope: "current-selected-resident-graph",
    unselected_source_scope: "expanded-source-ledger",
    fixed_policy_preserved: true,
    masks_expanded_source_coverage: false,
};

const BLOCKED_RUNTIME_SELECTION: RuntimeSelectionLedger = RuntimeSelectionLedger {
    selected_runtime_scope: "not-selected",
    unselected_source_scope: "expanded-source-ledger",
    fixed_policy_preserved: true,
    masks_expanded_source_coverage: false,
};

const BASE_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "baseline-admitted",
    stream_wrapper: "baseline-admitted",
    packet_semantics: "baseline-admitted",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

const BLOCKED_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "blocked-until-executor-proof",
    security_underlay: "blocked-until-underlay-proof",
    stream_wrapper: "blocked-until-wrapper-proof",
    packet_semantics: "blocked-until-packet-proof",
    plugin_wrapper: "blocked-until-wrapper-proof",
    legacy_layer: "blocked-until-legacy-proof",
    quic_option: "blocked-until-option-proof",
    secure_endpoint: "blocked-until-underlay-proof",
};

const NOT_SUPPORTED_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "rejected",
    security_underlay: "rejected",
    stream_wrapper: "rejected",
    packet_semantics: "rejected",
    plugin_wrapper: "rejected",
    legacy_layer: "rejected",
    quic_option: "rejected",
    secure_endpoint: "rejected",
};

const PENDING_LIVE_LEDGER: ExpandedLiveMatrixLedger = ExpandedLiveMatrixLedger {
    ledger_state: "pending-live-host-evidence",
    live_host_required: true,
    rollback_artifact_required: true,
    large_page_evidence_required: true,
    blocked_rows_reduce_pass_threshold: false,
};

const BLOCKED_LIVE_LEDGER: ExpandedLiveMatrixLedger = ExpandedLiveMatrixLedger {
    ledger_state: "blocked-before-live",
    live_host_required: true,
    rollback_artifact_required: true,
    large_page_evidence_required: true,
    blocked_rows_reduce_pass_threshold: false,
};

const REJECTED_LIVE_LEDGER: ExpandedLiveMatrixLedger = ExpandedLiveMatrixLedger {
    ledger_state: "not-source-supported",
    live_host_required: false,
    rollback_artifact_required: false,
    large_page_evidence_required: false,
    blocked_rows_reduce_pass_threshold: false,
};

const BASE_RELEASE_GATE: ReleaseGateReconciliation = ReleaseGateReconciliation {
    current_baseline_agrees: true,
    expanded_source_agrees: false,
    service_contract_agrees: false,
    product_chain_agrees: false,
    c9_switch_ready: false,
    c10_final_ready: false,
    rollback_artifact_ready: false,
};

const BLOCKED_RELEASE_GATE: ReleaseGateReconciliation = ReleaseGateReconciliation {
    current_baseline_agrees: false,
    expanded_source_agrees: true,
    service_contract_agrees: false,
    product_chain_agrees: false,
    c9_switch_ready: false,
    c10_final_ready: false,
    rollback_artifact_ready: false,
};

const REJECTED_RELEASE_GATE: ReleaseGateReconciliation = ReleaseGateReconciliation {
    current_baseline_agrees: true,
    expanded_source_agrees: true,
    service_contract_agrees: true,
    product_chain_agrees: false,
    c9_switch_ready: false,
    c10_final_ready: false,
    rollback_artifact_ready: false,
};

const SOURCE_SHAPE_REGISTRY_ROWS: [SourceShapeRegistryRow; 23] = [
    admitted_row(
        "baseline-aead-cipher-endpoint",
        "shadowsocks",
        &["ss"],
        "aead",
        "none",
        "udp-over-stream-or-datagram",
        "registry:baseline-aead-cipher-endpoint",
    ),
    admitted_row(
        "baseline-tls-auth-endpoint",
        "trojan",
        &["trojan"],
        "standard-tls",
        "none",
        "udp-over-stream-or-datagram",
        "registry:baseline-tls-auth-endpoint",
    ),
    admitted_row(
        "baseline-aead-framed-endpoint",
        "vmess",
        &["vmess"],
        "aead",
        "none",
        "udp-over-stream-or-datagram",
        "registry:baseline-aead-framed-endpoint",
    ),
    admitted_row(
        "baseline-tls-vision-endpoint",
        "vless",
        &["vless"],
        "standard-or-fingerprint-aware-tls",
        "none",
        "xudp",
        "registry:baseline-tls-vision-endpoint",
    ),
    admitted_row(
        "baseline-quic-auth-endpoint",
        "hysteria2",
        &["hysteria2", "hy2"],
        "quic-tls",
        "quic-stream",
        "quic-datagram-or-stream",
        "registry:baseline-quic-auth-endpoint",
    ),
    admitted_row(
        "baseline-quic-uuid-endpoint",
        "tuic",
        &["tuic"],
        "quic-tls",
        "quic-stream",
        "quic-datagram-or-stream",
        "registry:baseline-quic-uuid-endpoint",
    ),
    admitted_row(
        "baseline-quic-password-endpoint",
        "juicity",
        &["juicity"],
        "quic-tls",
        "quic-stream",
        "quic-datagram-or-stream",
        "registry:baseline-quic-password-endpoint",
    ),
    admitted_row(
        "baseline-frame-stream-endpoint",
        "anytls",
        &["anytls"],
        "standard-tls",
        "frame-stream",
        "udp-over-stream-or-datagram",
        "registry:baseline-frame-stream-endpoint",
    ),
    admitted_row(
        "baseline-connect-endpoint",
        "http-proxy",
        &["http"],
        "none",
        "none",
        "protocol-closed",
        "registry:baseline-connect-endpoint",
    ),
    admitted_row(
        "baseline-socks-endpoint",
        "socks5",
        &["socks5", "socks"],
        "none",
        "none",
        "udp-associate",
        "registry:baseline-socks-endpoint",
    ),
    blocked_row(
        "stream-wrapper-websocket",
        "multi-protocol",
        &["vless", "vmess", "trojan", "trojan-go"],
        "standard-or-fingerprint-aware-tls",
        "websocket",
        "udp-over-stream-or-datagram",
        "missing-stream-wrapper",
        &[
            "wrapper-cache-lifecycle",
            "cancellation",
            "loopback",
            "large-page-live",
            "benchmark",
            "rollback",
        ],
        "registry:stream-wrapper-websocket",
    ),
    blocked_row(
        "stream-wrapper-grpc",
        "multi-protocol",
        &["vless", "vmess", "trojan", "trojan-go"],
        "standard-or-fingerprint-aware-tls",
        "grpc",
        "udp-over-stream-or-datagram",
        "missing-stream-wrapper",
        &[
            "wrapper-cache-lifecycle",
            "cancellation",
            "loopback",
            "large-page-live",
            "benchmark",
            "rollback",
        ],
        "registry:stream-wrapper-grpc",
    ),
    blocked_row(
        "stream-wrapper-httpupgrade",
        "multi-protocol",
        &["vless", "vmess", "trojan-go"],
        "standard-or-fingerprint-aware-tls",
        "httpupgrade",
        "udp-over-stream-or-datagram",
        "missing-stream-wrapper",
        &[
            "wrapper-cache-lifecycle",
            "cancellation",
            "loopback",
            "large-page-live",
            "benchmark",
            "rollback",
        ],
        "registry:stream-wrapper-httpupgrade",
    ),
    blocked_row(
        "stream-wrapper-meek",
        "multi-protocol",
        &["vless", "vmess"],
        "standard-or-fingerprint-aware-tls",
        "meek",
        "udp-over-stream-or-datagram",
        "missing-stream-wrapper",
        &[
            "wrapper-cache-lifecycle",
            "cancellation",
            "loopback",
            "large-page-live",
            "benchmark",
            "rollback",
        ],
        "registry:stream-wrapper-meek",
    ),
    blocked_row(
        "stream-wrapper-xhttp",
        "multi-protocol",
        &["vless"],
        "standard-or-fingerprint-aware-tls",
        "xhttp",
        "udp-over-stream-or-datagram",
        "missing-stream-wrapper",
        &[
            "wrapper-cache-lifecycle",
            "cancellation",
            "loopback",
            "large-page-live",
            "benchmark",
            "rollback",
        ],
        "registry:stream-wrapper-xhttp",
    ),
    blocked_row(
        "nested-chain-shape",
        "multi-protocol",
        &["chain"],
        "composed",
        "composed",
        "composed",
        "missing-chain-executor",
        &[
            "nested-graph-executor",
            "no-endpoint-flattening",
            "large-page-live",
            "benchmark",
            "rollback",
        ],
        "registry:nested-chain-shape",
    ),
    blocked_row(
        "plugin-wrapper-layer",
        "multi-protocol",
        &["ss", "shadowsocks"],
        "aead",
        "plugin-wrapper",
        "udp-over-stream-or-datagram",
        "missing-stream-wrapper",
        &[
            "plugin-process-lifecycle",
            "cache-cleanup",
            "large-page-live",
            "benchmark",
            "rollback",
        ],
        "registry:plugin-wrapper-layer",
    ),
    blocked_row(
        "legacy-layer-shape",
        "multi-protocol",
        &["ss", "shadowsocks", "vmess"],
        "legacy-security",
        "legacy-obfs",
        "udp-over-stream-or-datagram",
        "missing-security-underlay",
        &[
            "encryption-auth-tests",
            "tcp-udp-live",
            "benchmark",
            "rollback",
        ],
        "registry:legacy-layer-shape",
    ),
    blocked_row(
        "quic-option-surface",
        "quic-family",
        &["hysteria2", "hy2", "tuic", "juicity"],
        "quic-tls",
        "quic-stream",
        "quic-datagram-or-stream",
        "missing-benchmark-evidence",
        &[
            "handshake",
            "packet-relay",
            "congestion-option",
            "cleanup",
            "benchmark",
            "large-page-live",
            "rollback",
        ],
        "registry:quic-option-surface",
    ),
    blocked_row(
        "secure-endpoint-capability",
        "proxy-endpoint",
        &["https"],
        "standard-tls",
        "none",
        "protocol-closed",
        "missing-security-underlay",
        &[
            "generic-underlay-admission",
            "large-page-connect-live",
            "rollback",
        ],
        "registry:secure-endpoint-capability",
    ),
    not_supported_row(
        "foreign-abi-outbound-shape",
        "foreign-runtime",
        &["ffi", "c-abi"],
        "external",
        "external",
        "external",
        "unsupported-source-policy",
        "registry:foreign-abi-outbound-shape",
    ),
    not_supported_row(
        "external-oracle-dependent-shape",
        "foreign-runtime",
        &["go-oracle"],
        "external",
        "external",
        "external",
        "unsupported-source-policy",
        "registry:external-oracle-dependent-shape",
    ),
    not_supported_row(
        "internal-fallback-dependent-shape",
        "fallback-runtime",
        &["rust-fallback"],
        "internal-fallback",
        "internal-fallback",
        "internal-fallback",
        "unsupported-source-policy",
        "registry:internal-fallback-dependent-shape",
    ),
];

const fn admitted_row(
    shape_id: &'static str,
    protocol_family: &'static str,
    link_schemes: &'static [&'static str],
    security_underlay: &'static str,
    stream_wrapper: &'static str,
    packet_semantics: &'static str,
    redacted_identity: &'static str,
) -> SourceShapeRegistryRow {
    SourceShapeRegistryRow {
        shape_id,
        source_support: "source-supported",
        protocol_family,
        link_schemes,
        endpoint: "host-port",
        security_underlay,
        stream_wrapper,
        packet_semantics,
        chain_shape: "single-graph",
        policy_surface: "selected-runtime-plus-expanded-ledger",
        reload_lifecycle: "drop-on-graph-diff-or-runtime-stop",
        parser_coverage: "covered",
        resident_status: "admitted-baseline",
        blocker_id: None,
        evidence_requirements: &["large-page-live", "benchmark", "rollback"],
        redacted_identity,
        state_ledger: ADMITTED_STATE,
        executor_proof: ADMITTED_EXECUTOR_PROOF,
        runtime_selection: ADMITTED_RUNTIME_SELECTION,
        capability: BASE_CAPABILITY,
        expanded_live_matrix: PENDING_LIVE_LEDGER,
        release_gate: BASE_RELEASE_GATE,
    }
}

const fn blocked_row(
    shape_id: &'static str,
    protocol_family: &'static str,
    link_schemes: &'static [&'static str],
    security_underlay: &'static str,
    stream_wrapper: &'static str,
    packet_semantics: &'static str,
    blocker_id: &'static str,
    evidence_requirements: &'static [&'static str],
    redacted_identity: &'static str,
) -> SourceShapeRegistryRow {
    SourceShapeRegistryRow {
        shape_id,
        source_support: "source-supported",
        protocol_family,
        link_schemes,
        endpoint: "host-port",
        security_underlay,
        stream_wrapper,
        packet_semantics,
        chain_shape: "single-or-composed-graph",
        policy_surface: "expanded-ledger-only-until-executor-proof",
        reload_lifecycle: "requires-proof",
        parser_coverage: "covered-or-source-declared",
        resident_status: "blocked",
        blocker_id: Some(blocker_id),
        evidence_requirements,
        redacted_identity,
        state_ledger: BLOCKED_STATE,
        executor_proof: BLOCKED_EXECUTOR_PROOF,
        runtime_selection: BLOCKED_RUNTIME_SELECTION,
        capability: BLOCKED_CAPABILITY,
        expanded_live_matrix: BLOCKED_LIVE_LEDGER,
        release_gate: BLOCKED_RELEASE_GATE,
    }
}

const fn not_supported_row(
    shape_id: &'static str,
    protocol_family: &'static str,
    link_schemes: &'static [&'static str],
    security_underlay: &'static str,
    stream_wrapper: &'static str,
    packet_semantics: &'static str,
    blocker_id: &'static str,
    redacted_identity: &'static str,
) -> SourceShapeRegistryRow {
    SourceShapeRegistryRow {
        shape_id,
        source_support: "not-source-supported",
        protocol_family,
        link_schemes,
        endpoint: "external",
        security_underlay,
        stream_wrapper,
        packet_semantics,
        chain_shape: "external",
        policy_surface: "rejected",
        reload_lifecycle: "rejected",
        parser_coverage: "rejected",
        resident_status: "not-source-supported",
        blocker_id: Some(blocker_id),
        evidence_requirements: &[],
        redacted_identity,
        state_ledger: NOT_SOURCE_SUPPORTED_STATE,
        executor_proof: BLOCKED_EXECUTOR_PROOF,
        runtime_selection: BLOCKED_RUNTIME_SELECTION,
        capability: NOT_SUPPORTED_CAPABILITY,
        expanded_live_matrix: REJECTED_LIVE_LEDGER,
        release_gate: REJECTED_RELEASE_GATE,
    }
}
