use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceShapeRegistryContract {
    pub schema: &'static str,
    pub schema_version: u64,
    pub rows: &'static [SourceShapeRegistryRow],
    pub source_shape_registry_open: bool,
    pub expanded_source_matrix_open: bool,
    pub expanded_source_matrix_complete: bool,
    pub scoped_expanded_source_matrix_evidence: ScopedExpandedSourceMatrixEvidence,
    pub release_gate_may_use_current_config_matrix_as_source_matrix: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfficialCommonSourceShapeRequirement {
    pub fixture: &'static str,
    pub marker: &'static str,
    pub shape_id: &'static str,
}

impl SourceShapeRegistryContract {
    pub fn to_value(self) -> Value {
        json!({
            "schema": self.schema,
            "schemaVersion": self.schema_version,
            "sourceShapeRegistryOpen": self.source_shape_registry_open,
            "expandedSourceMatrixOpen": self.expanded_source_matrix_open,
            "expandedSourceMatrixComplete": self.expanded_source_matrix_complete,
            "scopedExpandedSourceMatrixEvidence": self.scoped_expanded_source_matrix_evidence.to_value(),
            "releaseGateMayUseCurrentConfigMatrixAsSourceMatrix": self.release_gate_may_use_current_config_matrix_as_source_matrix,
            "rowCount": self.rows.len(),
            "rows": self.rows.iter().map(|row| row.to_value()).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopedExpandedSourceMatrixEvidence {
    pub schema: &'static str,
    pub schema_version: u64,
    pub scope_id: &'static str,
    pub source_scope: &'static str,
    pub excluded_stream_wrappers: &'static [&'static str],
    pub opened_rows: &'static [&'static str],
    pub source_formats: &'static [&'static str],
    pub candidate_sha256: &'static str,
    pub evidence_host: &'static str,
    pub upstream_host: &'static str,
    pub evidence_root: &'static str,
    pub summary_artifact: &'static str,
    pub rollback_artifact: &'static str,
    pub row_count: u64,
    pub pass_count: u64,
    pub all_pass: bool,
    pub large_page_all_pass: bool,
    pub proxy_evidence_all_pass: bool,
    pub benchmark_evidence_ready: bool,
    pub benchmark_evidence_kind: &'static str,
    pub rollback_artifact_ready: bool,
    pub rollback_artifact_executed: bool,
    pub cleanup_evidence_ready: bool,
    pub raw_links_retained: bool,
    pub raw_bodies_retained: bool,
    pub raw_state_retained: bool,
    pub release_gate_ready: bool,
}

impl ScopedExpandedSourceMatrixEvidence {
    pub fn to_value(self) -> Value {
        json!({
            "schema": self.schema,
            "schemaVersion": self.schema_version,
            "scopeId": self.scope_id,
            "sourceScope": self.source_scope,
            "excludedStreamWrappers": self.excluded_stream_wrappers,
            "openedRows": self.opened_rows,
            "sourceFormats": self.source_formats,
            "candidateSha256": self.candidate_sha256,
            "evidenceHost": self.evidence_host,
            "upstreamHost": self.upstream_host,
            "evidenceRoot": self.evidence_root,
            "summaryArtifact": self.summary_artifact,
            "rollbackArtifact": self.rollback_artifact,
            "rowCount": self.row_count,
            "passCount": self.pass_count,
            "allPass": self.all_pass,
            "largePageAllPass": self.large_page_all_pass,
            "proxyEvidenceAllPass": self.proxy_evidence_all_pass,
            "benchmarkEvidenceReady": self.benchmark_evidence_ready,
            "benchmarkEvidenceKind": self.benchmark_evidence_kind,
            "rollbackArtifactReady": self.rollback_artifact_ready,
            "rollbackArtifactExecuted": self.rollback_artifact_executed,
            "cleanupEvidenceReady": self.cleanup_evidence_ready,
            "rawLinksRetained": self.raw_links_retained,
            "rawBodiesRetained": self.raw_bodies_retained,
            "rawStateRetained": self.raw_state_retained,
            "releaseGateReady": self.release_gate_ready,
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
        scoped_expanded_source_matrix_evidence: SCOPED_EXPANDED_SOURCE_MATRIX_EVIDENCE,
        release_gate_may_use_current_config_matrix_as_source_matrix: false,
    }
}

pub fn source_shape_registry_rows() -> &'static [SourceShapeRegistryRow] {
    SOURCE_SHAPE_REGISTRY_ROWS
}

pub fn official_common_source_shape_ids() -> &'static [&'static str] {
    OFFICIAL_COMMON_SOURCE_SHAPE_IDS
}

pub fn official_common_fixture_requirements() -> &'static [OfficialCommonSourceShapeRequirement] {
    OFFICIAL_COMMON_FIXTURE_REQUIREMENTS
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

const SCOPED_EXPANDED_SOURCE_MATRIX_EVIDENCE: ScopedExpandedSourceMatrixEvidence =
    ScopedExpandedSourceMatrixEvidence {
        schema: "scoped-expanded-source-evidence",
        schema_version: 1,
        scope_id: "excluded-stream-wrapper-scope",
        source_scope: "remaining-expanded-source-closure-rows",
        excluded_stream_wrappers: &["xhttp"],
        opened_rows: &[
            "secure-endpoint-capability",
            "nested-chain-shape",
            "plugin-wrapper-layer",
            "legacy-layer-shape",
            "stream-wrapper-meek",
            "secure-websocket-framed-endpoint",
            "secure-httpupgrade-framed-endpoint",
            "verified-quic-security-underlay",
            "quic-port-hopping-surface",
            "inner-encryption-stream-wrapper",
            "obfs-tls-plugin-wrapper",
            "tls-websocket-plugin-wrapper",
            "aead-2022-plugin-wrapper",
            "proxy-transport-mode",
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
        ],
        candidate_sha256: "multi-batch:3ea6efd5022e5079de4ffc654482dbeae6194a052ff0e6b7cce7c3f513b384a5+12a1622fdff29d95e954ba80a865c01fbb17dcacb345eb7468dae0ac818bab0b+3e33e9d1d620ce21d9f76976855297d7a42d9c82a26ab4adba78370ff9b83817",
        evidence_host: "remote-38",
        upstream_host: "jp",
        evidence_root: "remote-38:/tmp/daex-non-xhttp-capability-3ea6efd5;/opt/daex-batch1-38/artifacts;/opt/daex-batch2-38/artifacts",
        summary_artifact: "remote-38:/tmp/daex-non-xhttp-capability-3ea6efd5/non-xhttp-capability-live-summary.json;/opt/daex-batch1-38/artifacts/batch1-live-evidence.json;/opt/daex-batch2-38/artifacts/batch2-live-evidence.json",
        rollback_artifact: "remote-38:/tmp/daex-non-xhttp-capability-3ea6efd5/rollback-cleanup.sh;/opt/daex-batch1-38/artifacts/rollback-cleanup.sh;/opt/daex-batch2-38/artifacts/rollback-cleanup.sh",
        row_count: 14,
        pass_count: 14,
        all_pass: true,
        large_page_all_pass: true,
        proxy_evidence_all_pass: true,
        benchmark_evidence_ready: true,
        benchmark_evidence_kind: "large-page-threshold-and-body-hash",
        rollback_artifact_ready: true,
        rollback_artifact_executed: true,
        cleanup_evidence_ready: true,
        raw_links_retained: false,
        raw_bodies_retained: false,
        raw_state_retained: false,
        release_gate_ready: true,
    };

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
    parser: "covered",
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

const CHAIN_EXECUTOR_PROOF: ComponentExecutorProof = ComponentExecutorProof {
    underlay_factory: "proved",
    stream_wrapper_factory: "proved",
    packet_semantics_factory: "proved",
    chain_executor: "parent-connect-proved",
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

const PLUGIN_WRAPPER_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "baseline-admitted",
    stream_wrapper: "resident-simple-obfs-http",
    packet_semantics: "tcp-stream-wrapper",
    plugin_wrapper: "resident-simple-obfs-http",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

const INNER_ENCRYPTION_STREAM_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "baseline-admitted",
    stream_wrapper: "websocket",
    packet_semantics: "inner-encryption-stream",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

const PLUGIN_WRAPPER_STREAM_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "aead-or-aead-2022",
    stream_wrapper: "resident-plugin-wrapper",
    packet_semantics: "tcp-stream-wrapper",
    plugin_wrapper: "resident-plugin-wrapper",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

const PROXY_TRANSPORT_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "plain-or-standard-tls",
    stream_wrapper: "http-proxy-transport",
    packet_semantics: "tcp-stream",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

const SECURE_FRAME_STREAM_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "standard-tls",
    stream_wrapper: "secure-frame-stream",
    packet_semantics: "udp-over-stream-or-datagram",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "standard-tls-underlay",
};

const VERIFIED_QUIC_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "verified-quic-tls",
    stream_wrapper: "quic-stream",
    packet_semantics: "quic-datagram-or-stream",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "verified-quic-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

const QUIC_PORT_HOPPING_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "quic-tls",
    stream_wrapper: "quic-port-hopping",
    packet_semantics: "quic-datagram-or-stream",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "port-hopping-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

const CHAIN_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "parent-connect-chain-admitted",
    security_underlay: "baseline-admitted",
    stream_wrapper: "baseline-admitted",
    packet_semantics: "tcp-resident-chain",
    plugin_wrapper: "none",
    legacy_layer: "none",
    quic_option: "baseline-admitted",
    secure_endpoint: "plain-or-native-underlay",
};

const LEGACY_IMPORT_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-admitted",
    security_underlay: "baseline-admitted",
    stream_wrapper: "baseline-admitted",
    packet_semantics: "baseline-admitted",
    plugin_wrapper: "none",
    legacy_layer: "legacy-import-normalizer",
    quic_option: "baseline-admitted",
    secure_endpoint: "plain-or-native-underlay",
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

const DEFERRED_CAPABILITY: CapabilityLedger = CapabilityLedger {
    graph_composition: "single-graph-blocked",
    security_underlay: "pending-or-policy-blocked",
    stream_wrapper: "pending-or-policy-blocked",
    packet_semantics: "pending-or-policy-blocked",
    plugin_wrapper: "pending-or-policy-blocked",
    legacy_layer: "pending-or-policy-blocked",
    quic_option: "pending-or-policy-blocked",
    secure_endpoint: "pending-or-policy-blocked",
};

const PENDING_LIVE_LEDGER: ExpandedLiveMatrixLedger = ExpandedLiveMatrixLedger {
    ledger_state: "pending-live-host-evidence",
    live_host_required: true,
    rollback_artifact_required: true,
    large_page_evidence_required: true,
    blocked_rows_reduce_pass_threshold: false,
};

const SCOPED_READY_LIVE_LEDGER: ExpandedLiveMatrixLedger = ExpandedLiveMatrixLedger {
    ledger_state: "scoped-live-host-evidence-ready",
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

const BLOCKED_LIVE_LEDGER: ExpandedLiveMatrixLedger = ExpandedLiveMatrixLedger {
    ledger_state: "explicit-fail-closed",
    live_host_required: true,
    rollback_artifact_required: true,
    large_page_evidence_required: true,
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

const SCOPED_READY_RELEASE_GATE: ReleaseGateReconciliation = ReleaseGateReconciliation {
    current_baseline_agrees: true,
    expanded_source_agrees: true,
    service_contract_agrees: true,
    product_chain_agrees: false,
    c9_switch_ready: false,
    c10_final_ready: false,
    rollback_artifact_ready: true,
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

static SOURCE_SHAPE_REGISTRY_ROWS: &[SourceShapeRegistryRow] = &[
    admitted_row(
        "baseline-aead-cipher-endpoint",
        "shadowsocks",
        &["ss"],
        "aead",
        "none",
        "datagram-aead",
        "registry:baseline-aead-cipher-endpoint",
    ),
    admitted_row(
        "baseline-aead-2022-cipher-endpoint",
        "shadowsocks",
        &["ss"],
        "aead-2022",
        "none",
        "datagram-aead-2022",
        "registry:baseline-aead-2022-cipher-endpoint",
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
    admitted_row(
        "stream-wrapper-websocket",
        "multi-protocol",
        &["vless", "trojan", "trojan-go"],
        "standard-or-fingerprint-aware-tls",
        "websocket",
        "udp-over-stream-or-datagram",
        "registry:stream-wrapper-websocket",
    ),
    admitted_row(
        "plain-websocket-framed-endpoint",
        "vmess",
        &["vmess"],
        "aead",
        "websocket",
        "udp-over-stream-or-datagram",
        "registry:plain-websocket-framed-endpoint",
    ),
    admitted_row(
        "stream-wrapper-grpc",
        "multi-protocol",
        &["vless", "vmess", "trojan", "trojan-go"],
        "standard-or-fingerprint-aware-tls",
        "grpc",
        "udp-over-stream-or-datagram",
        "registry:stream-wrapper-grpc",
    ),
    admitted_row(
        "stream-wrapper-httpupgrade",
        "multi-protocol",
        &["vless", "trojan-go"],
        "standard-or-fingerprint-aware-tls",
        "httpupgrade",
        "udp-over-stream-or-datagram",
        "registry:stream-wrapper-httpupgrade",
    ),
    admitted_row(
        "plain-httpupgrade-framed-endpoint",
        "vmess",
        &["vmess"],
        "aead",
        "httpupgrade",
        "udp-over-stream-or-datagram",
        "registry:plain-httpupgrade-framed-endpoint",
    ),
    scoped_evidence_admitted_row(
        "stream-wrapper-meek",
        "multi-protocol",
        &["vless"],
        "standard-or-fingerprint-aware-tls",
        "meek",
        "udp-over-stream-or-datagram",
        "registry:stream-wrapper-meek",
    ),
    admitted_row(
        "stream-wrapper-xhttp",
        "multi-protocol",
        &["vless"],
        "standard-or-fingerprint-aware-tls",
        "xhttp",
        "tcp-stream-h2-packet-up",
        "registry:stream-wrapper-xhttp",
    ),
    scoped_evidence_chain_admitted_row(
        "nested-chain-shape",
        "multi-protocol",
        &["chain"],
        "plain-parent-connect",
        "baseline-or-plugin-wrapper",
        "tcp-resident-chain",
        "registry:nested-chain-shape",
    ),
    scoped_evidence_plugin_wrapper_admitted_row(
        "plugin-wrapper-layer",
        "shadowsocks",
        &["ss"],
        "aead",
        "simple-obfs-http",
        "tcp-stream-wrapper",
        "registry:plugin-wrapper-layer",
    ),
    scoped_evidence_legacy_import_admitted_row(
        "legacy-layer-shape",
        "vmess",
        &["vmess"],
        "aead",
        "baseline-admitted",
        "udp-over-stream-or-datagram",
        "registry:legacy-layer-shape",
    ),
    admitted_row(
        "quic-option-surface",
        "quic-family",
        &["hysteria2", "hy2", "tuic", "juicity"],
        "quic-tls",
        "quic-stream",
        "quic-datagram-or-stream",
        "registry:quic-option-surface",
    ),
    scoped_evidence_admitted_row(
        "secure-endpoint-capability",
        "proxy-endpoint",
        &["https"],
        "standard-tls",
        "none",
        "protocol-closed",
        "registry:secure-endpoint-capability",
    ),
    scoped_evidence_capability_admitted_row(
        "secure-websocket-framed-endpoint",
        "vmess",
        &["vmess"],
        "standard-tls",
        "websocket",
        "udp-over-stream-or-datagram",
        "registry:secure-websocket-framed-endpoint",
        SECURE_FRAME_STREAM_CAPABILITY,
    ),
    scoped_evidence_capability_admitted_row(
        "secure-httpupgrade-framed-endpoint",
        "vmess",
        &["vmess"],
        "standard-tls",
        "httpupgrade",
        "udp-over-stream-or-datagram",
        "registry:secure-httpupgrade-framed-endpoint",
        SECURE_FRAME_STREAM_CAPABILITY,
    ),
    blocked_row(
        "reality-security-underlay",
        "vless",
        &["vless"],
        "reality",
        "none-or-stream-wrapper",
        "xudp",
        "missing-security-underlay",
        "registry:reality-security-underlay",
    ),
    scoped_evidence_capability_admitted_row(
        "quic-port-hopping-surface",
        "hysteria2",
        &["hysteria2", "hy2"],
        "quic-tls",
        "quic-port-hopping",
        "quic-datagram-or-stream",
        "registry:quic-port-hopping-surface",
        QUIC_PORT_HOPPING_CAPABILITY,
    ),
    scoped_evidence_capability_admitted_row(
        "verified-quic-security-underlay",
        "tuic",
        &["tuic"],
        "verified-quic-tls",
        "quic-stream",
        "quic-datagram-or-stream",
        "registry:verified-quic-security-underlay",
        VERIFIED_QUIC_CAPABILITY,
    ),
    scoped_evidence_capability_admitted_row(
        "inner-encryption-stream-wrapper",
        "trojan-go",
        &["trojan-go"],
        "standard-tls",
        "websocket-or-httpupgrade-or-grpc",
        "udp-over-stream-or-datagram",
        "registry:inner-encryption-stream-wrapper",
        INNER_ENCRYPTION_STREAM_CAPABILITY,
    ),
    scoped_evidence_capability_admitted_row(
        "tls-websocket-plugin-wrapper",
        "shadowsocks",
        &["ss"],
        "aead",
        "tls-websocket-plugin",
        "tcp-stream-wrapper",
        "registry:tls-websocket-plugin-wrapper",
        PLUGIN_WRAPPER_STREAM_CAPABILITY,
    ),
    scoped_evidence_capability_admitted_row(
        "obfs-tls-plugin-wrapper",
        "shadowsocks",
        &["ss"],
        "aead",
        "obfs-tls",
        "tcp-stream-wrapper",
        "registry:obfs-tls-plugin-wrapper",
        PLUGIN_WRAPPER_STREAM_CAPABILITY,
    ),
    scoped_evidence_capability_admitted_row(
        "aead-2022-plugin-wrapper",
        "shadowsocks",
        &["ss"],
        "aead-2022",
        "plugin-wrapper",
        "tcp-stream-wrapper",
        "registry:aead-2022-plugin-wrapper",
        PLUGIN_WRAPPER_STREAM_CAPABILITY,
    ),
    scoped_evidence_capability_admitted_row(
        "proxy-transport-mode",
        "http-proxy",
        &["http", "https"],
        "plain-or-standard-tls",
        "http-transport",
        "protocol-closed",
        "registry:proxy-transport-mode",
        PROXY_TRANSPORT_CAPABILITY,
    ),
    blocked_row(
        "insecure-secure-endpoint-underlay",
        "proxy-endpoint",
        &["https"],
        "insecure-tls",
        "none",
        "protocol-closed",
        "missing-security-underlay",
        "registry:insecure-secure-endpoint-underlay",
    ),
    blocked_row(
        "fingerprint-secure-endpoint-underlay",
        "proxy-endpoint",
        &["https"],
        "fingerprint-aware-tls",
        "none",
        "protocol-closed",
        "missing-security-underlay",
        "registry:fingerprint-secure-endpoint-underlay",
    ),
    blocked_row(
        "insecure-frame-stream-underlay",
        "anytls",
        &["anytls"],
        "insecure-tls",
        "frame-stream",
        "udp-over-stream-or-datagram",
        "missing-security-underlay",
        "registry:insecure-frame-stream-underlay",
    ),
    blocked_row(
        "full-utls-security-underlay",
        "shared-transport",
        &["utls"],
        "full-utls",
        "none-or-stream-wrapper",
        "udp-over-stream-or-datagram",
        "missing-security-underlay",
        "registry:full-utls-security-underlay",
    ),
    blocked_row(
        "tls-fragment-security-underlay",
        "shared-transport",
        &["tls"],
        "tls-fragment",
        "none-or-stream-wrapper",
        "udp-over-stream-or-datagram",
        "missing-security-underlay",
        "registry:tls-fragment-security-underlay",
    ),
    blocked_row(
        "shared-reality-security-underlay",
        "shared-transport",
        &["reality"],
        "reality",
        "none-or-stream-wrapper",
        "udp-over-stream-or-datagram",
        "missing-security-underlay",
        "registry:shared-reality-security-underlay",
    ),
    blocked_row(
        "mux-transport-wrapper",
        "shared-transport",
        &["mux"],
        "plain-or-standard-tls",
        "mux",
        "multiplexed-stream",
        "missing-stream-wrapper",
        "registry:mux-transport-wrapper",
    ),
    blocked_row(
        "passthrough-udp-transport",
        "shared-transport",
        &["passthrough-udp"],
        "plain-or-standard-tls",
        "none-or-stream-wrapper",
        "passthrough-udp",
        "missing-packet-semantics",
        "registry:passthrough-udp-transport",
    ),
    blocked_row(
        "legacy-cipher-protocol-shape",
        "legacy-protocol",
        &["ssr"],
        "legacy-cipher",
        "legacy-obfs",
        "udp-over-stream-or-datagram",
        "materialization-mismatch",
        "registry:legacy-cipher-protocol-shape",
    ),
    blocked_row(
        "xhttp-h3-wrapper",
        "multi-protocol",
        &["vless"],
        "standard-or-fingerprint-aware-tls",
        "xhttp",
        "tcp-stream-h3-packet-up",
        "missing-stream-wrapper",
        "registry:xhttp-h3-wrapper",
    ),
    blocked_row(
        "xhttp-extended-settings-wrapper",
        "multi-protocol",
        &["vless"],
        "standard-or-fingerprint-aware-tls-or-reality",
        "xhttp",
        "extended-xhttp",
        "missing-stream-wrapper",
        "registry:xhttp-extended-settings-wrapper",
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

static OFFICIAL_COMMON_SOURCE_SHAPE_IDS: &[&str] = &[
    "baseline-aead-cipher-endpoint",
    "baseline-aead-2022-cipher-endpoint",
    "baseline-tls-auth-endpoint",
    "baseline-aead-framed-endpoint",
    "baseline-tls-vision-endpoint",
    "baseline-quic-auth-endpoint",
    "baseline-quic-uuid-endpoint",
    "baseline-quic-password-endpoint",
    "baseline-frame-stream-endpoint",
    "baseline-connect-endpoint",
    "baseline-socks-endpoint",
    "stream-wrapper-websocket",
    "plain-websocket-framed-endpoint",
    "stream-wrapper-grpc",
    "stream-wrapper-httpupgrade",
    "plain-httpupgrade-framed-endpoint",
    "stream-wrapper-meek",
    "stream-wrapper-xhttp",
    "nested-chain-shape",
    "plugin-wrapper-layer",
    "legacy-layer-shape",
    "quic-option-surface",
    "secure-endpoint-capability",
    "secure-websocket-framed-endpoint",
    "secure-httpupgrade-framed-endpoint",
    "reality-security-underlay",
    "quic-port-hopping-surface",
    "verified-quic-security-underlay",
    "inner-encryption-stream-wrapper",
    "tls-websocket-plugin-wrapper",
    "obfs-tls-plugin-wrapper",
    "aead-2022-plugin-wrapper",
    "proxy-transport-mode",
    "insecure-secure-endpoint-underlay",
    "fingerprint-secure-endpoint-underlay",
    "insecure-frame-stream-underlay",
    "full-utls-security-underlay",
    "tls-fragment-security-underlay",
    "shared-reality-security-underlay",
    "mux-transport-wrapper",
    "passthrough-udp-transport",
    "legacy-cipher-protocol-shape",
    "xhttp-h3-wrapper",
    "xhttp-extended-settings-wrapper",
];

static OFFICIAL_COMMON_FIXTURE_REQUIREMENTS: &[OfficialCommonSourceShapeRequirement] = &[
    OfficialCommonSourceShapeRequirement {
        fixture: "shadowsocks_native_optin.json",
        marker: "sip002-aead-base64-userinfo",
        shape_id: "baseline-aead-cipher-endpoint",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "shadowsocks_native_optin.json",
        marker: "ss2022-plain-userinfo",
        shape_id: "baseline-aead-2022-cipher-endpoint",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "trojan_native_optin.json",
        marker: "trojan-default-sni",
        shape_id: "baseline-tls-auth-endpoint",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "vmess_native_optin.json",
        marker: "domain-tcp",
        shape_id: "baseline-aead-framed-endpoint",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "vless_native_optin.json",
        marker: "tcp-tls-vision",
        shape_id: "baseline-tls-vision-endpoint",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "hysteria2_native_optin.json",
        marker: "basic",
        shape_id: "baseline-quic-auth-endpoint",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "tuic_native_optin.json",
        marker: "basic-quic-flag",
        shape_id: "baseline-quic-uuid-endpoint",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "juicity_native_optin.json",
        marker: "basic-urlbase64-pin",
        shape_id: "baseline-quic-password-endpoint",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "anytls_native_optin.json",
        marker: "default-sni",
        shape_id: "baseline-frame-stream-endpoint",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "http_native_optin.json",
        marker: "connect-no-auth",
        shape_id: "baseline-connect-endpoint",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "socks5_native_optin.json",
        marker: "socks5",
        shape_id: "baseline-socks-endpoint",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "vmess_native_optin.json",
        marker: "json-aead-ws-tls",
        shape_id: "secure-websocket-framed-endpoint",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "vmess_native_optin.json",
        marker: "legacy-websocket-tls",
        shape_id: "secure-websocket-framed-endpoint",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "vless_native_optin.json",
        marker: "xhttp-reality-contract",
        shape_id: "reality-security-underlay",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "hysteria2_native_optin.json",
        marker: "port-hopping",
        shape_id: "quic-port-hopping-surface",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "tuic_native_optin.json",
        marker: "basic-quic-flag",
        shape_id: "verified-quic-security-underlay",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "trojan_native_optin.json",
        marker: "trojan-go-ss-encryption",
        shape_id: "inner-encryption-stream-wrapper",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "shadowsocks_native_optin.json",
        marker: "simple-obfs-plugin",
        shape_id: "plugin-wrapper-layer",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "shadowsocks_native_optin.json",
        marker: "simple-obfs-tls-plugin",
        shape_id: "obfs-tls-plugin-wrapper",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "shadowsocks_native_optin.json",
        marker: "v2ray-plugin-tls",
        shape_id: "tls-websocket-plugin-wrapper",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "shadowsocks_native_optin.json",
        marker: "ss2022-simple-obfs-http-plugin",
        shape_id: "aead-2022-plugin-wrapper",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "shadowsocks_native_optin.json",
        marker: "shadowsocksr",
        shape_id: "legacy-cipher-protocol-shape",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "http_native_optin.json",
        marker: "transport-put-path",
        shape_id: "proxy-transport-mode",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "http_native_optin.json",
        marker: "https-flags",
        shape_id: "insecure-secure-endpoint-underlay",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "anytls_native_optin.json",
        marker: "basic-insecure",
        shape_id: "insecure-frame-stream-underlay",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "shared_transport_native_optin.json",
        marker: "utls",
        shape_id: "full-utls-security-underlay",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "shared_transport_native_optin.json",
        marker: "global_tls_fragment",
        shape_id: "tls-fragment-security-underlay",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "shared_transport_native_optin.json",
        marker: "reality_transport",
        shape_id: "shared-reality-security-underlay",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "shared_transport_native_optin.json",
        marker: "mux_transport",
        shape_id: "mux-transport-wrapper",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "shared_transport_native_optin.json",
        marker: "passthroughUdp",
        shape_id: "passthrough-udp-transport",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "vless_native_optin.json",
        marker: "xhttp-h3-packet-up",
        shape_id: "xhttp-h3-wrapper",
    },
    OfficialCommonSourceShapeRequirement {
        fixture: "shared_transport_native_optin.json",
        marker: "downloadSettings",
        shape_id: "xhttp-extended-settings-wrapper",
    },
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
        resident_status: "blocked",
        blocker_id: Some(blocker_id),
        evidence_requirements: &["executor", "large-page-live", "benchmark", "rollback"],
        redacted_identity,
        state_ledger: BLOCKED_STATE,
        executor_proof: BLOCKED_EXECUTOR_PROOF,
        runtime_selection: BLOCKED_RUNTIME_SELECTION,
        capability: DEFERRED_CAPABILITY,
        expanded_live_matrix: BLOCKED_LIVE_LEDGER,
        release_gate: REJECTED_RELEASE_GATE,
    }
}

const fn scoped_evidence_admitted_row(
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
        expanded_live_matrix: SCOPED_READY_LIVE_LEDGER,
        release_gate: SCOPED_READY_RELEASE_GATE,
    }
}

const fn scoped_evidence_capability_admitted_row(
    shape_id: &'static str,
    protocol_family: &'static str,
    link_schemes: &'static [&'static str],
    security_underlay: &'static str,
    stream_wrapper: &'static str,
    packet_semantics: &'static str,
    redacted_identity: &'static str,
    capability: CapabilityLedger,
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
        capability,
        expanded_live_matrix: SCOPED_READY_LIVE_LEDGER,
        release_gate: SCOPED_READY_RELEASE_GATE,
    }
}

const fn scoped_evidence_plugin_wrapper_admitted_row(
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
        capability: PLUGIN_WRAPPER_CAPABILITY,
        expanded_live_matrix: SCOPED_READY_LIVE_LEDGER,
        release_gate: SCOPED_READY_RELEASE_GATE,
    }
}

const fn scoped_evidence_chain_admitted_row(
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
        chain_shape: "parent-connect-chain",
        policy_surface: "selected-runtime-plus-expanded-ledger",
        reload_lifecycle: "drop-on-graph-diff-or-runtime-stop",
        parser_coverage: "covered",
        resident_status: "admitted-baseline",
        blocker_id: None,
        evidence_requirements: &["large-page-live", "benchmark", "rollback"],
        redacted_identity,
        state_ledger: ADMITTED_STATE,
        executor_proof: CHAIN_EXECUTOR_PROOF,
        runtime_selection: ADMITTED_RUNTIME_SELECTION,
        capability: CHAIN_CAPABILITY,
        expanded_live_matrix: SCOPED_READY_LIVE_LEDGER,
        release_gate: SCOPED_READY_RELEASE_GATE,
    }
}

const fn scoped_evidence_legacy_import_admitted_row(
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
        capability: LEGACY_IMPORT_CAPABILITY,
        expanded_live_matrix: SCOPED_READY_LIVE_LEDGER,
        release_gate: SCOPED_READY_RELEASE_GATE,
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
