use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketSemanticsCapabilityContract {
    pub schema: &'static str,
    pub schema_version: u64,
    pub rows: &'static [PacketSemanticsCapabilityRow],
    pub common_packet_semantics_ready: bool,
    pub resident_source_admission_ready: bool,
    pub expanded_packet_semantics_complete: bool,
}

impl PacketSemanticsCapabilityContract {
    pub fn to_value(self) -> Value {
        json!({
            "schema": self.schema,
            "schemaVersion": self.schema_version,
            "commonPacketSemanticsReady": self.common_packet_semantics_ready,
            "residentSourceAdmissionReady": self.resident_source_admission_ready,
            "expandedPacketSemanticsComplete": self.expanded_packet_semantics_complete,
            "rowCount": self.rows.len(),
            "rows": self.rows.iter().map(|row| row.to_value()).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketSemanticsCapabilityRow {
    pub semantics_id: &'static str,
    pub status: &'static str,
    pub provider: &'static str,
    pub packet_semantics: &'static str,
    pub graph_binding: &'static str,
    pub reload_cleanup: &'static str,
    pub no_direct_alternate_path: bool,
    pub blocker_id: Option<&'static str>,
    pub evidence_requirements: &'static [&'static str],
}

impl PacketSemanticsCapabilityRow {
    pub fn to_value(self) -> Value {
        json!({
            "semanticsId": self.semantics_id,
            "status": self.status,
            "provider": self.provider,
            "packetSemantics": self.packet_semantics,
            "graphBinding": self.graph_binding,
            "reloadCleanup": self.reload_cleanup,
            "noDirectAlternatePath": self.no_direct_alternate_path,
            "blockerId": self.blocker_id,
            "evidenceRequirements": self.evidence_requirements,
        })
    }
}

pub fn packet_semantics_capability_contract() -> PacketSemanticsCapabilityContract {
    PacketSemanticsCapabilityContract {
        schema: "packet-semantics-capability",
        schema_version: 1,
        rows: packet_semantics_capability_rows(),
        common_packet_semantics_ready: true,
        resident_source_admission_ready: true,
        expanded_packet_semantics_complete: true,
    }
}

pub fn packet_semantics_capability_rows() -> &'static [PacketSemanticsCapabilityRow] {
    &PACKET_SEMANTICS_CAPABILITY_ROWS
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtensionLayerCapabilityContract {
    pub schema: &'static str,
    pub schema_version: u64,
    pub rows: &'static [ExtensionLayerCapabilityRow],
    pub no_plugin_baseline_ready: bool,
    pub plugin_wrapper_resident_source_admission_ready: bool,
    pub legacy_layer_resident_source_admission_ready: bool,
    pub expanded_extension_layer_complete: bool,
}

impl ExtensionLayerCapabilityContract {
    pub fn to_value(self) -> Value {
        json!({
            "schema": self.schema,
            "schemaVersion": self.schema_version,
            "noPluginBaselineReady": self.no_plugin_baseline_ready,
            "pluginWrapperResidentSourceAdmissionReady": self.plugin_wrapper_resident_source_admission_ready,
            "legacyLayerResidentSourceAdmissionReady": self.legacy_layer_resident_source_admission_ready,
            "expandedExtensionLayerComplete": self.expanded_extension_layer_complete,
            "rowCount": self.rows.len(),
            "rows": self.rows.iter().map(|row| row.to_value()).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtensionLayerCapabilityRow {
    pub layer_id: &'static str,
    pub layer: &'static str,
    pub status: &'static str,
    pub provider: &'static str,
    pub admission_boundary: &'static str,
    pub reload_cleanup: &'static str,
    pub no_inherited_admission: bool,
    pub blocker_id: Option<&'static str>,
    pub evidence_requirements: &'static [&'static str],
}

impl ExtensionLayerCapabilityRow {
    pub fn to_value(self) -> Value {
        json!({
            "layerId": self.layer_id,
            "layer": self.layer,
            "status": self.status,
            "provider": self.provider,
            "admissionBoundary": self.admission_boundary,
            "reloadCleanup": self.reload_cleanup,
            "noInheritedAdmission": self.no_inherited_admission,
            "blockerId": self.blocker_id,
            "evidenceRequirements": self.evidence_requirements,
        })
    }
}

pub fn extension_layer_capability_contract() -> ExtensionLayerCapabilityContract {
    ExtensionLayerCapabilityContract {
        schema: "extension-layer-capability",
        schema_version: 1,
        rows: extension_layer_capability_rows(),
        no_plugin_baseline_ready: true,
        plugin_wrapper_resident_source_admission_ready: true,
        legacy_layer_resident_source_admission_ready: true,
        expanded_extension_layer_complete: true,
    }
}

pub fn extension_layer_capability_rows() -> &'static [ExtensionLayerCapabilityRow] {
    &EXTENSION_LAYER_CAPABILITY_ROWS
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportOptionCapabilityContract {
    pub schema: &'static str,
    pub schema_version: u64,
    pub rows: &'static [TransportOptionCapabilityRow],
    pub baseline_transport_options_ready: bool,
    pub quic_option_resident_source_admission_ready: bool,
    pub secure_endpoint_resident_source_admission_ready: bool,
    pub expanded_transport_option_complete: bool,
}

impl TransportOptionCapabilityContract {
    pub fn to_value(self) -> Value {
        json!({
            "schema": self.schema,
            "schemaVersion": self.schema_version,
            "baselineTransportOptionsReady": self.baseline_transport_options_ready,
            "quicOptionResidentSourceAdmissionReady": self.quic_option_resident_source_admission_ready,
            "secureEndpointResidentSourceAdmissionReady": self.secure_endpoint_resident_source_admission_ready,
            "expandedTransportOptionComplete": self.expanded_transport_option_complete,
            "rowCount": self.rows.len(),
            "rows": self.rows.iter().map(|row| row.to_value()).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportOptionCapabilityRow {
    pub option_id: &'static str,
    pub option_surface: &'static str,
    pub status: &'static str,
    pub provider: &'static str,
    pub security_underlay: &'static str,
    pub packet_semantics: &'static str,
    pub reload_cleanup: &'static str,
    pub blocker_id: Option<&'static str>,
    pub evidence_requirements: &'static [&'static str],
}

impl TransportOptionCapabilityRow {
    pub fn to_value(self) -> Value {
        json!({
            "optionId": self.option_id,
            "optionSurface": self.option_surface,
            "status": self.status,
            "provider": self.provider,
            "securityUnderlay": self.security_underlay,
            "packetSemantics": self.packet_semantics,
            "reloadCleanup": self.reload_cleanup,
            "blockerId": self.blocker_id,
            "evidenceRequirements": self.evidence_requirements,
        })
    }
}

pub fn transport_option_capability_contract() -> TransportOptionCapabilityContract {
    TransportOptionCapabilityContract {
        schema: "transport-option-capability",
        schema_version: 1,
        rows: transport_option_capability_rows(),
        baseline_transport_options_ready: true,
        quic_option_resident_source_admission_ready: true,
        secure_endpoint_resident_source_admission_ready: true,
        expanded_transport_option_complete: true,
    }
}

pub fn transport_option_capability_rows() -> &'static [TransportOptionCapabilityRow] {
    &TRANSPORT_OPTION_CAPABILITY_ROWS
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpandedLiveMatrixValidationBoundaryContract {
    pub schema: &'static str,
    pub schema_version: u64,
    pub validation_boundary: &'static str,
    pub upstream_boundary: &'static str,
    pub google_min_bytes: u64,
    pub youtube_min_bytes: u64,
    pub proxy_path_required: bool,
    pub direct_control_excluded: bool,
    pub benchmark_required: bool,
    pub cleanup_artifact_required: bool,
    pub blocked_rows_reduce_pass_threshold: bool,
    pub expanded_live_matrix_complete: bool,
}

impl ExpandedLiveMatrixValidationBoundaryContract {
    pub fn to_value(self) -> Value {
        json!({
            "schema": self.schema,
            "schemaVersion": self.schema_version,
            "validationBoundary": self.validation_boundary,
            "upstreamBoundary": self.upstream_boundary,
            "googleMinBytes": self.google_min_bytes,
            "youtubeMinBytes": self.youtube_min_bytes,
            "proxyPathRequired": self.proxy_path_required,
            "directControlExcluded": self.direct_control_excluded,
            "benchmarkRequired": self.benchmark_required,
            "cleanupArtifactRequired": self.cleanup_artifact_required,
            "blockedRowsReducePassThreshold": self.blocked_rows_reduce_pass_threshold,
            "expandedLiveMatrixComplete": self.expanded_live_matrix_complete,
        })
    }
}

pub fn expanded_live_matrix_validation_boundary_contract()
-> ExpandedLiveMatrixValidationBoundaryContract {
    ExpandedLiveMatrixValidationBoundaryContract {
        schema: "expanded-live-matrix-validation-boundary",
        schema_version: 1,
        validation_boundary: "external-client-through-resident-proxy",
        upstream_boundary: "external-proxy-server-path",
        google_min_bytes: 10_000,
        youtube_min_bytes: 100_000,
        proxy_path_required: true,
        direct_control_excluded: true,
        benchmark_required: true,
        cleanup_artifact_required: true,
        blocked_rows_reduce_pass_threshold: false,
        expanded_live_matrix_complete: false,
    }
}

const PACKET_SEMANTICS_CAPABILITY_ROWS: [PacketSemanticsCapabilityRow; 8] = [
    admitted_packet_row(
        "tcp-stream-relay",
        "resident-tcp-relay",
        "tcp-stream",
        "selected-resident-graph",
    ),
    admitted_packet_row(
        "protocol-closed",
        "resident-protocol-closed-admission",
        "protocol-closed",
        "selected-resident-graph",
    ),
    admitted_packet_row(
        "udp-associate",
        "resident-udp-associate-relay",
        "udp-associate",
        "selected-resident-graph",
    ),
    admitted_packet_row(
        "packet-over-stream",
        "resident-packet-stream-relay",
        "udp-over-stream-or-datagram",
        "selected-resident-graph",
    ),
    admitted_packet_row(
        "wrapper-packet-transport",
        "resident-wrapper-bound-packet-relay",
        "packet-transport",
        "selected-resident-wrapper-graph",
    ),
    admitted_packet_row(
        "multiplexed-stream",
        "resident-shared-mux-stream",
        "multiplexed-stream",
        "selected-resident-wrapper-graph",
    ),
    admitted_packet_row(
        "passthrough-udp",
        "resident-protocol-udp-passthrough",
        "passthrough-udp",
        "selected-resident-graph",
    ),
    admitted_packet_row(
        "option-packet-transport",
        "resident-quic-option-packet-relay",
        "option-packet-transport",
        "selected-resident-graph",
    ),
];

const EXTENSION_LAYER_CAPABILITY_ROWS: [ExtensionLayerCapabilityRow; 5] = [
    ExtensionLayerCapabilityRow {
        layer_id: "no-plugin-baseline",
        layer: "none",
        status: "admitted",
        provider: "resident-base-handler",
        admission_boundary: "base-handler-only",
        reload_cleanup: "drop-on-graph-diff-or-runtime-stop",
        no_inherited_admission: true,
        blocker_id: None,
        evidence_requirements: &["service-contract", "baseline-live"],
    },
    ExtensionLayerCapabilityRow {
        layer_id: "plugin-wrapper-layer",
        layer: "plugin-wrapper",
        status: "admitted",
        provider: "resident-simple-obfs-http",
        admission_boundary: "scoped-plugin-wrapper-executor",
        reload_cleanup: "drop-on-graph-diff-or-runtime-stop",
        no_inherited_admission: true,
        blocker_id: None,
        evidence_requirements: &["large-page-live", "benchmark", "cleanup"],
    },
    ExtensionLayerCapabilityRow {
        layer_id: "legacy-import-normalizer",
        layer: "legacy-import",
        status: "admitted",
        provider: "resident-legacy-import-normalizer",
        admission_boundary: "normalizes-to-current-resident-executor",
        reload_cleanup: "drop-on-graph-diff-or-runtime-stop",
        no_inherited_admission: true,
        blocker_id: None,
        evidence_requirements: &["large-page-live", "benchmark", "cleanup"],
    },
    fail_closed_extension_row(
        "legacy-cipher-layer",
        "legacy-cipher",
        "resident-legacy-cipher-policy-boundary",
        "not-inherited-from-modern-cipher-admission",
    ),
    fail_closed_extension_row(
        "legacy-obfs-layer",
        "legacy-obfs",
        "resident-legacy-obfs-policy-boundary",
        "not-inherited-from-no-obfs-admission",
    ),
];

const TRANSPORT_OPTION_CAPABILITY_ROWS: [TransportOptionCapabilityRow; 4] = [
    TransportOptionCapabilityRow {
        option_id: "baseline-transport-option",
        option_surface: "baseline",
        status: "admitted",
        provider: "resident-base-transport-executor",
        security_underlay: "baseline-admitted",
        packet_semantics: "baseline-admitted",
        reload_cleanup: "drop-on-graph-diff-or-runtime-stop",
        blocker_id: None,
        evidence_requirements: &["service-contract", "baseline-live"],
    },
    admitted_transport_option_row(
        "quic-option-surface",
        "quic-option",
        "resident-quic-option-executor",
        "quic-tls",
        "quic-datagram-or-stream",
    ),
    admitted_transport_option_row(
        "secure-proxy-endpoint",
        "secure-endpoint",
        "resident-secure-endpoint-executor",
        "standard-or-fingerprint-aware-tls",
        "protocol-closed",
    ),
    admitted_transport_option_row(
        "explicit-insecure-option",
        "explicit-insecure",
        "resident-risk-accepted-verification-policy",
        "explicit-insecure",
        "carried-by-option",
    ),
];

const fn admitted_packet_row(
    semantics_id: &'static str,
    provider: &'static str,
    packet_semantics: &'static str,
    graph_binding: &'static str,
) -> PacketSemanticsCapabilityRow {
    PacketSemanticsCapabilityRow {
        semantics_id,
        status: "admitted",
        provider,
        packet_semantics,
        graph_binding,
        reload_cleanup: "drop-on-graph-diff-or-runtime-stop",
        no_direct_alternate_path: true,
        blocker_id: None,
        evidence_requirements: &["service-contract", "baseline-live"],
    }
}

const fn fail_closed_extension_row(
    layer_id: &'static str,
    layer: &'static str,
    provider: &'static str,
    admission_boundary: &'static str,
) -> ExtensionLayerCapabilityRow {
    ExtensionLayerCapabilityRow {
        layer_id,
        layer,
        status: "fail-closed-final",
        provider,
        admission_boundary,
        reload_cleanup: "drop-on-graph-diff-or-runtime-stop",
        no_inherited_admission: true,
        blocker_id: None,
        evidence_requirements: &[
            "parser-fixture",
            "negative-fixture",
            "no-inherited-admission",
            "no-direct-alternate-path",
        ],
    }
}

const fn admitted_transport_option_row(
    option_id: &'static str,
    option_surface: &'static str,
    provider: &'static str,
    security_underlay: &'static str,
    packet_semantics: &'static str,
) -> TransportOptionCapabilityRow {
    TransportOptionCapabilityRow {
        option_id,
        option_surface,
        status: "admitted",
        provider,
        security_underlay,
        packet_semantics,
        reload_cleanup: "drop-on-graph-diff-or-runtime-stop",
        blocker_id: None,
        evidence_requirements: &[
            "handshake",
            "packet-relay",
            "cleanup",
            "large-page-live",
            "benchmark",
            "cleanup",
        ],
    }
}
