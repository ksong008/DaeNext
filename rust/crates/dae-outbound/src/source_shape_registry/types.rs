use super::*;
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
