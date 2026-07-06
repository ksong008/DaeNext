use super::*;
pub fn source_shape_registry_contract() -> SourceShapeRegistryContract {
    let rows = source_shape_registry_rows();
    SourceShapeRegistryContract {
        schema: "outbound-source-shape-registry",
        schema_version: 1,
        rows,
        source_shape_registry_open: true,
        expanded_source_matrix_open: true,
        expanded_source_matrix_complete: expanded_source_matrix_is_complete(
            rows,
            SCOPED_EXPANDED_SOURCE_MATRIX_EVIDENCE,
        ),
        scoped_expanded_source_matrix_evidence: SCOPED_EXPANDED_SOURCE_MATRIX_EVIDENCE,
        production_readiness_may_use_current_config_matrix_as_source_matrix: false,
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

fn expanded_source_matrix_is_complete(
    rows: &[SourceShapeRegistryRow],
    evidence: ScopedExpandedSourceMatrixEvidence,
) -> bool {
    let source_supported = rows
        .iter()
        .filter(|row| row.source_support == "source-supported")
        .collect::<Vec<_>>();
    let all_source_supported_rows_admitted = !source_supported.is_empty()
        && source_supported.iter().all(|row| {
            row.resident_status == "admitted-baseline"
                && row.state_ledger.resident_graph == "admitted"
                && row.executor_proof.proof_state == "runtime-executable"
                && row.blocker_id.is_none()
        });
    let policy_rejected_rows_fail_closed = rows
        .iter()
        .filter(|row| row.source_support == "not-source-supported")
        .all(|row| {
            row.resident_status == "not-source-supported"
                && row.blocker_id == Some("unsupported-source-policy")
                && row.state_ledger.resident_graph == "blocked"
                && row.executor_proof.proof_state == "descriptor-only-fail-closed"
        });
    let no_unscoped_stream_wrapper_exclusions = evidence.excluded_stream_wrappers.is_empty();
    all_source_supported_rows_admitted
        && policy_rejected_rows_fail_closed
        && no_unscoped_stream_wrapper_exclusions
        && evidence.production_ready
        && evidence.all_pass
        && evidence.large_page_all_pass
        && evidence.proxy_evidence_all_pass
        && evidence.benchmark_evidence_ready
        && evidence.cleanup_evidence_ready
        && !evidence.raw_links_retained
        && !evidence.raw_bodies_retained
        && !evidence.raw_state_retained
}
