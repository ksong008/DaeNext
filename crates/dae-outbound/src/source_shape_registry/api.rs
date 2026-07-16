use super::*;
pub fn source_shape_registry_contract() -> SourceShapeRegistryContract {
    let rows = source_shape_registry_rows();
    SourceShapeRegistryContract {
        schema: "outbound-source-shape-registry",
        schema_version: 2,
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
    let reconciliations_are_total = rows.iter().all(|row| {
        source_shape_reconciliation(row.shape_id).is_some_and(|reconciliation| match reconciliation
            .kind
        {
            SourceShapeReconciliationKind::ProductionWitness => {
                reconciliation.contributes_production_witness()
                    && direct_selector_ownership_is_total(row, reconciliation)
            }
            SourceShapeReconciliationKind::AggregateCapability => {
                aggregate_reconciliation_is_total(rows, row, reconciliation)
            }
            SourceShapeReconciliationKind::DeferredCapability => {
                row.resident_status == "blocked"
                    && row.blocker_id.is_some()
                    && direct_selector_ownership_is_total(row, reconciliation)
            }
            SourceShapeReconciliationKind::SourceRejected => {
                row.source_support == "not-source-supported"
            }
        })
    });
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
    reconciliations_are_total
        && all_source_supported_rows_admitted
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

fn aggregate_reconciliation_is_total(
    rows: &[SourceShapeRegistryRow],
    aggregate_row: &SourceShapeRegistryRow,
    reconciliation: &SourceShapeReconciliation,
) -> bool {
    if reconciliation.aggregate_components.is_empty() {
        return aggregate_row.resident_status == "blocked"
            && aggregate_row.blocker_id.is_some()
            && !reconciliation.classification_selectors.is_empty()
            && direct_selector_ownership_is_total(aggregate_row, reconciliation);
    }
    if !reconciliation.classification_selectors.is_empty() {
        return false;
    }

    let components_are_total = reconciliation.aggregate_components.iter().enumerate().all(
        |(index, aggregate_component)| {
            let unique = reconciliation.aggregate_components[..index]
                .iter()
                .all(|earlier| earlier != aggregate_component);
            let Some(component) = source_shape_reconciliation(aggregate_component.shape_id) else {
                return false;
            };
            let Some(component_row) = rows
                .iter()
                .find(|row| row.shape_id == aggregate_component.shape_id)
            else {
                return false;
            };
            let projected_shapes = component
                .selectors
                .iter()
                .flat_map(|selector| selector.materialized_shapes())
                .filter(|shape| aggregate_component.projection.matches(*shape))
                .collect::<Vec<_>>();
            unique
                && component.kind == SourceShapeReconciliationKind::ProductionWitness
                && component.contributes_production_witness()
                && !projected_shapes.is_empty()
                && projected_shapes.iter().all(|shape| {
                    reconciliation.classifies(*shape)
                        && aggregate_row
                            .runtime_ownership
                            .accepts_materialized(shape.runtime_ownership_model())
                })
                && component_row
                    .runtime_ownership
                    .allowed_materialized_models
                    .iter()
                    .all(|model| aggregate_row.runtime_ownership.accepts_materialized(*model))
        },
    );
    components_are_total && projected_security_surface_is_total(reconciliation)
}

fn direct_selector_ownership_is_total(
    row: &SourceShapeRegistryRow,
    reconciliation: &SourceShapeReconciliation,
) -> bool {
    reconciliation
        .selectors
        .iter()
        .chain(reconciliation.classification_selectors)
        .flat_map(|selector| selector.materialized_shapes())
        .all(|shape| {
            row.runtime_ownership
                .accepts_materialized(shape.runtime_ownership_model())
        })
}

fn projected_security_surface_is_total(reconciliation: &SourceShapeReconciliation) -> bool {
    let covers_fragment = reconciliation
        .aggregate_components
        .iter()
        .any(|component| component.projection == SourceShapeProjection::TlsFragment);
    let covers_reality = reconciliation
        .aggregate_components
        .iter()
        .any(|component| component.projection == SourceShapeProjection::Reality);
    source_shape_reconciliations()
        .iter()
        .filter(|candidate| candidate.kind == SourceShapeReconciliationKind::ProductionWitness)
        .flat_map(|candidate| candidate.selectors)
        .flat_map(|selector| selector.materialized_shapes())
        .all(|shape| {
            (!covers_fragment || !shape.tls_features.fragment || reconciliation.classifies(shape))
                && (!covers_reality
                    || !matches!(
                        shape.security,
                        MaterializedSecurity::RealityRustls
                            | MaterializedSecurity::RealityFingerprint
                    )
                    || reconciliation.classifies(shape))
        })
}
