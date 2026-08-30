use dae_outbound_core::{
    SourceShapeReconciliation, SourceShapeReconciliationKind, SourceShapeRegistryRow,
};

pub(super) fn source_shape_reconciliation_kind(
    row: &SourceShapeRegistryRow,
) -> Option<SourceShapeReconciliationKind> {
    dae_outbound_core::source_shape_reconciliation(row.shape_id)
        .map(|reconciliation| reconciliation.kind)
}

fn row_has_admitted_runtime_evidence(row: &SourceShapeRegistryRow) -> bool {
    row.resident_status == "admitted-baseline"
        && row.state_ledger.resident_graph == "admitted"
        && row.executor_proof.proof_state == "runtime-executable"
        && row.blocker_id.is_none()
}

pub(super) fn production_witness_row_is_admitted(row: &SourceShapeRegistryRow) -> bool {
    source_shape_reconciliation_kind(row) == Some(SourceShapeReconciliationKind::ProductionWitness)
        && row_has_admitted_runtime_evidence(row)
}

pub(super) fn source_rejected_row_is_fail_closed(row: &SourceShapeRegistryRow) -> bool {
    source_shape_reconciliation_kind(row) == Some(SourceShapeReconciliationKind::SourceRejected)
        && row.source_support == "not-source-supported"
        && row.resident_status == "not-source-supported"
        && row.blocker_id == Some("unsupported-source-policy")
        && row.state_ledger.resident_graph == "blocked"
        && row.executor_proof.proof_state == "descriptor-only-fail-closed"
}

fn aggregate_components_are_admitted(
    reconciliation: &SourceShapeReconciliation,
    rows: &[SourceShapeRegistryRow],
    excluded_stream_wrappers: &[&str],
) -> bool {
    let component_shape_ids = reconciliation.component_shape_ids();
    !component_shape_ids.is_empty()
        && component_shape_ids.iter().all(|shape_id| {
            rows.iter()
                .find(|row| row.shape_id == *shape_id)
                .is_some_and(|row| {
                    !excluded_stream_wrappers.contains(&row.stream_wrapper)
                        && production_witness_row_is_admitted(row)
                })
        })
}

pub(super) fn aggregate_row_is_resolved(
    row: &SourceShapeRegistryRow,
    rows: &[SourceShapeRegistryRow],
    excluded_stream_wrappers: &[&str],
) -> bool {
    dae_outbound_core::source_shape_reconciliation(row.shape_id).is_some_and(|reconciliation| {
        reconciliation.kind == SourceShapeReconciliationKind::AggregateCapability
            && row_has_admitted_runtime_evidence(row)
            && aggregate_components_are_admitted(reconciliation, rows, excluded_stream_wrappers)
    })
}

pub(super) fn source_shape_row_is_resolved(
    row: &SourceShapeRegistryRow,
    rows: &[SourceShapeRegistryRow],
    excluded_stream_wrappers: &[&str],
) -> bool {
    match source_shape_reconciliation_kind(row) {
        Some(SourceShapeReconciliationKind::ProductionWitness) => {
            production_witness_row_is_admitted(row)
        }
        Some(SourceShapeReconciliationKind::AggregateCapability) => {
            aggregate_row_is_resolved(row, rows, excluded_stream_wrappers)
        }
        Some(SourceShapeReconciliationKind::DeferredCapability) => false,
        Some(SourceShapeReconciliationKind::SourceRejected) => {
            source_rejected_row_is_fail_closed(row)
        }
        None => false,
    }
}

pub(super) fn source_shape_registry_report_status(row: &SourceShapeRegistryRow) -> &'static str {
    match source_shape_reconciliation_kind(row) {
        Some(SourceShapeReconciliationKind::ProductionWitness)
            if production_witness_row_is_admitted(row) =>
        {
            "admitted"
        }
        Some(SourceShapeReconciliationKind::ProductionWitness) | None => "blocked",
        Some(SourceShapeReconciliationKind::AggregateCapability)
            if row.resident_status == "blocked" =>
        {
            "blocked-aggregate-report-only"
        }
        Some(SourceShapeReconciliationKind::AggregateCapability) => "aggregate-report-only",
        Some(SourceShapeReconciliationKind::DeferredCapability) => "blocked-deferred",
        Some(SourceShapeReconciliationKind::SourceRejected) => "not-source-supported",
    }
}

pub(super) fn source_shape_row_is_explicit_fail_closed(row: &SourceShapeRegistryRow) -> bool {
    match source_shape_reconciliation_kind(row) {
        Some(SourceShapeReconciliationKind::ProductionWitness)
        | Some(SourceShapeReconciliationKind::DeferredCapability)
        | None => {
            row.source_support == "source-supported"
                && row.resident_status == "blocked"
                && row.state_ledger.resident_graph == "blocked"
                && row.executor_proof.proof_state == "descriptor-only-fail-closed"
                && row.blocker_id.is_some()
        }
        Some(SourceShapeReconciliationKind::AggregateCapability)
        | Some(SourceShapeReconciliationKind::SourceRejected) => false,
    }
}
