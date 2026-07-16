use super::*;
use dae_outbound::{SourceShapeReconciliationKind, SourceShapeRegistryRow};

#[path = "source_shapes/reconciliation.rs"]
mod reconciliation;
use self::reconciliation::*;

pub(super) fn source_shape_registry_status_counts(rows: &[SourceShapeRegistryRow]) -> Value {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for row in rows {
        *counts
            .entry(source_shape_registry_report_status(row).to_owned())
            .or_default() += 1;
    }
    json!(counts)
}

pub(super) fn source_shape_registry_runtime_blocked_row_count(
    rows: &[SourceShapeRegistryRow],
) -> usize {
    rows.iter()
        .filter(|row| {
            if row.source_support != "source-supported" {
                return false;
            }
            match source_shape_reconciliation_kind(row) {
                Some(SourceShapeReconciliationKind::ProductionWitness) => {
                    !production_witness_row_is_admitted(row)
                }
                Some(SourceShapeReconciliationKind::AggregateCapability) => {
                    !aggregate_row_is_resolved(row, rows, &[])
                }
                Some(SourceShapeReconciliationKind::DeferredCapability) | None => true,
                Some(SourceShapeReconciliationKind::SourceRejected) => false,
            }
        })
        .count()
}

pub(super) fn source_shape_registry_policy_rejected_row_count(
    rows: &[SourceShapeRegistryRow],
) -> usize {
    rows.iter()
        .filter(|row| {
            source_shape_reconciliation_kind(row)
                == Some(SourceShapeReconciliationKind::SourceRejected)
        })
        .count()
}

pub(super) fn required_protocol_variant_shape_ids() -> &'static [&'static str] {
    dae_outbound::official_common_source_shape_ids()
}

pub(super) fn excluded_stream_wrapper_source_matrix_typed_report(
    rows: &[SourceShapeRegistryRow],
    excluded_stream_wrappers: &[&str],
    scoped_closure_evidence_ready: bool,
) -> Value {
    let source_supported = rows
        .iter()
        .filter(|row| row.source_support == "source-supported")
        .collect::<Vec<_>>();
    let included_source_supported = source_supported
        .iter()
        .copied()
        .filter(|row| !excluded_stream_wrappers.contains(&row.stream_wrapper))
        .collect::<Vec<_>>();
    let production_witness_rows = included_source_supported
        .iter()
        .copied()
        .filter(|row| {
            source_shape_reconciliation_kind(row)
                == Some(SourceShapeReconciliationKind::ProductionWitness)
        })
        .collect::<Vec<_>>();
    let aggregate_rows = included_source_supported
        .iter()
        .copied()
        .filter(|row| {
            source_shape_reconciliation_kind(row)
                == Some(SourceShapeReconciliationKind::AggregateCapability)
        })
        .collect::<Vec<_>>();
    let deferred_rows = included_source_supported
        .iter()
        .copied()
        .filter(|row| {
            source_shape_reconciliation_kind(row)
                == Some(SourceShapeReconciliationKind::DeferredCapability)
        })
        .collect::<Vec<_>>();
    let missing_reconciliation_rows = included_source_supported
        .iter()
        .copied()
        .filter(|row| source_shape_reconciliation_kind(row).is_none())
        .collect::<Vec<_>>();
    let admitted = production_witness_rows
        .iter()
        .copied()
        .filter(|row| production_witness_row_is_admitted(row))
        .collect::<Vec<_>>();
    let resolved_aggregate_rows = aggregate_rows
        .iter()
        .copied()
        .filter(|row| aggregate_row_is_resolved(row, rows, excluded_stream_wrappers))
        .collect::<Vec<_>>();
    let unresolved_aggregate_rows = aggregate_rows
        .iter()
        .copied()
        .filter(|row| !aggregate_row_is_resolved(row, rows, excluded_stream_wrappers))
        .collect::<Vec<_>>();
    let explicit_fail_closed = included_source_supported
        .iter()
        .copied()
        .filter(|row| source_shape_row_is_explicit_fail_closed(row))
        .collect::<Vec<_>>();
    let protocol_variant_rows = included_source_supported
        .iter()
        .copied()
        .map(|row| {
            let reconciliation = dae_outbound::source_shape_reconciliation(row.shape_id);
            json!({
                "variantId": row.shape_id,
                "protocolFamily": row.protocol_family,
                "linkSchemes": row.link_schemes,
                "securityUnderlay": row.security_underlay,
                "streamWrapper": row.stream_wrapper,
                "packetSemantics": row.packet_semantics,
                "residentStatus": row.resident_status,
                "reportStatus": source_shape_registry_report_status(row),
                "reconciliationKind": reconciliation.map(|reconciliation| reconciliation.kind.as_report_str()).unwrap_or("missing"),
                "resolved": source_shape_row_is_resolved(row, rows, excluded_stream_wrappers),
                "contributesProductionWitness": reconciliation.is_some_and(|reconciliation| reconciliation.contributes_production_witness()),
                "blockerId": row.blocker_id,
                "executorProof": row.executor_proof.proof_state,
            })
        })
        .collect::<Vec<_>>();
    let official_common_source_shape_ids = dae_outbound::official_common_source_shape_ids();
    let official_common_source_shape_total = official_common_source_shape_ids.len();
    let official_common_rows = rows
        .iter()
        .filter(|row| official_common_source_shape_ids.contains(&row.shape_id))
        .collect::<Vec<_>>();
    let admitted_official_common_source_shape_count = official_common_rows
        .iter()
        .filter(|row| production_witness_row_is_admitted(row))
        .count();
    let resolved_official_common_source_shape_count = official_common_rows
        .iter()
        .filter(|row| source_shape_row_is_resolved(row, rows, &[]))
        .count();
    let aggregate_official_common_source_shape_count = official_common_rows
        .iter()
        .filter(|row| {
            source_shape_reconciliation_kind(row)
                == Some(SourceShapeReconciliationKind::AggregateCapability)
        })
        .count();
    let deferred_official_common_source_shape_count = official_common_rows
        .iter()
        .filter(|row| {
            source_shape_reconciliation_kind(row)
                == Some(SourceShapeReconciliationKind::DeferredCapability)
        })
        .count();
    let explicit_fail_closed_official_common_source_shape_count = official_common_rows
        .iter()
        .filter(|row| source_shape_row_is_explicit_fail_closed(row))
        .count();
    let absent_official_common_source_shape_ids = official_common_source_shape_ids
        .iter()
        .copied()
        .filter(|shape_id| !rows.iter().any(|row| row.shape_id == *shape_id))
        .collect::<Vec<_>>();
    let absent_official_common_source_shape_count = absent_official_common_source_shape_ids.len();
    let required_protocol_variant_shape_ids = required_protocol_variant_shape_ids()
        .iter()
        .copied()
        .filter(|shape_id| {
            rows.iter()
                .find(|row| row.shape_id == *shape_id)
                .map(|row| !excluded_stream_wrappers.contains(&row.stream_wrapper))
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    let blocked_protocol_variant_ids = included_source_supported
        .iter()
        .copied()
        .filter(|row| !source_shape_row_is_resolved(row, rows, excluded_stream_wrappers))
        .map(|row| row.shape_id)
        .collect::<Vec<_>>();
    let missing_required_protocol_variant_shape_ids = required_protocol_variant_shape_ids
        .iter()
        .copied()
        .filter(|shape_id| {
            !included_source_supported
                .iter()
                .any(|row| row.shape_id == *shape_id)
        })
        .collect::<Vec<_>>();
    let all_required_protocol_variants_present =
        missing_required_protocol_variant_shape_ids.is_empty();
    let excluded_shape_ids = source_supported
        .iter()
        .copied()
        .filter(|row| excluded_stream_wrappers.contains(&row.stream_wrapper))
        .map(|row| row.shape_id)
        .collect::<Vec<_>>();
    let opened_shape_ids = admitted.iter().map(|row| row.shape_id).collect::<Vec<_>>();
    let aggregate_shape_ids = aggregate_rows
        .iter()
        .map(|row| row.shape_id)
        .collect::<Vec<_>>();
    let resolved_aggregate_shape_ids = resolved_aggregate_rows
        .iter()
        .map(|row| row.shape_id)
        .collect::<Vec<_>>();
    let unresolved_aggregate_shape_ids = unresolved_aggregate_rows
        .iter()
        .map(|row| row.shape_id)
        .collect::<Vec<_>>();
    let deferred_shape_ids = deferred_rows
        .iter()
        .map(|row| row.shape_id)
        .collect::<Vec<_>>();
    let missing_reconciliation_shape_ids = missing_reconciliation_rows
        .iter()
        .map(|row| row.shape_id)
        .collect::<Vec<_>>();
    let explicit_fail_closed_shape_ids = explicit_fail_closed
        .iter()
        .map(|row| row.shape_id)
        .collect::<Vec<_>>();
    let policy_rejected_rows = rows
        .iter()
        .filter(|row| {
            source_shape_reconciliation_kind(row)
                == Some(SourceShapeReconciliationKind::SourceRejected)
        })
        .collect::<Vec<_>>();
    let policy_rejected_shape_ids = policy_rejected_rows
        .iter()
        .map(|row| row.shape_id)
        .collect::<Vec<_>>();
    let policy_rejected_rows_fail_closed = policy_rejected_rows
        .iter()
        .all(|row| source_rejected_row_is_fail_closed(row));
    let all_source_supported_rows_admitted =
        admitted.len() == included_source_supported.len() && !included_source_supported.is_empty();
    let all_production_witness_rows_admitted =
        admitted.len() == production_witness_rows.len() && !production_witness_rows.is_empty();
    let all_aggregate_rows_resolved = resolved_aggregate_rows.len() == aggregate_rows.len();
    let no_deferred_rows = deferred_rows.is_empty();
    let reconciliations_are_total = missing_reconciliation_rows.is_empty();
    let official_common_source_shapes_fully_represented =
        absent_official_common_source_shape_count == 0;
    let official_common_source_shapes_all_resolved = official_common_source_shapes_fully_represented
        && resolved_official_common_source_shape_count == official_common_source_shape_total;
    let all_protocol_rows_open = all_production_witness_rows_admitted
        && all_aggregate_rows_resolved
        && no_deferred_rows
        && reconciliations_are_total
        && all_required_protocol_variants_present
        && blocked_protocol_variant_ids.is_empty();
    let complete =
        all_protocol_rows_open && policy_rejected_rows_fail_closed && scoped_closure_evidence_ready;
    let source_scope = if excluded_stream_wrappers.is_empty() {
        "source-supported-rows"
    } else {
        "source-supported-rows-excluding-stream-wrapper"
    };
    let full_expanded_source_matrix_complete = excluded_stream_wrappers.is_empty() && complete;

    json!({
        "schema": "excluded-stream-wrapper-source-report",
        "schemaVersion": 2,
        "status": if complete { "pass" } else { "blocked" },
        "open": true,
        "complete": complete,
        "production_ready": complete,
        "final_state_ready": complete,
        "source_scope": source_scope,
        "excluded_stream_wrappers": excluded_stream_wrappers,
        "excluded_shape_ids": excluded_shape_ids,
        "source_supported_row_count": included_source_supported.len(),
        "production_witness_row_count": production_witness_rows.len(),
        "admitted_row_count": admitted.len(),
        "aggregate_report_only_row_count": aggregate_rows.len(),
        "resolved_aggregate_row_count": resolved_aggregate_rows.len(),
        "unresolved_aggregate_row_count": unresolved_aggregate_rows.len(),
        "deferred_row_count": deferred_rows.len(),
        "missing_reconciliation_row_count": missing_reconciliation_rows.len(),
        "explicit_fail_closed_row_count": explicit_fail_closed.len(),
        "all_source_supported_rows_admitted": all_source_supported_rows_admitted,
        "all_production_witness_rows_admitted": all_production_witness_rows_admitted,
        "all_aggregate_rows_resolved": all_aggregate_rows_resolved,
        "no_deferred_rows": no_deferred_rows,
        "reconciliations_are_total": reconciliations_are_total,
        "all_protocol_rows_open": all_protocol_rows_open,
        "official_common_source_shape_total": official_common_source_shape_total,
        "admitted_official_common_source_shape_count": admitted_official_common_source_shape_count,
        "resolved_official_common_source_shape_count": resolved_official_common_source_shape_count,
        "aggregate_official_common_source_shape_count": aggregate_official_common_source_shape_count,
        "deferred_official_common_source_shape_count": deferred_official_common_source_shape_count,
        "explicit_fail_closed_official_common_source_shape_count": explicit_fail_closed_official_common_source_shape_count,
        "absent_official_common_source_shape_count": absent_official_common_source_shape_count,
        "absent_official_common_source_shape_ids": absent_official_common_source_shape_ids,
        "official_common_source_shapes_fully_represented": official_common_source_shapes_fully_represented,
        "official_common_source_shapes_all_resolved": official_common_source_shapes_all_resolved,
        "protocol_variant_row_count": protocol_variant_rows.len(),
        "protocol_variant_rows": protocol_variant_rows,
        "required_protocol_variant_shape_ids": required_protocol_variant_shape_ids,
        "all_required_protocol_variants_present": all_required_protocol_variants_present,
        "missing_required_protocol_variant_shape_ids": missing_required_protocol_variant_shape_ids,
        "blocked_protocol_variant_count": blocked_protocol_variant_ids.len(),
        "blocked_protocol_variant_ids": blocked_protocol_variant_ids,
        "opened_shape_ids": opened_shape_ids,
        "aggregate_shape_ids": aggregate_shape_ids,
        "resolved_aggregate_shape_ids": resolved_aggregate_shape_ids,
        "unresolved_aggregate_shape_ids": unresolved_aggregate_shape_ids,
        "deferred_shape_ids": deferred_shape_ids,
        "missing_reconciliation_shape_ids": missing_reconciliation_shape_ids,
        "explicit_fail_closed_shape_ids": explicit_fail_closed_shape_ids,
        "policy_rejected_row_count": policy_rejected_rows.len(),
        "policy_rejected_shape_ids": policy_rejected_shape_ids,
        "policy_rejected_rows_fail_closed": policy_rejected_rows_fail_closed,
        "scoped_closure_evidence_ready": scoped_closure_evidence_ready,
        "full_expanded_source_matrix_complete": full_expanded_source_matrix_complete,
        "current_report_schema": true,
    })
}
