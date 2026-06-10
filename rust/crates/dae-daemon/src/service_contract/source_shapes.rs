use super::*;
pub(super) fn source_shape_registry_status_counts(
    rows: &[dae_outbound::SourceShapeRegistryRow],
) -> Value {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for row in rows {
        let status = match row.resident_status {
            "admitted-baseline" => "admitted",
            other => other,
        };
        *counts.entry(status.to_owned()).or_default() += 1;
    }
    json!(counts)
}

pub(super) fn required_protocol_variant_shape_ids() -> &'static [&'static str] {
    dae_outbound::official_common_source_shape_ids()
}

pub(super) fn excluded_stream_wrapper_source_matrix_typed_report(
    rows: &[dae_outbound::SourceShapeRegistryRow],
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
    let admitted = included_source_supported
        .iter()
        .copied()
        .filter(|row| {
            row.resident_status == "admitted-baseline"
                && row.state_ledger.resident_graph == "admitted"
                && row.executor_proof.proof_state == "runtime-executable"
                && row.blocker_id.is_none()
        })
        .collect::<Vec<_>>();
    let explicit_fail_closed = included_source_supported
        .iter()
        .copied()
        .filter(|row| {
            row.resident_status == "blocked"
                && row.state_ledger.resident_graph == "blocked"
                && row.executor_proof.proof_state == "descriptor-only-fail-closed"
                && row.blocker_id.is_some()
        })
        .collect::<Vec<_>>();
    let protocol_variant_rows = included_source_supported
        .iter()
        .copied()
        .map(|row| {
            let admitted = row.resident_status == "admitted-baseline"
                && row.state_ledger.resident_graph == "admitted"
                && row.executor_proof.proof_state == "runtime-executable"
                && row.blocker_id.is_none();
            json!({
                "variantId": row.shape_id,
                "protocolFamily": row.protocol_family,
                "linkSchemes": row.link_schemes,
                "securityUnderlay": row.security_underlay,
                "streamWrapper": row.stream_wrapper,
                "packetSemantics": row.packet_semantics,
                "residentStatus": if admitted { "admitted" } else { "blocked" },
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
        .filter(|row| {
            row.resident_status == "admitted-baseline"
                && row.state_ledger.resident_graph == "admitted"
                && row.executor_proof.proof_state == "runtime-executable"
                && row.blocker_id.is_none()
        })
        .count();
    let explicit_fail_closed_official_common_source_shape_count = official_common_rows
        .iter()
        .filter(|row| {
            row.resident_status == "blocked"
                && row.state_ledger.resident_graph == "blocked"
                && row.executor_proof.proof_state == "descriptor-only-fail-closed"
                && row.blocker_id.is_some()
        })
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
        .filter(|row| {
            row.resident_status != "admitted-baseline"
                || row.state_ledger.resident_graph != "admitted"
                || row.executor_proof.proof_state != "runtime-executable"
                || row.blocker_id.is_some()
        })
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
    let explicit_fail_closed_shape_ids = explicit_fail_closed
        .iter()
        .map(|row| row.shape_id)
        .collect::<Vec<_>>();
    let policy_rejected_rows = rows
        .iter()
        .filter(|row| row.source_support == "not-source-supported")
        .collect::<Vec<_>>();
    let policy_rejected_shape_ids = policy_rejected_rows
        .iter()
        .map(|row| row.shape_id)
        .collect::<Vec<_>>();
    let policy_rejected_rows_fail_closed = policy_rejected_rows.iter().all(|row| {
        row.resident_status == "not-source-supported"
            && row.blocker_id == Some("unsupported-source-policy")
            && row.state_ledger.resident_graph == "blocked"
            && row.executor_proof.proof_state == "descriptor-only-fail-closed"
    });
    let all_source_supported_rows_admitted =
        admitted.len() == included_source_supported.len() && !included_source_supported.is_empty();
    let official_common_source_shapes_fully_represented =
        absent_official_common_source_shape_count == 0;
    let official_common_source_shapes_all_resolved = official_common_source_shapes_fully_represented
        && admitted_official_common_source_shape_count == official_common_source_shape_total;
    let all_protocol_rows_open = all_source_supported_rows_admitted
        && all_required_protocol_variants_present
        && blocked_protocol_variant_ids.is_empty();
    let complete = all_source_supported_rows_admitted
        && all_protocol_rows_open
        && policy_rejected_rows_fail_closed
        && scoped_closure_evidence_ready;

    json!({
        "schema": "excluded-stream-wrapper-source-report",
        "status": if complete { "pass" } else { "blocked" },
        "open": true,
        "complete": complete,
        "release_gate_ready": complete,
        "c10_ready": complete,
        "source_scope": "source-supported-rows-excluding-stream-wrapper",
        "excluded_stream_wrappers": excluded_stream_wrappers,
        "excluded_shape_ids": excluded_shape_ids,
        "source_supported_row_count": included_source_supported.len(),
        "admitted_row_count": admitted.len(),
        "explicit_fail_closed_row_count": explicit_fail_closed.len(),
        "all_source_supported_rows_admitted": all_source_supported_rows_admitted,
        "all_protocol_rows_open": all_protocol_rows_open,
        "official_common_source_shape_total": official_common_source_shape_total,
        "admitted_official_common_source_shape_count": admitted_official_common_source_shape_count,
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
        "explicit_fail_closed_shape_ids": explicit_fail_closed_shape_ids,
        "policy_rejected_row_count": policy_rejected_rows.len(),
        "policy_rejected_shape_ids": policy_rejected_shape_ids,
        "policy_rejected_rows_fail_closed": policy_rejected_rows_fail_closed,
        "scoped_closure_evidence_ready": scoped_closure_evidence_ready,
        "full_expanded_source_matrix_complete": false,
        "stage_report_schema": false,
    })
}
