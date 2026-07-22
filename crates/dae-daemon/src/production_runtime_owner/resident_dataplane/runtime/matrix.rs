use super::*;
#[path = "matrix/ownership.rs"]
mod ownership;
use self::ownership::*;
#[path = "matrix/source_reconciliation.rs"]
pub(in crate::production_runtime_owner::resident_dataplane) mod source_reconciliation;
use self::source_reconciliation::*;
#[path = "matrix/source_materialization.rs"]
mod source_materialization;
use self::source_materialization::*;

const PLANNER_STATUS_AGGREGATE_REPORT_ONLY: &str = "aggregate-report-only";
const PLANNER_STATUS_BLOCKED_AGGREGATE_REPORT_ONLY: &str = "blocked-aggregate-report-only";
const PLANNER_STATUS_BLOCKED_DEFERRED: &str = "blocked-deferred";
const EXPANDED_SOURCE_MATRIX_ROW_SCHEMA_VERSION: u64 = 2;

pub(super) fn resident_full_matrix_config_rows(
    config: &Config,
    nodes: &[plan::ResidentNodeLinkShape],
) -> Vec<Value> {
    let live_evidence = resident_live_matrix_evidence_from_env();
    resident_live_adapter_matrix_entries()
        .iter()
        .map(|entry| {
            let remote_live_matrix =
                resident_live_adapter_entry_remote_live_matrix_ready(entry, &live_evidence);
            let missing = resident_live_adapter_entry_missing(entry, &live_evidence);
            let schemes = matrix_row_schemes(entry.formal_matrix_handler);
            let candidates = nodes
                .iter()
                .filter(|node| schemes.iter().any(|scheme| *scheme == node.scheme))
                .collect::<Vec<_>>();
            let candidate_reports = candidates
                .iter()
                .map(|node| resident_matrix_candidate_report(config, entry, node))
                .collect::<Vec<_>>();
            let admitted_count = candidate_reports
                .iter()
                .filter(|candidate| candidate["planner_status"].as_str() == Some("admitted"))
                .count();
            let blocked_count = candidate_reports
                .iter()
                .filter(|candidate| candidate["planner_status"].as_str() == Some("blocked"))
                .count();
            let planner_status = if candidates.is_empty() {
                "not-present"
            } else if admitted_count > 0 {
                "admitted"
            } else {
                "blocked"
            };
            let runtime_components_ready = candidate_reports
                .iter()
                .any(resident_matrix_candidate_runtime_components_ready);
            let generated_solver = resident_matrix_solver_value(
                entry,
                candidates.len(),
                admitted_count,
                blocked_count,
                runtime_components_ready,
                remote_live_matrix,
                missing.is_empty(),
            );
            let native_ready = generated_solver["nativeReady"].clone();
            let production_ready = generated_solver["productionReady"].clone();
            json!({
                "handler": entry.handler,
                "formal_matrix_handler": entry.formal_matrix_handler,
                "matrix_scope": "current-config-formal-handler-matrix",
                "opened": true,
                "source_supported": true,
                "source_supported_scope": "formal-handler-baseline",
                "source_shape_registry_status": "open",
                "expanded_source_matrix_state": "generated",
                "planner_status": planner_status,
                "wired_ready": entry.wired_ready(),
                "tcp_live_adapter": entry.tcp_live_adapter,
                "tcp_semantics": entry.tcp_semantics,
                "tcp_path_ready": entry.tcp_path_ready(),
                "runtime_components_ready": runtime_components_ready,
                "live_ready": entry.wired_ready() && remote_live_matrix && missing.is_empty(),
                "remote_live_matrix": remote_live_matrix,
                "udp_live_adapter": entry.udp_live_adapter,
                "udp_semantics": entry.udp_semantics,
                "udp_path_ready": entry.udp_path_ready(),
                "candidate_count": candidates.len(),
                "admitted_count": admitted_count,
                "blocked_count": blocked_count,
                "selected_node_fail_closed": entry.selected_node_fail_closed,
                "fingerprint_behavior": entry.fingerprint_behavior,
                "generated_solver": generated_solver,
                "native_ready": native_ready,
                "production_ready": production_ready,
                "missing": missing,
                "candidates": candidate_reports,
            })
        })
        .collect()
}

pub(super) struct ResidentExpandedSourceMatrix {
    pub(super) rows: Vec<Value>,
    pub(super) source_admission_diagnostics: Vec<Value>,
}

pub(super) fn resident_expanded_source_matrix(
    config: &Config,
    nodes: &[plan::ResidentNodeLinkShape],
    current_config_rows: &[Value],
) -> ResidentExpandedSourceMatrix {
    let rows = source_shape_registry_rows();
    let materializations = resident_source_materializations(config, nodes, rows);
    let source_admission_diagnostics =
        resident_source_materialization_diagnostics(rows, &materializations);
    let rows = rows
        .iter()
        .map(|row| resident_expanded_source_matrix_row(row, &materializations, current_config_rows))
        .collect();
    ResidentExpandedSourceMatrix {
        rows,
        source_admission_diagnostics,
    }
}

#[cfg(test)]
pub(super) fn resident_expanded_source_matrix_rows(
    config: &Config,
    nodes: &[plan::ResidentNodeLinkShape],
    current_config_rows: &[Value],
) -> Vec<Value> {
    resident_expanded_source_matrix(config, nodes, current_config_rows).rows
}

fn resident_expanded_source_matrix_row(
    row: &SourceShapeRegistryRow,
    materializations: &[ResidentSourceMaterialization<'_>],
    current_config_rows: &[Value],
) -> Value {
    let reconciliation_kind = source_shape_reconciliation_kind(row);
    let candidate_materializations = if reconciliation_kind
        == Some(dae_outbound::SourceShapeReconciliationKind::ProductionWitness)
    {
        materializations
            .iter()
            .filter(|materialization| {
                resident_source_materialization_is_candidate(row, materialization)
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let candidate_count = candidate_materializations.len();
    let candidate_reports = candidate_materializations
        .iter()
        .map(|materialization| resident_source_shape_candidate_report(row, materialization))
        .collect::<Vec<_>>();
    let admitted_count = candidate_reports
        .iter()
        .filter(|candidate| candidate["planner_status"].as_str() == Some("admitted"))
        .count();
    let blocked_count = candidate_reports
        .iter()
        .filter(|candidate| candidate["planner_status"].as_str() == Some("blocked"))
        .count();
    let classified_materializations = materializations
        .iter()
        .filter(|materialization| {
            resident_source_materialization_is_classified(row, materialization)
        })
        .collect::<Vec<_>>();
    let classified_candidate_reports = classified_materializations
        .iter()
        .map(|materialization| resident_source_shape_classified_report(row, materialization))
        .collect::<Vec<_>>();
    let classified_candidate_count = classified_candidate_reports.len();
    let relevant_current_config_statuses = current_config_rows.iter().filter_map(|current| {
        let handler = current["formal_matrix_handler"]
            .as_str()
            .or_else(|| current["handler"].as_str())?;
        let directly_named = handler == row.protocol_family;
        let scheme_matches = matrix_row_schemes(handler)
            .iter()
            .any(|scheme| row.link_schemes.contains(scheme));
        (directly_named || scheme_matches)
            .then(|| current["planner_status"].as_str())
            .flatten()
    });
    let mut current_config_status = "not-present";
    for status in relevant_current_config_statuses {
        match status {
            "admitted" => {
                current_config_status = "admitted";
                break;
            }
            "blocked" => current_config_status = "blocked",
            _ => {}
        }
    }
    let production_witness_status = match (row.source_support, row.resident_status) {
        ("not-source-supported", _) => "not-source-supported",
        ("source-supported", "blocked") => "blocked",
        ("source-supported", "admitted-baseline") if candidate_count == 0 => "not-present",
        ("source-supported", "admitted-baseline") if admitted_count > 0 => "admitted",
        ("source-supported", "admitted-baseline") if blocked_count > 0 => "blocked",
        ("source-supported", "admitted-baseline") => current_config_status,
        _ => "blocked",
    };
    let (planner_status, candidate_evaluation) = match reconciliation_kind {
        Some(dae_outbound::SourceShapeReconciliationKind::ProductionWitness) => {
            (production_witness_status, "per-node-materialization")
        }
        Some(dae_outbound::SourceShapeReconciliationKind::AggregateCapability)
            if row.resident_status == "blocked" =>
        {
            (
                PLANNER_STATUS_BLOCKED_AGGREGATE_REPORT_ONLY,
                "blocked-aggregate-classification",
            )
        }
        Some(dae_outbound::SourceShapeReconciliationKind::AggregateCapability) => (
            PLANNER_STATUS_AGGREGATE_REPORT_ONLY,
            "aggregate-report-only",
        ),
        Some(dae_outbound::SourceShapeReconciliationKind::DeferredCapability) => {
            (PLANNER_STATUS_BLOCKED_DEFERRED, "deferred-row-blocker")
        }
        Some(dae_outbound::SourceShapeReconciliationKind::SourceRejected) => {
            ("not-source-supported", "source-policy-rejected")
        }
        None => ("blocked", "missing-reconciliation"),
    };
    let capability_reason_id = match reconciliation_kind {
        Some(dae_outbound::SourceShapeReconciliationKind::AggregateCapability)
            if row.resident_status == "blocked" =>
        {
            json!(row.blocker_id.unwrap_or("aggregate-capability-blocked"))
        }
        Some(dae_outbound::SourceShapeReconciliationKind::AggregateCapability) => Value::Null,
        Some(dae_outbound::SourceShapeReconciliationKind::DeferredCapability) => {
            json!(row.blocker_id.unwrap_or("deferred-capability"))
        }
        Some(dae_outbound::SourceShapeReconciliationKind::SourceRejected) => {
            json!("unsupported-source-policy")
        }
        Some(dae_outbound::SourceShapeReconciliationKind::ProductionWitness) => {
            match planner_status {
                "admitted" | "not-present" => Value::Null,
                "not-source-supported" => json!("unsupported-source-policy"),
                _ => json!(row.blocker_id.unwrap_or("materialization-mismatch")),
            }
        }
        None => json!(row.blocker_id.unwrap_or("missing-source-reconciliation")),
    };
    let redacted_detail = match reconciliation_kind {
        Some(dae_outbound::SourceShapeReconciliationKind::AggregateCapability)
            if row.resident_status == "blocked" =>
        {
            "aggregate classification is visible, but exact component coverage remains blocked"
        }
        Some(dae_outbound::SourceShapeReconciliationKind::AggregateCapability) => {
            "aggregate capability is report-only; classified sources do not contribute planner admission"
        }
        Some(dae_outbound::SourceShapeReconciliationKind::DeferredCapability) => {
            "shape is blocked and deferred by its registry blocker; no per-node candidate is reported"
        }
        Some(dae_outbound::SourceShapeReconciliationKind::SourceRejected) => {
            "shape is rejected by Rust native source policy"
        }
        Some(dae_outbound::SourceShapeReconciliationKind::ProductionWitness) => {
            match planner_status {
                "admitted" => "current config candidate is admitted by resident planner",
                "not-present" => "shape is source-supported but absent from current config",
                "not-source-supported" => "shape is rejected by Rust native source policy",
                _ => "shape remains fail-closed until its capability evidence is complete",
            }
        }
        None => "shape has no typed reconciliation contract and remains fail-closed",
    };

    json!({
        "schemaVersion": EXPANDED_SOURCE_MATRIX_ROW_SCHEMA_VERSION,
        "shapeId": row.shape_id,
        "sourceSupport": row.source_support,
        "protocolFamily": row.protocol_family,
        "linkSchemes": row.link_schemes,
        "planner_status": planner_status,
        "candidateEvaluation": candidate_evaluation,
        "candidate_count": candidate_count,
        "admitted_count": admitted_count,
        "blocked_count": blocked_count,
        "classifiedCandidateCount": classified_candidate_count,
        "classifiedCurrentConfigStatus": if classified_candidate_count == 0 {
            "not-present"
        } else {
            "present"
        },
        "currentConfigStatus": current_config_status,
        "residentStatus": row.resident_status,
        "blockerId": row.blocker_id,
        "capabilityReasonId": capability_reason_id,
        "redactedDetail": redacted_detail,
        "redactedIdentity": row.redacted_identity,
        "endpoint": row.endpoint,
        "securityUnderlay": row.security_underlay,
        "streamWrapper": row.stream_wrapper,
        "packetSemantics": row.packet_semantics,
        "chainShape": row.chain_shape,
        "policySurface": row.policy_surface,
        "reloadLifecycle": row.reload_lifecycle,
        "parserCoverage": row.parser_coverage,
        "evidenceRequirements": row.evidence_requirements,
        "shapeStateLedger": row.state_ledger.to_value(),
        "componentExecutorProof": row.executor_proof.to_value(),
        "runtimeSelectionLedger": row.runtime_selection.to_value(),
        "capabilityLedger": row.capability.to_value(),
        "expandedLiveMatrixLedger": row.expanded_live_matrix.to_value(),
        "productionReadinessReconciliation": row.production_readiness.to_value(),
        "runtimeOwnershipLedger": row.runtime_ownership_ledger(),
        "sourceShapeReconciliation": source_shape_reconciliation_status(row),
        "candidates": candidate_reports,
        "classifiedCandidates": classified_candidate_reports,
        "sourceRegistryRow": (*row).to_value(),
    })
}

pub(super) fn resident_matrix_status_counts(rows: &[Value]) -> Value {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for row in rows {
        let status = row["planner_status"].as_str().unwrap_or("unknown");
        *counts.entry(status.to_owned()).or_default() += 1;
    }
    json!(counts)
}

pub(super) fn resident_matrix_solver_value(
    entry: &adapter_matrix::ResidentLiveAdapterMatrixEntry,
    candidate_count: usize,
    admitted_count: usize,
    blocked_count: usize,
    runtime_components_ready: bool,
    remote_live_matrix: bool,
    remote_live_matrix_complete: bool,
) -> Value {
    let parser_covered = candidate_count > 0;
    let normalized_graph_ready = admitted_count > 0;
    let executable_graph_ready =
        normalized_graph_ready && entry.wired_ready() && runtime_components_ready;
    let admission_fail_closed = blocked_count > 0 || candidate_count == admitted_count;
    let tcp_loopback_ready = executable_graph_ready && entry.tcp_path_ready();
    let udp_loopback_ready = executable_graph_ready && entry.udp_path_ready();
    let reload_cleanup_ready = executable_graph_ready;
    let benchmark_ready = false;
    let live_ready = executable_graph_ready && remote_live_matrix && remote_live_matrix_complete;
    let native_ready = live_ready && benchmark_ready;
    let production_ready = native_ready && entry.native_executor_ready;
    let blockers = resident_matrix_solver_blockers(
        parser_covered,
        normalized_graph_ready,
        runtime_components_ready,
        executable_graph_ready,
        live_ready,
        benchmark_ready,
    );
    json!({
        "schemaVersion": 1,
        "sourceShape": entry.formal_matrix_handler,
        "parserCovered": parser_covered,
        "normalizedGraphReady": normalized_graph_ready,
        "runtimeComponentsReady": runtime_components_ready,
        "executableGraphReady": executable_graph_ready,
        "admissionFailClosed": admission_fail_closed,
        "tcpLoopbackReady": tcp_loopback_ready,
        "udpLoopbackReady": udp_loopback_ready,
        "reloadCleanupReady": reload_cleanup_ready,
        "benchmarkReady": benchmark_ready,
        "liveReady": live_ready,
        "nativeReady": native_ready,
        "productionReady": production_ready,
        "blockers": blockers,
    })
}

pub(super) fn resident_matrix_solver_blockers(
    parser_covered: bool,
    normalized_graph_ready: bool,
    runtime_components_ready: bool,
    executable_graph_ready: bool,
    live_ready: bool,
    benchmark_ready: bool,
) -> Vec<&'static str> {
    let mut blockers = Vec::new();
    if !parser_covered {
        blockers.push("no source-supported candidate is present in this config");
    }
    if !normalized_graph_ready {
        blockers.push("no normalized resident graph was admitted");
    }
    if !runtime_components_ready {
        blockers.push("runtime component factory/session/probe evidence is missing or fail-closed");
    }
    if !executable_graph_ready {
        blockers.push("executable graph evidence is missing");
    }
    if !live_ready {
        blockers.push("remote live matrix evidence is missing or incomplete");
    }
    if !benchmark_ready {
        blockers.push("matched benchmark evidence is missing");
    }
    blockers
}

pub(super) fn resident_matrix_candidate_runtime_components_ready(candidate: &Value) -> bool {
    if candidate["planner_status"].as_str() != Some("admitted") {
        return false;
    }
    let components = &candidate["runtimeComponents"];
    let udp_agreement = &components["udpExecutionAgreement"];
    component_status_is_admitted(&components["underlayFactory"])
        && component_status_is_admitted(&components["streamWrapperFactory"])
        && component_status_is_admitted(&components["chainExecutor"])
        && generation_cache_contract_ready(&components["generationCache"])
        && component_status_is_admitted(&components["probeExecutor"])
        && udp_execution_agreement_ready(udp_agreement)
        && udp_component_matches_agreement(
            udp_agreement,
            &components["packetSessionManager"],
            "expectedPacketSessionStatus",
        )
        && udp_component_matches_agreement(
            udp_agreement,
            &components["probeExecutor"]["udp"],
            "expectedProbeStatus",
        )
}

pub(super) fn component_status_is_admitted(component: &Value) -> bool {
    component["status"].as_str() == Some("admitted")
}

pub(super) fn generation_cache_contract_ready(component: &Value) -> bool {
    component["schemaVersion"].as_i64() == Some(1)
        && component["graphId"]
            .as_str()
            .is_some_and(|graph| !graph.is_empty())
        && component["owner"].as_str() == Some("resident-dataplane-runtime")
        && component["cacheScope"].as_str() == Some("graph-and-reload-generation")
        && component["cleanupPolicy"].as_str() == Some("drop-on-graph-diff-or-runtime-stop")
}

fn udp_execution_agreement_ready(agreement: &Value) -> bool {
    let disposition = agreement["disposition"].as_str();
    let policy_closed = agreement["policyClosed"].as_bool();
    let negative_path_ready = agreement["negativePathReady"].as_bool();
    let packet_status = agreement["expectedPacketSessionStatus"].as_str();
    let probe_status = agreement["expectedProbeStatus"].as_str();
    let unsupported_reason = agreement["unsupportedReason"].as_str();
    let disposition_ready = match disposition {
        Some("packet-relay") => {
            policy_closed == Some(false)
                && negative_path_ready == Some(false)
                && packet_status == Some("admitted")
                && probe_status == Some("admitted")
                && agreement["unsupportedReason"].is_null()
        }
        Some("policy-closed-negative-path") => {
            policy_closed == Some(true)
                && negative_path_ready == Some(true)
                && packet_status == Some("fail-closed")
                && probe_status == Some("fail-closed")
                && unsupported_reason.is_some_and(|reason| !reason.is_empty())
        }
        _ => false,
    };
    disposition_ready
        && agreement["schemaVersion"].as_i64() == Some(1)
        && agreement["executor"]
            .as_str()
            .is_some_and(|executor| !executor.is_empty())
        && agreement["packetSemantics"]
            .as_str()
            .is_some_and(|semantics| !semantics.is_empty())
        && agreement["generationOwned"].as_bool() == Some(true)
        && agreement["cleanupOwner"].as_str() == Some(plan::RESIDENT_UDP_CLEANUP_OWNER)
        && agreement["cleanupPolicy"].as_str() == Some(plan::RESIDENT_UDP_CLEANUP_POLICY)
}

fn udp_component_matches_agreement(
    agreement: &Value,
    component: &Value,
    expected_status_field: &str,
) -> bool {
    component["schemaVersion"].as_i64() == Some(1)
        && component["status"] == agreement[expected_status_field]
        && component["executor"] == agreement["executor"]
        && component["packetSemantics"] == agreement["packetSemantics"]
        && component["agreementDisposition"] == agreement["disposition"]
        && component["policyClosed"] == agreement["policyClosed"]
        && component["negativePathReady"] == agreement["negativePathReady"]
        && component["unsupportedReason"] == agreement["unsupportedReason"]
        && component["generationOwned"] == agreement["generationOwned"]
        && component["cleanupOwner"] == agreement["cleanupOwner"]
        && component["cleanupPolicy"] == agreement["cleanupPolicy"]
}

pub(super) fn resident_matrix_candidate_report(
    config: &Config,
    entry: &adapter_matrix::ResidentLiveAdapterMatrixEntry,
    node: &plan::ResidentNodeLinkShape,
) -> Value {
    match plan::build_resident_proxy_plan_for_node(
        config,
        entry.formal_matrix_handler.to_owned(),
        node.tag.clone(),
        node.link.clone(),
    ) {
        Ok(proxy) => {
            let mut summary = resident_proxy_plan_summary_json(&proxy);
            summary["planner_status"] = json!("admitted");
            summary["scheme"] = json!(&node.scheme);
            summary["admission"] = json!({
                "status": "admitted",
                "failClosed": true,
                "unsupportedReason": Value::Null,
            });
            summary
        }
        Err(err) => json!({
            "planner_status": "blocked",
            "node_tag": safe_matrix_node_tag(&node.tag),
            "node_tag_source": matrix_node_tag_source(&node.tag),
            "scheme": &node.scheme,
            "admission": {
                "status": "fail-closed",
                "failClosed": true,
                "unsupportedReason": sanitize_matrix_error(&err),
            },
            "error": sanitize_matrix_error(&err),
        }),
    }
}

pub(super) fn matrix_row_schemes(formal_matrix_handler: &str) -> &'static [&'static str] {
    match formal_matrix_handler {
        "vless" => &["vless"],
        "shadowsocks" => &["ss", "shadowsocks"],
        "trojan" => &["trojan", "trojan-go"],
        "vmess" => &["vmess"],
        "hysteria2" => &["hysteria2", "hy2"],
        "tuic" => &["tuic"],
        "juicity" => &["juicity"],
        "anytls" => &["anytls"],
        "http-proxy" => &["http", "https"],
        "socks5" => &["socks", "socks5"],
        "connect-udp" => &["masque"],
        _ => &[],
    }
}

pub(super) fn sanitize_matrix_error(_error: &str) -> String {
    "resident matrix operation failed; inspect protected daemon logs for details".to_owned()
}

pub(super) fn safe_matrix_node_tag(node_tag: &str) -> String {
    if node_tag.contains("://") {
        link_hash(node_tag)
    } else {
        node_tag.to_owned()
    }
}

pub(super) fn matrix_node_tag_source(node_tag: &str) -> &'static str {
    if node_tag.contains("://") {
        "derived-link-hash"
    } else {
        "explicit-display-tag"
    }
}

pub(super) fn resident_proxy_plan_summary_json(proxy: &plan::ResidentProxyPlan) -> Value {
    let fingerprint = proxy.utls_fingerprint.as_ref().map(|fingerprint| {
        json!({
            "source": fingerprint.source,
            "requested": fingerprint.requested,
            "canonical": fingerprint.canonical,
            "family": fingerprint.family,
            "client": fingerprint.client,
            "randomized": fingerprint.randomized,
            "alpn_policy": fingerprint.alpn_policy,
        })
    });
    json!({
        "protocol": proxy.protocol,
        "group": proxy.group_name,
        "group_policy": proxy.group_policy,
        "node_tag": safe_matrix_node_tag(&proxy.node_tag),
        "node_tag_source": matrix_node_tag_source(&proxy.node_tag),
        "transport": proxy.net,
        "security": proxy.tls,
        "flow": proxy.flow,
        "alpn": proxy.alpn,
        "allow_insecure": proxy.allow_insecure,
        "fingerprint_underlay": fingerprint.is_some(),
        "utls_fingerprint": fingerprint,
        "server_port": proxy.server_port,
        "server_name_present": !proxy.server_name.is_empty(),
        "mptcp": proxy.mptcp,
        "executableGraph": proxy.executable_graph_value(),
        "runtimeComponents": proxy.runtime_component_evidence_value(),
    })
}

pub(super) fn resident_proxy_group_plan_summary_json(
    group: &plan::ResidentProxyGroupPlan,
) -> Value {
    let mut summary = group
        .default_proxy_snapshot()
        .as_ref()
        .map(|binding| resident_proxy_plan_summary_json(binding.plan()))
        .unwrap_or_else(|| {
            json!({
                "group": group.group_name,
                "group_policy": group.group_policy_name(),
            })
        });
    summary["group"] = json!(group.group_name);
    summary["group_policy"] = json!(group.group_policy_name());
    summary["candidate_count"] = json!(group.candidate_count());
    summary["admitted_candidate_count"] = json!(group.admitted_candidate_count());
    summary["annotation_latency_offset_count"] = json!(group.annotation_latency_offset_count());
    summary["alive_state_wired"] = json!(group.alive_state_wired());
    summary["latency_state_wired"] = json!(group.latency_state_wired());
    summary["background_check_required"] = json!(group.needs_background_checks());
    summary["check_interval"] = json!(format!("{:?}", group.check_interval()));
    summary
}
