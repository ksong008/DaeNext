fn resident_full_matrix_config_rows(
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
            let default_ready = generated_solver["defaultReady"].clone();
            let go_free_ready = generated_solver["goFreeReady"].clone();
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
                "default_ready": default_ready,
                "go_free_ready": go_free_ready,
                "missing": missing,
                "candidates": candidate_reports,
            })
        })
        .collect()
}

fn resident_expanded_source_matrix_rows(
    config: &Config,
    nodes: &[plan::ResidentNodeLinkShape],
    current_config_rows: &[Value],
) -> Vec<Value> {
    source_shape_registry_rows()
        .iter()
        .map(|row| resident_expanded_source_matrix_row(config, row, nodes, current_config_rows))
        .collect()
}

fn resident_expanded_source_matrix_row(
    config: &Config,
    row: &SourceShapeRegistryRow,
    nodes: &[plan::ResidentNodeLinkShape],
    current_config_rows: &[Value],
) -> Value {
    let candidate_nodes = nodes
        .iter()
        .filter(|node| {
            row.link_schemes
                .iter()
                .any(|scheme| *scheme == node.scheme.as_str())
        })
        .collect::<Vec<_>>();
    let candidate_count = candidate_nodes.len();
    let candidate_reports = candidate_nodes
        .iter()
        .map(|node| resident_source_shape_candidate_report(config, row, node))
        .collect::<Vec<_>>();
    let admitted_count = candidate_reports
        .iter()
        .filter(|candidate| candidate["planner_status"].as_str() == Some("admitted"))
        .count();
    let blocked_count = candidate_reports
        .iter()
        .filter(|candidate| candidate["planner_status"].as_str() == Some("blocked"))
        .count();
    let current_config_row = current_config_rows.iter().find(|current| {
        current["formal_matrix_handler"].as_str() == Some(row.protocol_family)
            || current["handler"].as_str() == Some(row.protocol_family)
    });
    let current_config_status = current_config_row
        .and_then(|current| current["planner_status"].as_str())
        .unwrap_or("not-present");
    let planner_status = match (row.source_support, row.resident_status) {
        ("not-source-supported", _) => "not-source-supported",
        ("source-supported", "blocked") => "blocked",
        ("source-supported", "admitted-baseline") if candidate_count == 0 => "not-present",
        ("source-supported", "admitted-baseline") if admitted_count > 0 => "admitted",
        ("source-supported", "admitted-baseline") if blocked_count > 0 => "blocked",
        ("source-supported", "admitted-baseline") => current_config_status,
        _ => "blocked",
    };
    let capability_reason_id = match planner_status {
        "admitted" | "not-present" => Value::Null,
        "not-source-supported" => json!("unsupported-source-policy"),
        _ => json!(row.blocker_id.unwrap_or("materialization-mismatch")),
    };
    let redacted_detail = match planner_status {
        "admitted" => "current config candidate is admitted by resident planner",
        "not-present" => "shape is source-supported but absent from current config",
        "not-source-supported" => "shape is rejected by Rust native source policy",
        _ => "shape remains fail-closed until its capability evidence is complete",
    };

    json!({
        "schemaVersion": 1,
        "shapeId": row.shape_id,
        "sourceSupport": row.source_support,
        "protocolFamily": row.protocol_family,
        "linkSchemes": row.link_schemes,
        "planner_status": planner_status,
        "candidate_count": candidate_count,
        "admitted_count": admitted_count,
        "blocked_count": blocked_count,
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
        "releaseGateReconciliation": row.release_gate.to_value(),
        "candidates": candidate_reports,
        "sourceRegistryRow": (*row).to_value(),
    })
}

fn resident_source_shape_candidate_report(
    config: &Config,
    row: &SourceShapeRegistryRow,
    node: &plan::ResidentNodeLinkShape,
) -> Value {
    match plan::build_resident_proxy_plan_for_node(
        config,
        row.protocol_family.to_owned(),
        node.tag.clone(),
        node.link.clone(),
    ) {
        Ok(proxy) => {
            let mut summary = resident_proxy_plan_summary_json(&proxy);
            summary["scheme"] = json!(&node.scheme);
            if resident_proxy_matches_source_shape(row, &proxy, &summary["executableGraph"]) {
                summary["planner_status"] = json!("admitted");
                summary["admission"] = json!({
                    "status": "admitted",
                    "failClosed": true,
                    "unsupportedReason": Value::Null,
                });
            } else {
                summary["planner_status"] = json!("blocked");
                summary["admission"] = json!({
                    "status": "fail-closed",
                    "failClosed": true,
                    "unsupportedReason": "materialized resident graph does not match the source shape capability row",
                });
                summary["error"] = json!(
                    "materialized resident graph does not match the source shape capability row"
                );
            }
            summary
        }
        Err(err) => json!({
            "planner_status": "blocked",
            "node_tag": &node.tag,
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

fn resident_proxy_matches_source_shape(
    row: &SourceShapeRegistryRow,
    proxy: &plan::ResidentProxyPlan,
    graph: &Value,
) -> bool {
    source_shape_protocol_matches(row.protocol_family, &proxy.protocol)
        && source_shape_field_matches(row.security_underlay, graph["securityUnderlay"].as_str())
        && source_shape_field_matches(row.stream_wrapper, graph["streamWrapper"].as_str())
        && source_shape_field_matches(row.packet_semantics, graph["packetSemantics"].as_str())
}

fn source_shape_protocol_matches(row_family: &str, proxy_protocol: &str) -> bool {
    match row_family {
        "multi-protocol" => matches!(proxy_protocol, "vless" | "vmess" | "trojan"),
        "quic-family" => matches!(proxy_protocol, "hysteria2" | "tuic" | "juicity"),
        "proxy-endpoint" => proxy_protocol == "http-proxy",
        other => other == proxy_protocol,
    }
}

fn source_shape_field_matches(expected: &str, actual: Option<&str>) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    if expected == actual {
        return true;
    }
    match expected {
        "standard-or-fingerprint-aware-tls" => {
            matches!(actual, "standard-tls" | "fingerprint-aware-tls")
        }
        "udp-over-stream-or-datagram" => {
            matches!(
                actual,
                "udp-over-stream-or-datagram" | "udp-over-stream" | "datagram-aead" | "xudp"
            )
        }
        "quic-datagram-or-stream" => {
            matches!(
                actual,
                "quic-datagram-or-stream" | "quic-datagram" | "stream-packet"
            )
        }
        "plain-or-native-underlay" => matches!(actual, "none" | "standard-tls" | "quic-tls"),
        _ => false,
    }
}

fn resident_matrix_status_counts(rows: &[Value]) -> Value {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for row in rows {
        let status = row["planner_status"].as_str().unwrap_or("unknown");
        *counts.entry(status.to_owned()).or_default() += 1;
    }
    json!(counts)
}

fn resident_matrix_solver_value(
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
    let tcp_loopback_ready = executable_graph_ready && entry.tcp_live_adapter;
    let udp_loopback_ready = executable_graph_ready && entry.udp_path_ready();
    let reload_cleanup_ready = executable_graph_ready;
    let benchmark_ready = false;
    let live_ready = executable_graph_ready && remote_live_matrix && remote_live_matrix_complete;
    let default_ready = live_ready && benchmark_ready;
    let go_free_ready = default_ready && entry.go_outbound_fallback_retired;
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
        "defaultReady": default_ready,
        "goFreeReady": go_free_ready,
        "blockers": blockers,
    })
}

fn resident_matrix_solver_blockers(
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

fn resident_matrix_candidate_runtime_components_ready(candidate: &Value) -> bool {
    if candidate["planner_status"].as_str() != Some("admitted") {
        return false;
    }
    let components = &candidate["runtimeComponents"];
    component_status_is_admitted(&components["underlayFactory"])
        && component_status_is_admitted(&components["streamWrapperFactory"])
        && component_status_is_admitted(&components["chainExecutor"])
        && generation_cache_contract_ready(&components["generationCache"])
        && component_status_is_admitted(&components["packetSessionManager"])
        && component_status_is_admitted(&components["probeExecutor"])
}

fn component_status_is_admitted(component: &Value) -> bool {
    component["status"].as_str() == Some("admitted")
}

fn generation_cache_contract_ready(component: &Value) -> bool {
    component["schemaVersion"].as_i64() == Some(1)
        && component["graphId"]
            .as_str()
            .is_some_and(|graph| !graph.is_empty())
        && component["owner"].as_str() == Some("resident-dataplane-runtime")
        && component["cacheScope"].as_str() == Some("graph-and-reload-generation")
        && component["cleanupPolicy"].as_str() == Some("drop-on-graph-diff-or-runtime-stop")
}

fn resident_matrix_candidate_report(
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
            "node_tag": &node.tag,
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

fn matrix_row_schemes(formal_matrix_handler: &str) -> &'static [&'static str] {
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
        _ => &[],
    }
}

fn sanitize_matrix_error(error: &str) -> String {
    if error.contains("://") {
        return "planner error contained a raw link and was redacted".to_owned();
    }
    error.to_owned()
}

fn resident_proxy_plan_summary_json(proxy: &plan::ResidentProxyPlan) -> Value {
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
        "node_tag": proxy.node_tag,
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

fn resident_proxy_group_plan_summary_json(group: &plan::ResidentProxyGroupPlan) -> Value {
    let mut summary = group
        .default_proxy_snapshot()
        .as_ref()
        .map(resident_proxy_plan_summary_json)
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
