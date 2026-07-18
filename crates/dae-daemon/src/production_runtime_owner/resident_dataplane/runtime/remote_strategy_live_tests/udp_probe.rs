use super::super::udp::RESIDENT_UDP_PROBE_PUBLIC_ERROR;
use super::*;

pub(crate) fn resident_live_adapter_udp_probe(
    config: &Config,
    target: std::net::SocketAddr,
    payload: &[u8],
    config_path: Option<&Path>,
    include_response_hex: bool,
) -> Value {
    let started = std::time::Instant::now();
    let node_shapes = plan::resident_node_link_shapes(config);
    let probe_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build();
    let owner_stop = ResidentStopSignal::shared();
    let owner_resources = ResidentRuntimeResourceConfig::from_config(config);
    let owner_runtime = start_hysteria2_owner_registry(
        0,
        Arc::clone(&owner_stop),
        owner_resources.tcp_flow_stack_bytes.value(),
    )
    .ok();
    let owner_registry = owner_runtime.as_ref().map(|(handle, _)| handle.clone());
    let tuic_owner_runtime = start_tuic_owner_registry(
        0,
        Arc::clone(&owner_stop),
        owner_resources.tcp_flow_stack_bytes.value(),
    )
    .ok();
    let tuic_owner_registry = tuic_owner_runtime
        .as_ref()
        .map(|(handle, _)| handle.clone());
    let juicity_owner_runtime = node_shapes
        .iter()
        .any(|node| node.scheme.eq_ignore_ascii_case("juicity"))
        .then(|| {
            start_juicity_owner_registry(
                0,
                Arc::clone(&owner_stop),
                owner_resources.tcp_flow_stack_bytes.value(),
            )
            .ok()
        })
        .flatten();
    let juicity_owner_registry = juicity_owner_runtime
        .as_ref()
        .map(|(handle, _)| handle.clone());
    let anytls_owner_runtime = node_shapes
        .iter()
        .any(|node| node.scheme.eq_ignore_ascii_case("anytls"))
        .then(|| {
            start_anytls_owner_registry(
                0,
                Arc::clone(&owner_stop),
                owner_resources.tcp_flow_stack_bytes.value(),
            )
            .ok()
        })
        .flatten();
    let anytls_owner_registry = anytls_owner_runtime
        .as_ref()
        .map(|(handle, _)| handle.clone());
    let rows = resident_live_adapter_matrix_entries()
        .iter()
        .map(|entry| {
            let schemes = matrix_row_schemes(entry.formal_matrix_handler);
            let candidates = node_shapes
                .iter()
                .filter(|node| schemes.iter().any(|scheme| *scheme == node.scheme))
                .collect::<Vec<_>>();
            let mut blocked = Vec::new();
            for node in &candidates {
                match plan::build_resident_proxy_plan_for_node(
                    config,
                    entry.formal_matrix_handler.to_owned(),
                    node.tag.clone(),
                    node.link.clone(),
                ) {
                    Ok(proxy) => {
                        let proxy = Arc::new(proxy);
                        let mut probe = match &probe_runtime {
                            Ok(runtime) => runtime.block_on(probe_resident_proxy_udp_async(
                                Arc::clone(&proxy),
                                target,
                                payload,
                                include_response_hex,
                                owner_registry.clone(),
                                tuic_owner_registry.clone(),
                                juicity_owner_registry.clone(),
                                anytls_owner_registry.clone(),
                            )),
                            Err(_) => json!({
                                "status": "fail",
                                "ok": false,
                                "protocol_closed": false,
                                "handler": resident_udp_proxy_handler_name(&proxy),
                                "request_len": payload.len(),
                                "response_len": 0,
                                "payload_match": false,
                                "elapsed_ms": started.elapsed().as_millis(),
                                "graphId": proxy.graph_id,
                                "reasonId": "udp-probe-runtime-unavailable",
                                "error": RESIDENT_UDP_PROBE_PUBLIC_ERROR,
                            }),
                        };
                        probe["formal_matrix_handler"] = json!(entry.formal_matrix_handler);
                        probe["node_tag"] = json!(safe_matrix_node_tag(&node.tag));
                        probe["node_tag_source"] = json!(matrix_node_tag_source(&node.tag));
                        probe["udp_live_adapter"] = json!(entry.udp_live_adapter);
                        probe["udp_semantics"] = json!(entry.udp_semantics);
                        probe["udp_path_ready"] = json!(entry.udp_path_ready());
                        return probe;
                    }
                    Err(err) => blocked.push(json!({
                        "node_tag": safe_matrix_node_tag(&node.tag),
                        "node_tag_source": matrix_node_tag_source(&node.tag),
                        "scheme": node.scheme,
                        "reasonId": "source-materialization-failed",
                        "error": sanitize_matrix_error(&err),
                    })),
                }
            }
            json!({
                "formal_matrix_handler": entry.formal_matrix_handler,
                "status": if candidates.is_empty() { "not-present" } else { "blocked" },
                "ok": false,
                "protocol_closed": false,
                "candidate_count": candidates.len(),
                "udp_live_adapter": entry.udp_live_adapter,
                "udp_semantics": entry.udp_semantics,
                "udp_path_ready": entry.udp_path_ready(),
                "blocked": blocked,
            })
        })
        .collect::<Vec<_>>();
    owner_stop.store(true, Ordering::Release);
    if let Some((_, thread)) = owner_runtime {
        let _ = thread.join();
    }
    if let Some((_, thread)) = tuic_owner_runtime {
        let _ = thread.join();
    }
    if let Some((_, thread)) = juicity_owner_runtime {
        let _ = thread.join();
    }
    if let Some((_, thread)) = anytls_owner_runtime {
        let _ = thread.join();
    }
    let pass_count = rows
        .iter()
        .filter(|row| row["status"].as_str() == Some("pass"))
        .count();
    let protocol_closed_count = rows
        .iter()
        .filter(|row| row["status"].as_str() == Some("protocol-closed"))
        .count();
    let failure_count = rows
        .iter()
        .filter(|row| row["ok"].as_bool() != Some(true))
        .count();
    let matrix = resident_live_adapter_matrix_contract();
    json!({
        "schema": "resident-live-adapter-udp-live",
        "schemaVersion": 2,
        "config": config_path.map(redacted_path_identity),
        "configPathRedacted": config_path.is_some(),
        "target": target.to_string(),
        "payload_len": payload.len(),
        "network_io_executed": true,
        "host_mutation_executed": false,
        "matrix_schema": matrix.schema,
        "row_count": rows.len(),
        "pass_count": pass_count,
        "protocol_closed_count": protocol_closed_count,
        "failure_count": failure_count,
        "matrix_pass": failure_count == 0 && rows.len() == matrix.entries.len(),
        "elapsed_ms": started.elapsed().as_millis(),
        "rows": rows,
    })
}
