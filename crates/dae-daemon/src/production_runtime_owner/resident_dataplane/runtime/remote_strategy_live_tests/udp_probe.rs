use super::*;
pub(crate) fn resident_live_adapter_udp_probe(
    config: &Config,
    target: std::net::SocketAddr,
    payload: &[u8],
    config_path: Option<&Path>,
) -> Value {
    let started = std::time::Instant::now();
    let node_shapes = plan::resident_node_link_shapes(config);
    let probe_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build();
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
                        let mut probe = match &probe_runtime {
                            Ok(runtime) => {
                                runtime.block_on(probe_resident_proxy_udp_async(&proxy, target, payload))
                            }
                            Err(err) => json!({
                                "status": "fail",
                                "ok": false,
                                "protocol_closed": false,
                                "handler": resident_udp_handler_name(&proxy.handler),
                                "request_len": payload.len(),
                                "response_len": 0,
                                "payload_match": false,
                                "elapsed_ms": started.elapsed().as_millis(),
                                "graphId": proxy.graph_id,
                                "error": format!("start Tokio UDP live adapter probe runtime: {err}"),
                            }),
                        };
                        probe["formal_matrix_handler"] = json!(entry.formal_matrix_handler);
                        probe["node_tag"] = json!(node.tag);
                        probe["udp_live_adapter"] = json!(entry.udp_live_adapter);
                        probe["udp_semantics"] = json!(entry.udp_semantics);
                        probe["udp_path_ready"] = json!(entry.udp_path_ready());
                        return probe;
                    }
                    Err(err) => blocked.push(json!({
                        "node_tag": node.tag,
                        "scheme": node.scheme,
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
        "config": config_path.map(path_string),
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
