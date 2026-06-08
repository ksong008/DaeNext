#[cfg(test)]
mod remote_strategy_live_tests {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    use std::thread;
    use std::time::Duration;

    use dae_config::Config;

    use super::*;

    struct LiveHttpProxy {
        port: u16,
        delay_ms: Arc<AtomicU64>,
    }

    impl LiveHttpProxy {
        fn set_delay_ms(&self, delay_ms: u64) {
            self.delay_ms.store(delay_ms, Ordering::Relaxed);
        }
    }

    #[test]
    fn remote_resident_group_strategy_matrix_uses_live_proxy_health_checks() {
        if std::env::var("DAE_REMOTE_STRATEGY_LIVE").as_deref() != Ok("1") {
            return;
        }

        let check_server = start_live_http_check_server();
        let node_a = start_live_http_proxy(140);
        let node_b = start_live_http_proxy(20);

        assert_strategy_selects(
            "fixed(0)",
            &format!(
                r#"
        filter: name(node_a, node_b)
        policy: fixed(0)
        "#
            ),
            &node_a,
            &node_b,
            check_server,
            "node_a",
        );
        assert_strategy_selects(
            "random",
            &format!(
                r#"
        filter: name(node_a, node_b)
        policy: random
        "#
            ),
            &node_a,
            &node_b,
            check_server,
            "any",
        );
        assert_strategy_selects(
            "min",
            &format!(
                r#"
        filter: name(node_a, node_b)
        policy: min
        "#
            ),
            &node_a,
            &node_b,
            check_server,
            "node_b",
        );
        assert_strategy_selects(
            "min_avg10",
            &format!(
                r#"
        filter: name(node_a, node_b)
        policy: min_avg10
        "#
            ),
            &node_a,
            &node_b,
            check_server,
            "node_b",
        );
        assert_strategy_selects(
            "min_moving_avg",
            &format!(
                r#"
        filter: name(node_a, node_b)
        policy: min_moving_avg
        "#
            ),
            &node_a,
            &node_b,
            check_server,
            "node_b",
        );
        assert_strategy_selects(
            "add_latency",
            &format!(
                r#"
        filter: name(node_a)
        filter: name(node_b) [add_latency: 250ms]
        policy: min
        "#
            ),
            &node_a,
            &node_b,
            check_server,
            "node_a",
        );

        node_a.set_delay_ms(140);
        node_b.set_delay_ms(110);
        let tolerance_config = live_strategy_config(
            &format!(
                r#"
        filter: name(node_a, node_b)
        policy: min
        check_tolerance: 80ms
        "#
            ),
            &node_a,
            &node_b,
            check_server,
        );
        let plan = build_resident_dataplane_plan(&tolerance_config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        let probes = group.probe_candidates();
        run_resident_group_health_checks(group, &probes);
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_a");
        node_b.set_delay_ms(20);
        run_resident_group_health_checks(group, &probes);
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
    }

    fn assert_strategy_selects(
        label: &str,
        group_body: &str,
        node_a: &LiveHttpProxy,
        node_b: &LiveHttpProxy,
        check_server: u16,
        expected: &str,
    ) {
        let config = live_strategy_config(group_body, node_a, node_b, check_server);
        let plan = build_resident_dataplane_plan(&config)
            .unwrap_or_else(|err| panic!("{label}: build plan: {err}"));
        let group = plan
            .default_proxy_group()
            .unwrap_or_else(|| panic!("{label}: missing default proxy group"));
        let probes = group.probe_candidates();
        run_resident_group_health_checks(group, &probes);
        if expected == "any" {
            let selected = group
                .select_proxy_for_tcp()
                .unwrap_or_else(|err| panic!("{label}: select tcp: {err}"));
            assert!(
                matches!(selected.node_tag.as_str(), "node_a" | "node_b"),
                "{label}: unexpected random selection {}",
                selected.node_tag
            );
            assert!(
                group
                    .latency_snapshots()
                    .iter()
                    .filter(|snapshot| snapshot.latency_ms.is_some())
                    .count()
                    >= 2,
                "{label}: expected live latency for both candidates"
            );
            return;
        }
        assert_eq!(
            group
                .select_proxy_for_tcp()
                .unwrap_or_else(|err| panic!("{label}: select tcp: {err}"))
                .node_tag,
            expected,
            "{label}: selected node"
        );
    }

    fn live_strategy_config(
        group_body: &str,
        node_a: &LiveHttpProxy,
        node_b: &LiveHttpProxy,
        check_server: u16,
    ) -> Config {
        let input = format!(
            r#"
        global {{
        lan_interface: daerust0
        tcp_check_url: 'http://127.0.0.1:{check_server}/generate_204,127.0.0.1'
        udp_check_dns: '127.0.0.1:53,127.0.0.1'
        check_interval: 1s
        }}
        node {{
        node_a: 'http://127.0.0.1:{node_a_port}'
        node_b: 'http://127.0.0.1:{node_b_port}'
        }}
        group {{
        proxy {{
        {group_body}
        }}
        }}
        routing {{
        l4proto(tcp) -> proxy
        fallback: direct
        }}
        "#,
            node_a_port = node_a.port,
            node_b_port = node_b.port,
        );
        let sections = dae_config::parser::parse_config(&input)
            .unwrap_or_else(|err| panic!("parse live strategy config: {err}"));
        dae_config::schema::build_config(&sections)
            .unwrap_or_else(|err| panic!("build live strategy config: {err}"))
    }

    fn start_live_http_check_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || handle_live_http_check(stream));
            }
        });
        port
    }

    fn handle_live_http_check(mut stream: TcpStream) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = read_headers(&mut stream);
        let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
        let _ = stream.flush();
        let _ = stream.shutdown(Shutdown::Both);
    }

    fn start_live_http_proxy(delay_ms: u64) -> LiveHttpProxy {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let delay_ms = Arc::new(AtomicU64::new(delay_ms));
        let delay_for_thread = Arc::clone(&delay_ms);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let delay_ms = Arc::clone(&delay_for_thread);
                thread::spawn(move || handle_live_http_proxy(stream, delay_ms));
            }
        });
        LiveHttpProxy { port, delay_ms }
    }

    fn handle_live_http_proxy(mut inbound: TcpStream, delay_ms: Arc<AtomicU64>) {
        let _ = inbound.set_read_timeout(Some(Duration::from_secs(5)));
        let request = match read_headers(&mut inbound) {
            Ok(request) => request,
            Err(_) => return,
        };
        let Some(target) = connect_target_from_request(&request) else {
            let _ = inbound.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            return;
        };
        thread::sleep(Duration::from_millis(delay_ms.load(Ordering::Relaxed)));
        let mut outbound = match TcpStream::connect(target) {
            Ok(outbound) => outbound,
            Err(_) => {
                let _ = inbound.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                return;
            }
        };
        let _ = outbound.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = inbound.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
        let _ = inbound.flush();
        let mut inbound_reader = match inbound.try_clone() {
            Ok(stream) => stream,
            Err(_) => return,
        };
        let mut outbound_writer = match outbound.try_clone() {
            Ok(stream) => stream,
            Err(_) => return,
        };
        let upload = thread::spawn(move || {
            let _ = std::io::copy(&mut inbound_reader, &mut outbound_writer);
            let _ = outbound_writer.shutdown(Shutdown::Write);
        });
        let _ = std::io::copy(&mut outbound, &mut inbound);
        let _ = inbound.shutdown(Shutdown::Write);
        let _ = upload.join();
    }

    fn read_headers(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        let mut request = Vec::new();
        let mut buf = [0_u8; 256];
        while request.len() < 8192 {
            let read = stream.read(&mut buf)?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buf[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        Ok(request)
    }

    fn connect_target_from_request(request: &[u8]) -> Option<String> {
        let text = String::from_utf8_lossy(request);
        let mut first_line = text.lines().next()?.split_whitespace();
        let method = first_line.next()?;
        let target = first_line.next()?;
        if method.eq_ignore_ascii_case("CONNECT") && !target.is_empty() {
            Some(target.to_owned())
        } else {
            None
        }
    }
}

pub(crate) fn resident_live_adapter_config_assessment(
    config: &Config,
    config_path: Option<&Path>,
) -> Value {
    let matrix = resident_live_adapter_matrix_contract();
    let live_evidence = resident_live_matrix_evidence_from_env();
    let node_shapes = plan::resident_node_link_shapes(config);
    let matrix_entries = resident_live_adapter_matrix_entries()
        .iter()
        .map(|entry| {
            let remote_live_matrix =
                resident_live_adapter_entry_remote_live_matrix_ready(entry, &live_evidence);
            let missing = resident_live_adapter_entry_missing(entry, &live_evidence);
            json!({
                "handler": entry.handler,
                "formal_matrix_handler": entry.formal_matrix_handler,
                "udp_semantics": entry.udp_semantics,
                "udp_path_ready": entry.udp_path_ready(),
                "wired_ready": entry.wired_ready(),
                "remote_live_matrix": remote_live_matrix,
                "live_ready": entry.wired_ready() && remote_live_matrix && missing.is_empty(),
                "missing": missing,
            })
        })
        .collect::<Vec<_>>();
    let full_matrix_rows = resident_full_matrix_config_rows(config, &node_shapes);
    let full_matrix_present_rows = full_matrix_rows
        .iter()
        .filter(|row| row["candidate_count"].as_u64().unwrap_or(0) > 0)
        .count();
    let full_matrix_admitted_rows = full_matrix_rows
        .iter()
        .filter(|row| row["planner_status"].as_str() == Some("admitted"))
        .count();
    let source_shape_registry = source_shape_registry_contract();
    let expanded_source_matrix_rows =
        resident_expanded_source_matrix_rows(config, &node_shapes, &full_matrix_rows);
    let expanded_source_matrix_status_counts =
        resident_matrix_status_counts(&expanded_source_matrix_rows);
    let expanded_source_matrix_complete = false;
    let matrix_scope = "current-config-formal-handler-matrix";
    let matrix_scope_contract = json!({
        "schemaVersion": 1,
        "scope": matrix_scope,
        "currentConfigMatrixOpen": true,
        "currentAdmittedBaselineOpen": true,
        "sourceShapeRegistryOpen": source_shape_registry.source_shape_registry_open,
        "expandedSourceMatrixOpen": source_shape_registry.expanded_source_matrix_open,
        "expandedSourceMatrixComplete": expanded_source_matrix_complete,
        "currentConfigRows": full_matrix_rows.len(),
        "currentConfigPresentRows": full_matrix_present_rows,
        "currentConfigAdmittedRows": full_matrix_admitted_rows,
        "formalHandlerRows": resident_live_adapter_matrix_entries().len(),
        "releaseGateMayUseAsSourceMatrix": false,
        "c10MayUseAsExpandedSourceMatrix": false,
    });
    let mut report = json!({
        "schema": "resident-live-adapter-config-assessment",
        "config": config_path.map(path_string),
        "read_only": true,
        "host_mutation_executed": false,
        "network_io_executed": false,
        "live_traffic_executed": false,
        "matrix_schema": matrix.schema,
        "resident_live_adapter_matrix_ready": matrix.matrix_ready,
        "resident_live_adapter_wired_matrix_ready": matrix.wired_matrix_ready,
        "resident_live_adapter_remote_live_matrix_ready": matrix.remote_live_matrix_ready,
        "resident_live_adapter_remote_live_matrix_evidence": {
            "env": live_evidence.env,
            "source": live_evidence.source,
            "schema": live_evidence.schema,
            "schemaVersion": live_evidence.schema_version,
            "candidateSha256": live_evidence.candidate_sha256,
            "rowCount": live_evidence.row_count,
            "passCount": live_evidence.pass_count,
            "allPass": live_evidence.all_pass,
            "valid": live_evidence.valid,
            "readyHandlers": live_evidence.ready_handlers.iter().cloned().collect::<Vec<_>>(),
            "error": live_evidence.error,
        },
        "resident_live_adapter_entries": matrix_entries,
    });
    report["matrix_scope"] = json!(matrix_scope);
    report["current_config_matrix_open"] = json!(true);
    report["current_admitted_baseline_open"] = json!(true);
    report["source_shape_registry_open"] = json!(source_shape_registry.source_shape_registry_open);
    report["expanded_source_matrix_open"] =
        json!(source_shape_registry.expanded_source_matrix_open);
    report["expanded_source_matrix_complete"] = json!(expanded_source_matrix_complete);
    report["matrix_scope_contract"] = matrix_scope_contract;
    report["full_matrix_open"] = json!(true);
    report["full_matrix_scope"] = json!(matrix_scope);
    report["full_matrix_is_expanded_source_matrix"] = json!(false);
    report["full_matrix_release_gate_source_ready"] = json!(false);
    report["full_matrix_c10_expanded_source_ready"] = json!(false);
    report["full_matrix_row_count"] = json!(full_matrix_rows.len());
    report["full_matrix_present_row_count"] = json!(full_matrix_present_rows);
    report["full_matrix_admitted_row_count"] = json!(full_matrix_admitted_rows);
    report["full_matrix_complete"] = json!(matrix.matrix_ready);
    report["full_matrix_completion_blocker"] = if matrix.matrix_ready {
        Value::Null
    } else {
        json!(
            "real live traffic evidence is required before the resident live adapter matrix can be complete"
        )
    };
    report["source_shape_registry_schema"] = json!(source_shape_registry.schema);
    report["source_shape_registry_schema_version"] = json!(source_shape_registry.schema_version);
    report["source_shape_registry_row_count"] = json!(source_shape_registry.rows.len());
    report["source_shape_registry_contract"] = source_shape_registry.to_value();
    report["expanded_source_matrix_row_count"] = json!(expanded_source_matrix_rows.len());
    report["expanded_source_matrix_status_counts"] = expanded_source_matrix_status_counts;
    report["expanded_source_matrix_release_gate_ready"] = json!(false);
    report["expanded_source_matrix_c10_ready"] = json!(false);
    report["source_matrix_completion_blocker"] = json!(
        "expanded source matrix has fail-closed rows and requires live host, benchmark, and rollback evidence"
    );
    report["expanded_source_matrix_rows"] = json!(expanded_source_matrix_rows);
    report["full_matrix_rows"] = json!(full_matrix_rows);

    match build_resident_dataplane_plan(config) {
        Ok(plan) if plan.enabled => {
            let proxies = plan
                .proxies
                .iter()
                .map(|(outbound, group)| {
                    let mut summary = resident_proxy_group_plan_summary_json(group);
                    summary["outbound_index"] = json!(outbound);
                    summary
                })
                .collect::<Vec<_>>();
            let default_proxy = plan
                .default_proxy_snapshot()
                .as_ref()
                .map(resident_proxy_plan_summary_json)
                .unwrap_or(Value::Null);
            let default_group = plan
                .default_proxy_group()
                .map(resident_proxy_group_plan_summary_json)
                .unwrap_or(Value::Null);
            report["status"] = json!("admitted");
            report["planner_admitted"] = json!(true);
            report["selected_node_fail_closed"] = json!(true);
            report["resident_dataplane_enabled_by_config"] = json!(true);
            report["proxy_count"] = json!(plan.proxies.len());
            report["tcp_dial_mode"] = json!(plan.tcp_dial_mode.as_str());
            report["tcp_sniffing_timeout"] = json!(format!("{:?}", plan.sniffing_timeout));
            report["default_proxy"] = default_proxy;
            report["default_group"] = default_group;
            report["proxies"] = json!(proxies);
            report["blockers"] =
                json!(["remote live traffic matrix not executed by this read-only assessment"]);
        }
        Ok(plan) => {
            report["status"] = json!("not-applicable");
            report["planner_admitted"] = json!(false);
            report["selected_node_fail_closed"] = json!(true);
            report["resident_dataplane_enabled_by_config"] = json!(false);
            report["proxy_count"] = json!(plan.proxies.len());
            report["unsupported_reason"] = json!(plan.unsupported_reason);
            report["blockers"] = json!(["no selected proxy plan was admitted"]);
        }
        Err(err) => {
            report["status"] = json!("blocked");
            report["planner_admitted"] = json!(false);
            report["selected_node_fail_closed"] = json!(true);
            report["resident_dataplane_enabled_by_config"] = json!(false);
            report["planner_error"] = json!(err);
            report["blockers"] =
                json!(["selected node shape is not admitted by the live resident adapter"]);
        }
    }
    report
}

pub(crate) fn resident_live_adapter_udp_probe(
    config: &Config,
    target: SocketAddrV4,
    payload: &[u8],
    config_path: Option<&Path>,
) -> Value {
    let started = std::time::Instant::now();
    let node_shapes = plan::resident_node_link_shapes(config);
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
                        let mut probe = probe_resident_proxy_udp(&proxy, target, payload);
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
