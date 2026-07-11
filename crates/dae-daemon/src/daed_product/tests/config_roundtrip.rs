use super::support::FreshProductState;
use super::*;

#[test]
fn unchanged_parsed_global_round_trips_through_production_parser() {
    let fixture = FreshProductState::new("parsed-global-roundtrip");
    fixture.seed_selected_resources();
    let resource = get_section_value(fixture.state(), SectionKind::Config, 1)
        .unwrap()
        .unwrap();
    let rendered = section_request_value(
        SectionKind::Config,
        &json!({"parsedGlobal": resource["parsedGlobal"].clone()}),
    );
    let complete = format!("{rendered}\nrouting {{ fallback: direct }}\n");

    build_runtime_config_from_content(&complete)
        .expect("unchanged parsedGlobal must remain valid for production reload");
}

#[test]
fn parsed_global_preserves_every_supported_value_category() {
    let global = r#"
global {
  tproxy_port:'12345'
  tproxy_port_protect:'false'
  so_mark_from_dae:'7'
  log_level:'debug'
  tcp_check_url:'http://localhost,127.0.0.1'
  tcp_check_http_method:'GET'
  udp_check_dns:'localhost:53,[::1]:53'
  check_interval:'31s'
  check_tolerance:'250ms'
  udp_endpoint_pool_size:'2048'
  lan_interface:'lan0,lan1'
  wan_interface:'auto,wan0'
  allow_insecure:'false'
  dial_mode:'domain++'
  disable_waiting_network:'true'
  enable_local_tcp_fast_redirect:'true'
  auto_config_kernel_parameter:'true'
  auto_config_firewall_rule:'false'
  sniffing_timeout:'150ms'
  tls_implementation:'tls'
  utls_imitate:'chrome_auto'
  tls_fragment:'true'
  tls_fragment_length:'50-100'
  tls_fragment_interval:'10-20'
  pprof_port:'0'
  mptcp:'false'
  fallback_resolver:'127.0.0.1:53'
  bandwidth_max_tx:'200 mbps'
  bandwidth_max_rx:'1 gbps'
  udphop_interval:'20s'
  resident_udp_session_limit:'256'
  resident_udp_session_queue_depth:'64'
  resident_tcp_flow_stack_bytes:'1048576'
  resident_tcp_runtime_workers:'3'
  resident_tcp_connection_limit:'768'
  resident_dns_upstream_refresh_seconds:'45'
  resident_event_queue_depth:'8192'
  resident_manual_probe_concurrency:'12'
  resident_tcp_probe_timeout_ms:'5000'
  resident_health_check_concurrency:'4'
  http_queue:'512'
  http_workers:'6'
  http_worker_stack_bytes:'1048576'
  allocator_idle_reclaim_enabled:'false'
  allocator_idle_reclaim_sample_interval:'2m'
  allocator_idle_reclaim_min_interval:'10m'
  allocator_idle_reclaim_low_traffic_duration:'5m'
  allocator_idle_reclaim_pressure_threshold_bytes:'67108864'
  allocator_idle_reclaim_max_traffic_rate_bytes_per_second:'65536'
}
"#;
    let original =
        build_runtime_config_from_content(&format!("{global}\nrouting {{ fallback: direct }}\n"))
            .unwrap();
    let parsed = normalize_global_value(Some(global));
    let rendered = render_global_config_text(&parsed);
    let round_tripped =
        build_runtime_config_from_content(&format!("{rendered}\nrouting {{ fallback: direct }}\n"))
            .unwrap();

    assert_eq!(round_tripped.global, original.global);
}

#[test]
fn invalid_parsed_global_does_not_mutate_existing_resource() {
    let fixture = FreshProductState::new("parsed-global-invalid");
    fixture.seed_selected_resources();
    let request = HttpRequest {
        method: "PUT".to_owned(),
        path: "/api/configs/1".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: serde_json::to_vec(&json!({
            "name": "must-not-commit",
            "parsedGlobal": {"checkInterval": "not-a-duration"}
        }))
        .unwrap(),
    };

    let response = update_section(fixture.state(), &request, SectionKind::Config, 1);
    assert_eq!(response.status, 400);
    let stored = fixture
        .connection()
        .query_row("SELECT name, global FROM configs WHERE id = 1", [], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap();
    assert_eq!(
        stored,
        ("fixture-global".to_owned(), "global {}".to_owned())
    );
}
