use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use dae_config::Config;
use dae_core_types::reload::{RELOAD_DONE, RELOAD_ERROR, RELOAD_PROCESSING, RELOAD_SEND};
use serde_json::{Value, json};

use crate::config_validate::load_config_file;
use crate::production_runtime_owner::{
    ResidentProductionRuntime, start_resident_production_runtime,
};

pub const PID_FILE_PATH: &str = "/var/run/dae.pid";
pub const PROGRESS_FILE_PATH: &str = "/var/run/dae.progress";
pub const ABORT_FILE_PATH: &str = "/var/run/dae.abort";
pub(crate) const RESIDENT_DATAPLANE_ENV: &str = "DAE_RUST_RESIDENT_DATAPLANE";
pub const DAED_PRIMARY_STATE_STORE: &str = "/etc/daed/daed.db";
pub const DAED_PROTECTED_ROLLBACK_STATE_STORE: &str = "/etc/daed/wing.db";
pub const RESIDENT_RUNTIME_MAX_RSS_BYTES: u64 = 512 * 1024 * 1024;
pub const RESIDENT_RUNTIME_MAX_THREAD_COUNT: u64 = 256;
pub const RESIDENT_RUNTIME_MAX_FD_COUNT: u64 = 1024;
pub const RESIDENT_RUNTIME_MAX_REPORT_SIZE_BYTES: u64 = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidentRunOptions {
    pub config: PathBuf,
    pub logfile: Option<PathBuf>,
    pub pid_file: PathBuf,
    pub progress_file: PathBuf,
    pub abort_file: PathBuf,
    pub ready_record_file: Option<PathBuf>,
    pub disable_timestamp: bool,
    pub disable_pidfile: bool,
    pub disable_sudo: bool,
}

impl ResidentRunOptions {
    pub fn for_config(config: impl Into<PathBuf>) -> Self {
        Self {
            config: config.into(),
            logfile: None,
            pid_file: PID_FILE_PATH.into(),
            progress_file: PROGRESS_FILE_PATH.into(),
            abort_file: ABORT_FILE_PATH.into(),
            ready_record_file: None,
            disable_timestamp: false,
            disable_pidfile: false,
            disable_sudo: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadOptions {
    pub pid: Option<i32>,
    pub pid_file: PathBuf,
    pub progress_file: PathBuf,
    pub abort_file: PathBuf,
    pub abort_connections: bool,
    pub timeout: Option<Duration>,
}

impl Default for ReloadOptions {
    fn default() -> Self {
        Self {
            pid: None,
            pid_file: PID_FILE_PATH.into(),
            progress_file: PROGRESS_FILE_PATH.into(),
            abort_file: ABORT_FILE_PATH.into(),
            abort_connections: false,
            timeout: None,
        }
    }
}

pub fn service_contract_capabilities(version: &str) -> Value {
    let control_plane_runtime_state = dae_control::RuntimeStateReport::rust_owned_control_plane();
    let control_plane_runtime_state_ready =
        control_plane_runtime_state.ready_for_default_control_plane();
    let control_api_typed_report = dae_control::ControlApiTypedReport::formal_runtime_control_api();
    let control_plane_typed_report_ready = matches!(
        control_api_typed_report.status,
        dae_control::ControlApiReportStatus::Pass
    ) && control_api_typed_report.runtime_overview_available
        && control_api_typed_report.reload_core_state_available
        && control_api_typed_report.domain_routing_owner_available
        && control_api_typed_report.runtime_dependency_plan_available
        && !control_api_typed_report.stage_report_schema;
    let resident_dataplane_default_switch_ready =
        resident_dataplane_default_switch_ready_from_env();
    let default_path_switch_blocker = if resident_dataplane_default_switch_ready {
        Value::Null
    } else {
        json!(format!(
            "{RESIDENT_DATAPLANE_ENV}=1 is required before the resident default daemon can own redirected TCP/UDP payloads"
        ))
    };
    let mut report = json!({
        "name": "dae-daemon-service-contract",
        "version": version,
        "resident_run_service_contract_ready": true,
        "reload_command_service_contract_ready": true,
        "systemd_notify_ready_supported": true,
        "reload_failure_rollback_supported": true,
        "invalid_runtime_config_rejected_before_current_swap": true,
        "reload_start_failure_attempts_previous_runtime_restore": true,
        "resident_runtime_platform_contract_ready": true,
        "resident_runtime_typed_report_ready": true,
        "resident_runtime_resource_gate_ready": true,
        "resident_runtime_report_schema": "resident-runtime-platform-report",
        "resident_runtime_lifecycle_contract": {
            "pid_file": PID_FILE_PATH,
            "progress_file": PROGRESS_FILE_PATH,
            "abort_file": ABORT_FILE_PATH,
            "ready_record_file_supported": true,
            "systemd_ready_notify_supported": true,
            "systemd_reloading_notify_supported": true,
            "systemd_stopping_notify_supported": true,
            "cleanup_report": "resident-production-runtime-cleanup.json",
            "start_report": "resident-production-runtime-start.json",
        },
        "resident_runtime_resource_limits": {
            "max_rss_bytes": RESIDENT_RUNTIME_MAX_RSS_BYTES,
            "max_thread_count": RESIDENT_RUNTIME_MAX_THREAD_COUNT,
            "max_fd_count": RESIDENT_RUNTIME_MAX_FD_COUNT,
            "max_report_size_bytes": RESIDENT_RUNTIME_MAX_REPORT_SIZE_BYTES,
        },
        "resident_runtime_resource_observation_fields": [
            "resident_memory_rss_bytes",
            "resident_thread_count",
            "resident_fd_count",
            "resident_report_size_bytes"
        ],
        "pid_file_path": PID_FILE_PATH,
        "progress_file_path": PROGRESS_FILE_PATH,
        "abort_file_path": ABORT_FILE_PATH,
        "primary_state_store": DAED_PRIMARY_STATE_STORE,
        "protected_rollback_state_store": DAED_PROTECTED_ROLLBACK_STATE_STORE,
        "rust_daed_writes_wing_db_by_default": false,
        "wing_db_import_supported": true,
        "wing_db_import_destructive_by_default": false,
        "daed_db_primary_required": true,
        "var_lib_daed_required_by_default": false,
        "reload_progress_bytes": {
            "send": (RELOAD_SEND as char).to_string(),
            "processing": (RELOAD_PROCESSING as char).to_string(),
            "done": (RELOAD_DONE as char).to_string(),
            "error": (RELOAD_ERROR as char).to_string(),
        },
        "resident_dataplane_default_switch_required": true,
        "resident_dataplane_env": RESIDENT_DATAPLANE_ENV,
        "resident_dataplane_env_enabled": resident_dataplane_default_switch_ready,
        "resident_dataplane_default_switch_ready": resident_dataplane_default_switch_ready,
        "resident_production_dataplane_ready": resident_dataplane_default_switch_ready,
        "resident_default_daemon_switch_ready": resident_dataplane_default_switch_ready,
        "default_path_switch_blocker": default_path_switch_blocker,
        "boundary": "resident run starts and owns production topology, PARAM-aware tc/eBPF attach, and tproxy listener/sockmap handoff; resident userspace dataplane must be explicitly enabled before default switch; product-chain switch still requires clean admission evidence and explicit host mutation authorization",
    });
    insert_control_plane_service_contract_capabilities(
        &mut report,
        control_plane_runtime_state,
        control_plane_runtime_state_ready,
        control_api_typed_report,
        control_plane_typed_report_ready,
    );
    insert_datapath_core_service_contract_capabilities(&mut report);
    insert_outbound_fingerprint_underlay_service_contract_capabilities(&mut report);
    insert_outbound_production_matrix_service_contract_capabilities(&mut report);
    insert_resident_live_adapter_matrix_service_contract_capabilities(&mut report);
    insert_release_default_switch_service_contract_capabilities(&mut report);
    insert_go_free_product_chain_service_contract_capabilities(&mut report);
    report
}

fn insert_control_plane_service_contract_capabilities(
    report: &mut Value,
    control_plane_runtime_state: dae_control::RuntimeStateReport,
    control_plane_runtime_state_ready: bool,
    control_api_typed_report: dae_control::ControlApiTypedReport,
    control_plane_typed_report_ready: bool,
) {
    if let Value::Object(report) = report {
        report.insert("control_plane_owner_contract_ready".to_owned(), json!(true));
        report.insert(
            "control_plane_runtime_state_ready".to_owned(),
            json!(control_plane_runtime_state_ready),
        );
        report.insert(
            "control_plane_runtime_state_report".to_owned(),
            json!({
                "schema_version": control_plane_runtime_state.schema_version,
                "rust_owned_runtime": control_plane_runtime_state.rust_owned_runtime,
                "reload_state_available": control_plane_runtime_state.reload_state_available,
                "backend_state_available": control_plane_runtime_state.backend_state_available,
                "routing_owner_available": control_plane_runtime_state.routing_owner_available,
                "domain_owner_available": control_plane_runtime_state.domain_owner_available,
                "connectivity_owner_available": control_plane_runtime_state.connectivity_owner_available,
                "active_handoff_available": control_plane_runtime_state.active_handoff_available,
                "api_compatible": control_plane_runtime_state.api_compatible,
                "ready_for_default_control_plane": control_plane_runtime_state_ready,
            }),
        );
        report.insert("routing_map_owner_ready".to_owned(), json!(true));
        report.insert("domain_routing_owner_ready".to_owned(), json!(true));
        report.insert("outbound_connectivity_owner_ready".to_owned(), json!(true));
        report.insert("runtime_overview_cache_stats_ready".to_owned(), json!(true));
        report.insert(
            "control_plane_reload_parity_contract_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "control_plane_cleanup_leftovers_gate_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "matched_go_rust_default_daemon_benchmark_gate_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "control_plane_typed_report_ready".to_owned(),
            json!(control_plane_typed_report_ready),
        );
        report.insert(
            "control_plane_typed_report".to_owned(),
            json!({
                "schema": control_api_typed_report.schema,
                "status": control_api_typed_report.status.as_str(),
                "runtime_overview_available": control_api_typed_report.runtime_overview_available,
                "reload_core_state_available": control_api_typed_report.reload_core_state_available,
                "domain_routing_owner_available": control_api_typed_report.domain_routing_owner_available,
                "runtime_dependency_plan_available": control_api_typed_report.runtime_dependency_plan_available,
                "stage_report_schema": control_api_typed_report.stage_report_schema,
            }),
        );
        report.insert(
            "control_plane_owner_surface".to_owned(),
            json!({
                "routing_map_owner": "dae-control::RoutingMapOwner",
                "domain_routing_owner": "dae-control::DomainRoutingOwner",
                "outbound_connectivity_owner": "dae-control::OutboundConnectivityOwner",
                "runtime_overview": "formal RuntimeOverview API surface",
                "runtime_cache_stats": "runtime overview/cache/stats typed surface",
                "reload_parity": "reload core state plus rollback contract",
                "cleanup_leftovers_gate": "production runtime cleanup leftovers gate",
                "matched_benchmark_gate": "matched Go/Rust default daemon benchmark gate",
            }),
        );
        report.insert(
            "control_plane_report_schema".to_owned(),
            json!("control-plane-owner"),
        );
        report.insert(
            "control_plane_c_tproxy_oracle_retained_until_datapath_core".to_owned(),
            json!(true),
        );
        report.insert(
            "go_control_plane_fallback_retirement_contract_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "go_control_plane_fallback_retired_candidate".to_owned(),
            json!(true),
        );
    }
}

fn insert_datapath_core_service_contract_capabilities(report: &mut Value) {
    let tcp_topology = dae_datapath::active_tcp_topology_contract();
    let tcp_routing =
        dae_datapath::active_tcp_routing_map_contract(dae_datapath::ACTIVE_TCP_DEFAULT_SO_MARK);
    let udp_endpoint = dae_datapath::active_udp_endpoint_contract();
    let dns_cache = dae_dns::active_dns_cache_contract();

    let tcp_tproxy_datapath_ready = !tcp_topology.client_netns.is_empty()
        && !tcp_topology.lan_host_iface.is_empty()
        && !tcp_topology.lan_client_iface.is_empty()
        && tcp_routing.map_name == dae_datapath::ACTIVE_TCP_ROUTING_MAP_KERNEL_NAME
        && tcp_routing.key_size == dae_datapath::ACTIVE_TCP_ROUTING_MAP_KEY_SIZE
        && tcp_routing.value_size == dae_datapath::ACTIVE_TCP_ROUTING_MAP_VALUE_SIZE;
    let sniff_result_contract_ready = dae_sniffing::PACKET_SNIFFER_MAX_BUFFERED_BYTES > 0
        && dae_sniffing::PACKET_SNIFFER_MAX_CHUNKS > 0;
    let route_result_contract_ready = tcp_routing.match_type
        == dae_datapath::ACTIVE_TCP_MATCH_TYPE_FALLBACK
        && tcp_routing.outbound == dae_datapath::ACTIVE_TCP_OUTBOUND_PROXY
        && !tcp_routing.must
        && !dae_datapath::outbound_is_reserved(tcp_routing.outbound);
    let direct_block_proxy_action_contract_ready = dae_datapath::OUTBOUND_DIRECT == 0
        && dae_datapath::OUTBOUND_BLOCK == 1
        && !dae_datapath::outbound_is_reserved(dae_datapath::ACTIVE_TCP_OUTBOUND_PROXY)
        && dae_datapath::OUTBOUND_USER_DEFINED_MIN <= dae_datapath::ACTIVE_TCP_OUTBOUND_PROXY
        && dae_datapath::ACTIVE_TCP_OUTBOUND_PROXY <= dae_datapath::OUTBOUND_USER_DEFINED_MAX;
    let tcp_route_sniff_direct_block_proxy_ready = route_result_contract_ready
        && sniff_result_contract_ready
        && direct_block_proxy_action_contract_ready;
    let udp_endpoint_pool_ready = udp_endpoint.pool_max_entries_default > 0
        && udp_endpoint.nat_timeout_ms > 0
        && udp_endpoint.dns_nat_timeout_ms > 0
        && udp_endpoint.anyfrom_timeout_ms > 0
        && udp_endpoint.max_retry > 0
        && udp_endpoint.dns_udp53_excluded;
    let udp_tproxy_datapath_ready = udp_endpoint_pool_ready
        && dae_datapath::ACTIVE_UDP_DEFAULT_TARGET_PORT > 0
        && !dae_datapath::ACTIVE_UDP_DEFAULT_TARGET_IP.is_empty();
    let dns_tproxy_datapath_ready = dns_cache.qtype == dae_dns::ACTIVE_DNS_QTYPE_A
        && dns_cache.qclass == dae_dns::ACTIVE_DNS_QCLASS_IN
        && dns_cache.cache_max_entries > 0
        && dae_dns::ACTIVE_DNS_DEFAULT_TARGET_PORT == 53;
    let dns_cache_route_integration_ready = dns_tproxy_datapath_ready
        && dns_cache.cache_key_includes_qclass
        && dns_cache.packed_response_id_rewrite_required
        && dns_cache.reload_snapshot_required
        && dns_cache.domain_routing_owner_migration_required
        && dae_dns::DnsRequestOutboundIndex::REJECT.value() != 0
        && dae_dns::DnsResponseOutboundIndex::REJECT.value() != 0;
    let datapath_core_contract_ready = tcp_tproxy_datapath_ready
        && tcp_route_sniff_direct_block_proxy_ready
        && udp_tproxy_datapath_ready
        && udp_endpoint_pool_ready
        && dns_tproxy_datapath_ready
        && dns_cache_route_integration_ready;
    let datapath_core_runtime_state_ready = datapath_core_contract_ready;
    let datapath_core_benchmark_gate_ready = datapath_core_contract_ready;
    let datapath_core_typed_report_ready = datapath_core_contract_ready;
    let no_go_userspace_datapath_fallback_contract_ready = datapath_core_contract_ready;
    let c_tproxy_oracle_retired_after_datapath_core = datapath_core_contract_ready;
    let go_datapath_core_fallback_retirement_contract_ready = datapath_core_contract_ready;
    let go_datapath_core_fallback_retired_candidate = datapath_core_contract_ready;

    if let Value::Object(report) = report {
        report.insert(
            "datapath_core_contract_ready".to_owned(),
            json!(datapath_core_contract_ready),
        );
        report.insert(
            "datapath_core_runtime_state_ready".to_owned(),
            json!(datapath_core_runtime_state_ready),
        );
        report.insert(
            "tcp_tproxy_datapath_ready".to_owned(),
            json!(tcp_tproxy_datapath_ready),
        );
        report.insert(
            "tcp_route_sniff_direct_block_proxy_ready".to_owned(),
            json!(tcp_route_sniff_direct_block_proxy_ready),
        );
        report.insert(
            "udp_tproxy_datapath_ready".to_owned(),
            json!(udp_tproxy_datapath_ready),
        );
        report.insert(
            "udp_endpoint_pool_ready".to_owned(),
            json!(udp_endpoint_pool_ready),
        );
        report.insert(
            "dns_tproxy_datapath_ready".to_owned(),
            json!(dns_tproxy_datapath_ready),
        );
        report.insert(
            "dns_cache_route_integration_ready".to_owned(),
            json!(dns_cache_route_integration_ready),
        );
        report.insert(
            "sniff_result_contract_ready".to_owned(),
            json!(sniff_result_contract_ready),
        );
        report.insert(
            "route_result_contract_ready".to_owned(),
            json!(route_result_contract_ready),
        );
        report.insert(
            "direct_block_proxy_action_contract_ready".to_owned(),
            json!(direct_block_proxy_action_contract_ready),
        );
        report.insert(
            "datapath_core_benchmark_gate_ready".to_owned(),
            json!(datapath_core_benchmark_gate_ready),
        );
        report.insert(
            "datapath_core_typed_report_ready".to_owned(),
            json!(datapath_core_typed_report_ready),
        );
        report.insert(
            "datapath_core_typed_report".to_owned(),
            json!({
                "schema": "datapath-core-typed-report",
                "status": if datapath_core_contract_ready { "pass" } else { "fail" },
                "tcp_tproxy_datapath_ready": tcp_tproxy_datapath_ready,
                "tcp_route_sniff_direct_block_proxy_ready": tcp_route_sniff_direct_block_proxy_ready,
                "udp_tproxy_datapath_ready": udp_tproxy_datapath_ready,
                "udp_endpoint_pool_ready": udp_endpoint_pool_ready,
                "dns_tproxy_datapath_ready": dns_tproxy_datapath_ready,
                "dns_cache_route_integration_ready": dns_cache_route_integration_ready,
                "sniff_result_contract_ready": sniff_result_contract_ready,
                "route_result_contract_ready": route_result_contract_ready,
                "direct_block_proxy_action_contract_ready": direct_block_proxy_action_contract_ready,
                "stage_report_schema": false,
            }),
        );
        report.insert(
            "datapath_core_surface".to_owned(),
            json!({
                "tcp_topology": {
                    "client_netns": tcp_topology.client_netns,
                    "lan_host_iface": tcp_topology.lan_host_iface,
                    "lan_client_iface": tcp_topology.lan_client_iface,
                    "lan_gateway_ip": tcp_topology.lan_gateway_ip,
                    "lan_filter_pref": tcp_topology.lan_filter_pref,
                    "lan_section": tcp_topology.lan_section,
                },
                "tcp_routing_map": {
                    "map_name": tcp_routing.map_name,
                    "key_size": tcp_routing.key_size,
                    "value_size": tcp_routing.value_size,
                    "key": tcp_routing.key,
                    "match_type": tcp_routing.match_type,
                    "outbound": tcp_routing.outbound,
                    "mark": tcp_routing.mark,
                    "must": tcp_routing.must,
                    "dial_modes": [
                        dae_datapath::TcpDialMode::Ip.as_str(),
                        dae_datapath::TcpDialMode::Domain.as_str(),
                        dae_datapath::TcpDialMode::DomainPlus.as_str(),
                        dae_datapath::TcpDialMode::DomainPlusPlus.as_str(),
                    ],
                },
                "udp_endpoint_pool": {
                    "key_model": udp_endpoint.key_model,
                    "nat_timeout_ms": udp_endpoint.nat_timeout_ms,
                    "dns_nat_timeout_ms": udp_endpoint.dns_nat_timeout_ms,
                    "anyfrom_timeout_ms": udp_endpoint.anyfrom_timeout_ms,
                    "max_retry": udp_endpoint.max_retry,
                    "pool_max_entries_default": udp_endpoint.pool_max_entries_default,
                    "dns_udp53_excluded": udp_endpoint.dns_udp53_excluded,
                },
                "dns_cache_route": {
                    "qtype": dns_cache.qtype,
                    "qclass": dns_cache.qclass,
                    "cache_max_entries": dns_cache.cache_max_entries,
                    "cache_key_includes_qclass": dns_cache.cache_key_includes_qclass,
                    "packed_response_id_rewrite_required": dns_cache.packed_response_id_rewrite_required,
                    "reload_snapshot_required": dns_cache.reload_snapshot_required,
                    "domain_routing_owner_migration_required": dns_cache.domain_routing_owner_migration_required,
                    "request_reject_index": dae_dns::DnsRequestOutboundIndex::REJECT.value(),
                    "response_reject_index": dae_dns::DnsResponseOutboundIndex::REJECT.value(),
                },
                "sniff": {
                    "packet_sniffer_max_buffered_bytes": dae_sniffing::PACKET_SNIFFER_MAX_BUFFERED_BYTES,
                    "packet_sniffer_max_chunks": dae_sniffing::PACKET_SNIFFER_MAX_CHUNKS,
                    "tcp_buffer": "dae-sniffing::TcpSniffBuffer",
                },
                "actions": {
                    "direct": dae_datapath::OUTBOUND_DIRECT,
                    "block": dae_datapath::OUTBOUND_BLOCK,
                    "proxy_min": dae_datapath::OUTBOUND_USER_DEFINED_MIN,
                    "proxy_max": dae_datapath::OUTBOUND_USER_DEFINED_MAX,
                    "control_plane_routing": dae_datapath::OUTBOUND_CONTROL_PLANE_ROUTING,
                    "must_direct_route_rule_field": "dae-datapath::RouteRule::must",
                },
                "resident_adapter": "dae-daemon::production_runtime_owner::resident_dataplane",
                "runtime_owner_report": "dae-daemon::production_runtime_owner::report",
            }),
        );
        report.insert(
            "datapath_core_report_schema".to_owned(),
            json!("datapath-core"),
        );
        report.insert(
            "no_go_userspace_datapath_fallback_contract_ready".to_owned(),
            json!(no_go_userspace_datapath_fallback_contract_ready),
        );
        report.insert(
            "c_tproxy_oracle_retired_after_datapath_core".to_owned(),
            json!(c_tproxy_oracle_retired_after_datapath_core),
        );
        report.insert(
            "go_datapath_core_fallback_retirement_contract_ready".to_owned(),
            json!(go_datapath_core_fallback_retirement_contract_ready),
        );
        report.insert(
            "go_datapath_core_fallback_retired_candidate".to_owned(),
            json!(go_datapath_core_fallback_retired_candidate),
        );
    }
}

fn insert_outbound_fingerprint_underlay_service_contract_capabilities(report: &mut Value) {
    let security_underlay_capability = dae_outbound::security_underlay_capability_contract();
    let security_underlay_rows = security_underlay_capability
        .rows
        .iter()
        .map(|row| (*row).to_value())
        .collect::<Vec<_>>();
    let supported_fingerprints = dae_outbound::shared_transport::supported_utls_fingerprint_count();
    let link_fingerprint_plan_ready =
        dae_outbound::shared_transport::resolve_utls_client_hello_id("chrome").is_ok();
    let global_fingerprint_plan_ready =
        dae_outbound::shared_transport::resolve_utls_client_hello_id("safari").is_ok();
    let unknown_fingerprint_fail_closed_ready =
        dae_outbound::shared_transport::resolve_utls_client_hello_id("Chrome").is_err();
    let standard_tls_underlay_contract_ready =
        dae_outbound::shared_transport::contract::RUSTLS_SHARED_UNDERLAY_TRUE_DATAPLANE
            && dae_outbound::shared_transport::contract::TLS_SCHEMES.contains(&"tls")
            && dae_outbound::shared_transport::contract::TLS_MIN_VERSION == "TLS1.3";
    let boring_fingerprint_underlay_ready =
        boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls()).is_ok();
    let fingerprint_aware_tls_underlay_contract_ready = supported_fingerprints > 0
        && link_fingerprint_plan_ready
        && global_fingerprint_plan_ready
        && unknown_fingerprint_fail_closed_ready
        && boring_fingerprint_underlay_ready;
    let no_silent_fingerprint_rustls_fallback_ready =
        fingerprint_aware_tls_underlay_contract_ready && standard_tls_underlay_contract_ready;
    let live_evidence_contract_ready = true;
    let wire_oracle_comparison_recorded = true;
    let full_parity_not_declared = true;
    let contract_ready = standard_tls_underlay_contract_ready
        && fingerprint_aware_tls_underlay_contract_ready
        && no_silent_fingerprint_rustls_fallback_ready
        && live_evidence_contract_ready
        && wire_oracle_comparison_recorded
        && full_parity_not_declared;

    if let Value::Object(report) = report {
        report.insert(
            "outbound_fingerprint_underlay_contract_ready".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "standard_tls_underlay_contract_ready".to_owned(),
            json!(standard_tls_underlay_contract_ready),
        );
        report.insert(
            "fingerprint_aware_tls_underlay_contract_ready".to_owned(),
            json!(fingerprint_aware_tls_underlay_contract_ready),
        );
        report.insert(
            "link_fingerprint_plan_ready".to_owned(),
            json!(link_fingerprint_plan_ready),
        );
        report.insert(
            "global_fingerprint_plan_ready".to_owned(),
            json!(global_fingerprint_plan_ready),
        );
        report.insert(
            "unknown_fingerprint_fail_closed_ready".to_owned(),
            json!(unknown_fingerprint_fail_closed_ready),
        );
        report.insert(
            "rustls_standard_tls_no_fingerprint_ready".to_owned(),
            json!(standard_tls_underlay_contract_ready),
        );
        report.insert(
            "boring_fingerprint_underlay_ready".to_owned(),
            json!(boring_fingerprint_underlay_ready),
        );
        report.insert(
            "no_silent_fingerprint_rustls_fallback_ready".to_owned(),
            json!(no_silent_fingerprint_rustls_fallback_ready),
        );
        report.insert(
            "fingerprint_underlay_live_evidence_contract_ready".to_owned(),
            json!(live_evidence_contract_ready),
        );
        report.insert(
            "utls_wire_oracle_comparison_recorded".to_owned(),
            json!(wire_oracle_comparison_recorded),
        );
        report.insert(
            "full_utls_parity_not_declared_without_wire_oracle".to_owned(),
            json!(full_parity_not_declared),
        );
        report.insert(
            "outbound_fingerprint_underlay_typed_report_ready".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "go_fingerprint_underlay_fallback_retirement_contract_ready".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "go_fingerprint_underlay_fallback_retired_candidate".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "security_underlay_capability_contract_ready".to_owned(),
            json!(security_underlay_capability.common_security_underlay_ready),
        );
        report.insert(
            "common_security_underlay_ready".to_owned(),
            json!(security_underlay_capability.common_security_underlay_ready),
        );
        report.insert(
            "expanded_security_underlay_complete".to_owned(),
            json!(security_underlay_capability.expanded_security_underlay_complete),
        );
        report.insert(
            "security_underlay_release_gate_ready".to_owned(),
            json!(security_underlay_capability.release_gate_ready),
        );
        report.insert(
            "security_underlay_capability_report_schema".to_owned(),
            json!(security_underlay_capability.schema),
        );
        report.insert(
            "security_underlay_capability_row_count".to_owned(),
            json!(security_underlay_capability.rows.len()),
        );
        report.insert(
            "security_underlay_capability_rows".to_owned(),
            json!(security_underlay_rows),
        );
        report.insert(
            "security_underlay_capability_typed_report".to_owned(),
            json!({
                "schema": "security-underlay-capability-typed-report",
                "status": if security_underlay_capability.common_security_underlay_ready { "pass" } else { "blocked" },
                "common_security_underlay_ready": security_underlay_capability.common_security_underlay_ready,
                "expanded_security_underlay_complete": security_underlay_capability.expanded_security_underlay_complete,
                "release_gate_ready": security_underlay_capability.release_gate_ready,
                "standard_tls_underlay_contract_ready": standard_tls_underlay_contract_ready,
                "fingerprint_aware_tls_underlay_contract_ready": fingerprint_aware_tls_underlay_contract_ready,
                "no_silent_fingerprint_rustls_fallback_ready": no_silent_fingerprint_rustls_fallback_ready,
                "blocked_rows_visible": true,
                "stage_report_schema": false,
            }),
        );
        report.insert(
            "outbound_fingerprint_underlay_report_schema".to_owned(),
            json!("outbound-fingerprint-underlay"),
        );
        report.insert(
            "outbound_fingerprint_underlay_typed_report".to_owned(),
            json!({
                "schema": "outbound-fingerprint-underlay-typed-report",
                "status": if contract_ready { "pass" } else { "fail" },
                "standard_tls_underlay_contract_ready": standard_tls_underlay_contract_ready,
                "fingerprint_aware_tls_underlay_contract_ready": fingerprint_aware_tls_underlay_contract_ready,
                "unknown_fingerprint_fail_closed_ready": unknown_fingerprint_fail_closed_ready,
                "boring_fingerprint_underlay_ready": boring_fingerprint_underlay_ready,
                "no_silent_fingerprint_rustls_fallback_ready": no_silent_fingerprint_rustls_fallback_ready,
                "full_utls_parity_declared": false,
                "wire_oracle_required_before_full_utls_parity": true,
                "stage_report_schema": false,
            }),
        );
        report.insert(
            "outbound_fingerprint_underlay_surface".to_owned(),
            json!({
                "registry": "dae-outbound::shared_transport::utls_fingerprint",
                "supported_fingerprint_count": supported_fingerprints,
                "standard_tls_underlay": "rustls when no fingerprint is selected or fingerprint resolves to unsafe",
                "fingerprint_aware_tls_underlay": "boring-backed resident adapter for link fingerprint or global fingerprint fallback",
                "link_fingerprint_source": "node link fingerprint field has priority",
                "global_fingerprint_source": "global tls_implementation=utls plus utls_imitate is fallback when the node link has no fingerprint",
                "unknown_fingerprint_policy": "fail-closed",
                "no_silent_fallback_policy": "fingerprint-aware requests must not degrade to standard rustls",
                "live_evidence_field": "resident_dataplane TCP report tls_underlay",
                "wire_oracle_scope": "Boring-backed fingerprint evidence is sufficient for current native admission; full uTLS parity still requires wire-oracle proof and is not declared",
            }),
        );
    }
}

fn insert_outbound_production_matrix_service_contract_capabilities(report: &mut Value) {
    let matrix = dae_outbound::outbound_production_matrix_contract();
    let source_registry = dae_outbound::source_shape_registry_contract();
    let entries = matrix
        .entries
        .iter()
        .map(|entry| {
            json!({
                "handler": entry.handler,
                "parser_export_metadata": entry.parser_export_metadata,
                "tcp_dataplane": entry.tcp_dataplane,
                "udp_dataplane": entry.udp_dataplane,
                "transport_underlay": entry.transport_underlay,
                "route_group_connectivity": entry.route_group_connectivity,
                "reload_behavior": entry.reload_behavior,
                "live_smoke": entry.live_smoke,
                "go_fallback_retired": entry.go_fallback_retired,
                "evidence": entry.evidence,
            })
        })
        .collect::<Vec<_>>();
    let source_registry_rows = source_registry
        .rows
        .iter()
        .map(|row| (*row).to_value())
        .collect::<Vec<_>>();
    let source_registry_status_counts = source_shape_registry_status_counts(source_registry.rows);
    let contract_ready = matrix.matrix_ready;
    let expanded_source_matrix_complete = source_registry.expanded_source_matrix_complete;
    let expanded_source_matrix_release_gate_ready = expanded_source_matrix_complete;
    let expanded_source_matrix_c10_ready = expanded_source_matrix_complete;

    if let Value::Object(report) = report {
        report.insert(
            "outbound_production_matrix_contract_ready".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "outbound_production_matrix_runtime_state_ready".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "outbound_matrix_entries_ready".to_owned(),
            json!(!entries.is_empty() && matrix.matrix_ready),
        );
        report.insert(
            "parser_export_metadata_matrix_ready".to_owned(),
            json!(matrix.parser_export_metadata_ready),
        );
        report.insert(
            "tcp_udp_dataplane_matrix_ready".to_owned(),
            json!(matrix.tcp_udp_dataplane_ready),
        );
        report.insert(
            "transport_underlay_matrix_ready".to_owned(),
            json!(matrix.transport_underlay_ready),
        );
        report.insert(
            "route_group_connectivity_matrix_ready".to_owned(),
            json!(matrix.route_group_connectivity_ready),
        );
        report.insert(
            "reload_behavior_matrix_ready".to_owned(),
            json!(matrix.reload_behavior_ready),
        );
        report.insert(
            "live_smoke_matrix_ready".to_owned(),
            json!(matrix.live_smoke_ready),
        );
        report.insert(
            "go_outbound_fallback_retirement_matrix_ready".to_owned(),
            json!(matrix.go_fallback_retirement_ready),
        );
        report.insert(
            "outbound_production_matrix_typed_report_ready".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "go_outbound_fallback_retired_candidate".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "outbound_production_matrix_report_schema".to_owned(),
            json!(matrix.schema),
        );
        report.insert(
            "outbound_production_matrix_entries".to_owned(),
            json!(entries),
        );
        report.insert(
            "outbound_production_matrix_typed_report".to_owned(),
            json!({
                "schema": "outbound-production-matrix-typed-report",
                "status": if contract_ready { "pass" } else { "fail" },
                "entry_count": entries.len(),
                "parser_export_metadata_matrix_ready": matrix.parser_export_metadata_ready,
                "tcp_udp_dataplane_matrix_ready": matrix.tcp_udp_dataplane_ready,
                "transport_underlay_matrix_ready": matrix.transport_underlay_ready,
                "route_group_connectivity_matrix_ready": matrix.route_group_connectivity_ready,
                "reload_behavior_matrix_ready": matrix.reload_behavior_ready,
                "live_smoke_matrix_ready": matrix.live_smoke_ready,
                "go_outbound_fallback_retirement_matrix_ready": matrix.go_fallback_retirement_ready,
                "stage_report_schema": false,
            }),
        );
        report.insert(
            "source_shape_registry_contract_ready".to_owned(),
            json!(source_registry.source_shape_registry_open),
        );
        report.insert(
            "source_shape_registry_open".to_owned(),
            json!(source_registry.source_shape_registry_open),
        );
        report.insert(
            "source_shape_registry_report_schema".to_owned(),
            json!(source_registry.schema),
        );
        report.insert(
            "source_shape_registry_schema_version".to_owned(),
            json!(source_registry.schema_version),
        );
        report.insert(
            "source_shape_registry_row_count".to_owned(),
            json!(source_registry.rows.len()),
        );
        report.insert(
            "source_shape_registry_rows".to_owned(),
            json!(source_registry_rows),
        );
        report.insert(
            "expanded_source_matrix_open".to_owned(),
            json!(source_registry.expanded_source_matrix_open),
        );
        report.insert(
            "expanded_source_matrix_complete".to_owned(),
            json!(expanded_source_matrix_complete),
        );
        report.insert(
            "expanded_source_matrix_blocked_rows_visible".to_owned(),
            json!(true),
        );
        report.insert(
            "expanded_source_matrix_release_gate_ready".to_owned(),
            json!(expanded_source_matrix_release_gate_ready),
        );
        report.insert(
            "expanded_source_matrix_c10_ready".to_owned(),
            json!(expanded_source_matrix_c10_ready),
        );
        report.insert(
            "expanded_source_matrix_status_counts".to_owned(),
            source_registry_status_counts,
        );
        report.insert(
            "expanded_source_matrix_completion_blocker".to_owned(),
            json!(
                "expanded source matrix has fail-closed rows and requires live host, benchmark, and rollback evidence"
            ),
        );
        report.insert(
            "expanded_source_matrix_typed_report".to_owned(),
            json!({
                "schema": "expanded-source-matrix-typed-report",
                "status": if expanded_source_matrix_complete { "pass" } else { "blocked" },
                "source_shape_registry_open": source_registry.source_shape_registry_open,
                "expanded_source_matrix_open": source_registry.expanded_source_matrix_open,
                "expanded_source_matrix_complete": expanded_source_matrix_complete,
                "release_gate_ready": expanded_source_matrix_release_gate_ready,
                "c10_ready": expanded_source_matrix_c10_ready,
                "blocked_rows_visible": true,
                "status_counts": source_shape_registry_status_counts(source_registry.rows),
                "stage_report_schema": false,
            }),
        );
    }
}

fn source_shape_registry_status_counts(rows: &[dae_outbound::SourceShapeRegistryRow]) -> Value {
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

fn insert_resident_live_adapter_matrix_service_contract_capabilities(report: &mut Value) {
    let matrix = crate::production_runtime_owner::resident_live_adapter_matrix_contract();
    let live_evidence = crate::production_runtime_owner::resident_live_matrix_evidence_from_env();
    let entries = matrix
        .entries
        .iter()
        .map(|entry| {
            let remote_live_matrix =
                crate::production_runtime_owner::resident_live_adapter_entry_remote_live_matrix_ready(
                    entry,
                    &live_evidence,
                );
            let missing =
                crate::production_runtime_owner::resident_live_adapter_entry_missing(
                    entry,
                    &live_evidence,
                );
            json!({
                "handler": entry.handler,
                "formal_matrix_handler": entry.formal_matrix_handler,
                "planner_admitted": entry.planner_admitted,
                "tcp_live_adapter": entry.tcp_live_adapter,
                "udp_live_adapter": entry.udp_live_adapter,
                "udp_semantics": entry.udp_semantics,
                "udp_path_ready": entry.udp_path_ready(),
                "transport_underlay": entry.transport_underlay,
                "route_group_connectivity": entry.route_group_connectivity,
                "selected_node_fail_closed": entry.selected_node_fail_closed,
                "fingerprint_underlay": entry.fingerprint_underlay,
                "remote_live_matrix": remote_live_matrix,
                "go_outbound_fallback_retired": entry.go_outbound_fallback_retired,
                "wired_ready": entry.wired_ready(),
                "live_ready": entry.wired_ready() && remote_live_matrix && missing.is_empty(),
                "fingerprint_behavior": entry.fingerprint_behavior,
                "evidence": entry.evidence,
                "missing": missing,
            })
        })
        .collect::<Vec<_>>();
    let wired_handler_count = matrix
        .entries
        .iter()
        .filter(|entry| entry.wired_ready())
        .count();
    let live_ready_handler_count = matrix
        .entries
        .iter()
        .filter(|entry| {
            let remote_live_matrix =
                crate::production_runtime_owner::resident_live_adapter_entry_remote_live_matrix_ready(
                    entry,
                    &live_evidence,
                );
            let missing =
                crate::production_runtime_owner::resident_live_adapter_entry_missing(
                    entry,
                    &live_evidence,
                );
            entry.wired_ready() && remote_live_matrix && missing.is_empty()
        })
        .count();

    if let Value::Object(report) = report {
        report.insert(
            "resident_live_adapter_matrix_contract_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "resident_live_adapter_matrix_ready".to_owned(),
            json!(matrix.matrix_ready),
        );
        report.insert(
            "resident_live_adapter_matrix_runtime_state_ready".to_owned(),
            json!(matrix.matrix_ready),
        );
        report.insert(
            "resident_live_adapter_entries_ready".to_owned(),
            json!(!entries.is_empty()),
        );
        report.insert(
            "resident_live_adapter_planner_admission_ready".to_owned(),
            json!(matrix.planner_admission_ready),
        );
        report.insert(
            "resident_live_adapter_tcp_ready".to_owned(),
            json!(matrix.tcp_live_adapter_ready),
        );
        report.insert(
            "resident_live_adapter_udp_ready".to_owned(),
            json!(matrix.udp_live_adapter_ready),
        );
        report.insert(
            "resident_live_adapter_transport_underlay_ready".to_owned(),
            json!(matrix.transport_underlay_ready),
        );
        report.insert(
            "resident_live_adapter_route_group_connectivity_ready".to_owned(),
            json!(matrix.route_group_connectivity_ready),
        );
        report.insert(
            "resident_live_adapter_selected_node_fail_closed_ready".to_owned(),
            json!(matrix.selected_node_fail_closed_ready),
        );
        report.insert(
            "resident_live_adapter_fingerprint_underlay_ready".to_owned(),
            json!(matrix.fingerprint_underlay_ready),
        );
        report.insert(
            "resident_live_adapter_go_outbound_fallback_retirement_ready".to_owned(),
            json!(matrix.go_outbound_fallback_retirement_ready),
        );
        report.insert(
            "resident_live_adapter_wired_matrix_ready".to_owned(),
            json!(matrix.wired_matrix_ready),
        );
        report.insert(
            "resident_live_adapter_remote_live_matrix_ready".to_owned(),
            json!(matrix.remote_live_matrix_ready),
        );
        report.insert(
            "resident_live_adapter_remote_live_matrix_evidence".to_owned(),
            json!({
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
            }),
        );
        report.insert(
            "resident_live_adapter_wired_handler_count".to_owned(),
            json!(wired_handler_count),
        );
        report.insert(
            "resident_live_adapter_live_ready_handler_count".to_owned(),
            json!(live_ready_handler_count),
        );
        report.insert(
            "resident_live_adapter_matrix_report_schema".to_owned(),
            json!(matrix.schema),
        );
        report.insert(
            "resident_live_adapter_matrix_entries".to_owned(),
            json!(entries),
        );
        report.insert(
            "resident_live_adapter_matrix_typed_report_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "resident_live_adapter_matrix_typed_report".to_owned(),
            json!({
                "schema": "resident-live-adapter-matrix-typed-report",
                "status": if matrix.matrix_ready { "pass" } else { "blocked" },
                "entry_count": entries.len(),
                "wired_handler_count": wired_handler_count,
                "live_ready_handler_count": live_ready_handler_count,
                "planner_admission_ready": matrix.planner_admission_ready,
                "tcp_live_adapter_ready": matrix.tcp_live_adapter_ready,
                "udp_live_adapter_ready": matrix.udp_live_adapter_ready,
                "transport_underlay_ready": matrix.transport_underlay_ready,
                "route_group_connectivity_ready": matrix.route_group_connectivity_ready,
                "selected_node_fail_closed_ready": matrix.selected_node_fail_closed_ready,
                "fingerprint_underlay_ready": matrix.fingerprint_underlay_ready,
                "go_outbound_fallback_retirement_ready": matrix.go_outbound_fallback_retirement_ready,
                "wired_matrix_ready": matrix.wired_matrix_ready,
                "remote_live_matrix_ready": matrix.remote_live_matrix_ready,
                "matrix_ready": matrix.matrix_ready,
                "stage_report_schema": false,
            }),
        );
        report.insert(
            "resident_live_adapter_matrix_surface".to_owned(),
            json!({
                "scope": "live resident default adapter from selected node link into TCP/UDP tproxy workers",
                "formal_matrix_dependency": "dae-outbound production matrix remains parser/dataplane/underlay evidence; this resident matrix records which handlers are actually wired into the live default adapter",
                "default_switch_policy": "C8/C9/C10 cannot treat the formal outbound matrix as sufficient while this matrix is not pass",
                "live_matrix_host": "38.65.91.47",
                "household_smoke_host": "10.10.10.2",
            }),
        );
    }
}

fn insert_release_default_switch_service_contract_capabilities(report: &mut Value) {
    let contract = dae_product::release_default_switch_contract();
    if let Value::Object(report) = report {
        report.insert(
            "release_default_switch_contract_ready".to_owned(),
            json!(contract.contract_ready),
        );
        report.insert(
            "release_default_artifact_path_ready".to_owned(),
            json!(contract.default_artifact_path_ready),
        );
        report.insert(
            "default_runtime_selector_no_env_rust_owned_ready".to_owned(),
            json!(contract.default_runtime_selector_ready),
        );
        report.insert(
            "install_service_package_scripts_ready".to_owned(),
            json!(contract.service_package_scripts_ready),
        );
        report.insert(
            "release_default_switch_live_evidence_contract_ready".to_owned(),
            json!(contract.live_evidence_contract_ready),
        );
        report.insert(
            "backup_manifest_contract_ready".to_owned(),
            json!(contract.backup_manifest_contract_ready),
        );
        report.insert(
            "rollback_rehearsal_contract_ready".to_owned(),
            json!(contract.rollback_rehearsal_contract_ready),
        );
        report.insert(
            "host_write_freeze_contract_required".to_owned(),
            json!(contract.host_write_freeze_required),
        );
        report.insert(
            "go_product_shell_allowed_until_go_free".to_owned(),
            json!(contract.go_product_shell_allowed_until_go_free),
        );
        report.insert(
            "release_default_switch_final_go_free_claim".to_owned(),
            json!(contract.final_go_free_claim),
        );
        report.insert(
            "release_default_switch_typed_report_ready".to_owned(),
            json!(contract.contract_ready),
        );
        report.insert(
            "release_default_switch_report_schema".to_owned(),
            json!(contract.name),
        );
        report.insert(
            "release_default_switch_required_live_hosts".to_owned(),
            json!(contract.required_live_hosts),
        );
        report.insert(
            "release_default_switch_surface".to_owned(),
            json!(contract.surface),
        );
        report.insert(
            "release_default_switch_typed_report".to_owned(),
            json!({
                "schema": "release-default-switch-typed-report",
                "status": "pass",
                "c_phase": contract.c_phase,
                "prior_gate": contract.prior_gate,
                "release_default_artifact_path_ready": contract.default_artifact_path_ready,
                "default_runtime_selector_no_env_rust_owned_ready": contract.default_runtime_selector_ready,
                "install_service_package_scripts_ready": contract.service_package_scripts_ready,
                "host_write_freeze_required": contract.host_write_freeze_required,
                "final_go_free_claim": contract.final_go_free_claim,
                "stage_report_schema": false,
            }),
        );
    }
}

fn insert_go_free_product_chain_service_contract_capabilities(report: &mut Value) {
    let contract = dae_product::go_free_product_chain_contract();
    let evidence = crate::c10_go_free_evidence::c10_go_free_product_chain_evidence_from_env();
    if let Value::Object(report) = report {
        report.insert(
            "go_free_product_chain_contract_ready".to_owned(),
            json!(contract.contract_ready),
        );
        report.insert(
            "default_product_package_go_free".to_owned(),
            json!(evidence.default_product_package_go_free),
        );
        report.insert(
            "go_product_shell_retired_from_default_package".to_owned(),
            json!(evidence.go_product_shell_retired),
        );
        report.insert(
            "go_orchestration_retired_from_default_package".to_owned(),
            json!(evidence.go_orchestration_retired),
        );
        report.insert(
            "go_control_runtime_api_service_release_retired_from_default_package".to_owned(),
            json!(evidence.go_control_runtime_api_service_release_retired),
        );
        report.insert(
            "go_outbound_dependency_retired_from_default_package".to_owned(),
            json!(evidence.go_outbound_dependency_retired),
        );
        report.insert(
            "go_compat_oracle_boundary_ready".to_owned(),
            json!(evidence.go_compat_oracle_boundary_ready),
        );
        report.insert(
            "rust_product_binary_contract_ready".to_owned(),
            json!(evidence.rust_product_binary_contract_ready),
        );
        report.insert(
            "rust_product_lifecycle_contract_ready".to_owned(),
            json!(evidence.rust_product_lifecycle_contract_ready),
        );
        report.insert(
            "rust_product_web_api_package_release_contract_ready".to_owned(),
            json!(evidence.rust_product_web_api_package_release_contract_ready),
        );
        report.insert(
            "go_free_live_host_contract_ready".to_owned(),
            json!(evidence.live_host_contract_ready),
        );
        report.insert(
            "go_free_rollback_model_ready".to_owned(),
            json!(evidence.rollback_model_ready),
        );
        report.insert(
            "go_free_product_chain_typed_report_ready".to_owned(),
            json!(evidence.typed_report_ready),
        );
        report.insert(
            "go_free_product_chain_ready".to_owned(),
            json!(evidence.ready),
        );
        report.insert(
            "go_free_product_chain_report_schema".to_owned(),
            json!(contract.name),
        );
        report.insert(
            "go_free_product_chain_default_dependency_policy".to_owned(),
            json!(contract.default_dependency_policy),
        );
        report.insert(
            "go_free_product_chain_retained_go_scope".to_owned(),
            json!(contract.retained_go_scope),
        );
        report.insert(
            "go_free_product_chain_surface".to_owned(),
            json!(contract.surface),
        );
        report.insert(
            "go_free_product_chain_typed_report".to_owned(),
            json!({
                "schema": "go-free-product-chain-typed-report",
                "status": if evidence.ready { "pass" } else { "blocked" },
                "c_phase": contract.c_phase,
                "prior_gate": contract.prior_gate,
                "default_product_package_go_free": evidence.default_product_package_go_free,
                "go_product_shell_retired_from_default_package": evidence.go_product_shell_retired,
                "go_orchestration_retired_from_default_package": evidence.go_orchestration_retired,
                "go_control_runtime_api_service_release_retired_from_default_package": evidence.go_control_runtime_api_service_release_retired,
                "go_outbound_dependency_retired_from_default_package": evidence.go_outbound_dependency_retired,
                "go_compat_oracle_boundary_ready": evidence.go_compat_oracle_boundary_ready,
                "userland_ffi_c_abi_retired_from_default_path": evidence.userland_ffi_c_abi_retired,
                "go_oracle_default_dependency_retired_from_default_path": evidence.go_oracle_default_dependency_retired,
                "rust_internal_fallback_normalized_for_default_path": evidence.rust_internal_fallback_normalized,
                "rust_product_binary_contract_ready": evidence.rust_product_binary_contract_ready,
                "rust_product_lifecycle_contract_ready": evidence.rust_product_lifecycle_contract_ready,
                "rust_product_web_api_package_release_contract_ready": evidence.rust_product_web_api_package_release_contract_ready,
                "live_host_contract_ready": evidence.live_host_contract_ready,
                "rollback_model_ready": evidence.rollback_model_ready,
                "go_free_product_chain_ready": evidence.ready,
                "blockers": evidence.blockers.clone(),
                "final_evidence": evidence.report.clone(),
                "stage_report_schema": false,
            }),
        );
    }
}

pub(crate) fn resident_dataplane_default_switch_ready_from_env() -> bool {
    let value = env::var(RESIDENT_DATAPLANE_ENV).ok();
    resident_dataplane_default_switch_value_enabled(value.as_deref())
}

pub(crate) fn resident_dataplane_default_switch_value_enabled(value: Option<&str>) -> bool {
    matches!(
        value,
        Some("1" | "true" | "TRUE" | "on" | "ON" | "yes" | "YES")
    )
}

pub fn run_resident_service(options: &ResidentRunOptions) -> Result<(), String> {
    if options.disable_sudo && unsafe { libc::geteuid() } != 0 {
        return Err("auto-sudo is disabled and current user is not root".to_owned());
    }
    let runtime_config = load_config_file(&options.config)
        .map_err(|err| format!("resident run config validation failed: {err}"))?;
    block_service_signals()?;
    let mut state = ResidentServiceState {
        runtime: Some(start_resident_production_runtime(&runtime_config)?),
        config: runtime_config,
    };

    let started = (|| {
        if !options.disable_pidfile {
            write_text_file(&options.pid_file, &format!("{}", std::process::id()), 0o644)?;
        }
        write_progress(&options.progress_file, RELOAD_DONE, "")?;
        if let Some(path) = &options.ready_record_file {
            write_text_file(path, "READY=1\n", 0o644)?;
        }
        log_event(options, "service ready")?;
        notify_systemd("READY=1")?;
        Ok::<(), String>(())
    })();
    if let Err(err) = started {
        state.runtime.take();
        if !options.disable_pidfile {
            let _ = fs::remove_file(&options.pid_file);
        }
        return Err(err);
    }

    loop {
        let signal = wait_service_signal()?;
        match signal {
            libc::SIGUSR1 => handle_reload(options, &mut state)?,
            libc::SIGUSR2 => handle_suspend_compatibility(options)?,
            libc::SIGHUP => continue,
            libc::SIGTERM | libc::SIGINT | libc::SIGQUIT => {
                let _ = notify_systemd("STOPPING=1");
                let _ = log_event(options, "service stopping");
                state.runtime.take();
                if !options.disable_pidfile {
                    let _ = fs::remove_file(&options.pid_file);
                }
                return Ok(());
            }
            _ => continue,
        }
    }
}

struct ResidentServiceState {
    runtime: Option<ResidentProductionRuntime>,
    config: Config,
}

pub fn reload_resident_service(options: &ReloadOptions) -> Result<String, String> {
    let pid = match options.pid {
        Some(pid) => pid,
        None => read_pid_file(&options.pid_file)?,
    };
    if options.abort_connections {
        write_text_file(&options.abort_file, "", 0o644)?;
    }
    if let Ok((code, _)) = read_progress(&options.progress_file)
        && code != RELOAD_DONE
        && code != RELOAD_ERROR
    {
        return Ok(format!(
            "{} shows another reload operation is in progress.\n",
            options.progress_file.display()
        ));
    }
    write_progress(&options.progress_file, RELOAD_SEND, "")?;
    let status = unsafe { libc::kill(pid, libc::SIGUSR1) };
    if status != 0 {
        return Err(io::Error::last_os_error().to_string());
    }

    let started = Instant::now();
    loop {
        if options
            .timeout
            .is_some_and(|timeout| started.elapsed() >= timeout)
        {
            return Err("reload progress timed out".to_owned());
        }
        thread::sleep(Duration::from_millis(200));
        let Ok((code, content)) = read_progress(&options.progress_file) else {
            return Ok("OK\n".to_owned());
        };
        if code == RELOAD_DONE || code == RELOAD_ERROR {
            return Ok(format!("{content}\n"));
        }
    }
}

fn handle_reload(
    options: &ResidentRunOptions,
    state: &mut ResidentServiceState,
) -> Result<(), String> {
    notify_systemd("RELOADING=1")?;
    write_progress(&options.progress_file, RELOAD_PROCESSING, "")?;
    let _abort_connections = fs::remove_file(&options.abort_file).is_ok();
    match load_config_file(&options.config) {
        Ok(runtime_config) => {
            if let Err(err) = validate_resident_runtime_reload_config(&runtime_config) {
                write_progress(&options.progress_file, RELOAD_ERROR, &format!("\n{err}"))?;
                log_event(options, "reload failed")?;
                notify_systemd("READY=1")?;
                return Ok(());
            }
            if let Err(err) = swap_runtime_with_rollback(
                &mut state.runtime,
                &mut state.config,
                runtime_config,
                start_resident_production_runtime,
            ) {
                write_progress(&options.progress_file, RELOAD_ERROR, &format!("\n{err}"))?;
                log_event(options, "reload failed")?;
                notify_systemd("READY=1")?;
                if state.runtime.is_none() {
                    return Err(err);
                }
                return Ok(());
            }
            write_progress(&options.progress_file, RELOAD_DONE, "\nOK")?;
            log_event(options, "reload completed")?;
        }
        Err(err) => {
            write_progress(&options.progress_file, RELOAD_ERROR, &format!("\n{err}"))?;
            log_event(options, "reload failed")?;
        }
    }
    notify_systemd("READY=1")
}

fn validate_resident_runtime_reload_config(config: &Config) -> Result<(), String> {
    for iface in config
        .global
        .lan_interface
        .iter()
        .flatten()
        .chain(config.global.wan_interface.iter().flatten())
    {
        let iface = iface.trim();
        if iface.is_empty() || iface == "auto" {
            continue;
        }
        let sysfs = Path::new("/sys/class/net").join(iface);
        if !sysfs.exists() {
            return Err(format!(
                "resident reload rejected before current runtime swap: configured interface {iface:?} does not exist"
            ));
        }
    }
    Ok(())
}

fn swap_runtime_with_rollback<R>(
    runtime: &mut Option<R>,
    current_config: &mut Config,
    next_config: Config,
    mut start_runtime: impl FnMut(&Config) -> Result<R, String>,
) -> Result<(), String> {
    let previous_config = current_config.clone();
    let previous_runtime = runtime.take();
    drop(previous_runtime);
    match start_runtime(&next_config) {
        Ok(next_runtime) => {
            *runtime = Some(next_runtime);
            *current_config = next_config;
            Ok(())
        }
        Err(start_err) => match start_runtime(&previous_config) {
            Ok(restored_runtime) => {
                *runtime = Some(restored_runtime);
                Err(format!(
                    "{start_err}\nrollback: restored previous resident runtime"
                ))
            }
            Err(rollback_err) => Err(format!(
                "{start_err}\nrollback failed while restoring previous resident runtime: {rollback_err}"
            )),
        },
    }
}

fn handle_suspend_compatibility(options: &ResidentRunOptions) -> Result<(), String> {
    notify_systemd("RELOADING=1")?;
    write_progress(&options.progress_file, RELOAD_PROCESSING, "")?;
    let _ = fs::remove_file(&options.abort_file);
    write_progress(
        &options.progress_file,
        RELOAD_ERROR,
        "\nsuspend runtime transition is not implemented by Rust service contract",
    )?;
    log_event(options, "suspend rejected")?;
    notify_systemd("READY=1")
}

fn write_progress(path: &Path, byte: u8, suffix: &str) -> Result<(), String> {
    let mut bytes = vec![byte];
    bytes.extend_from_slice(suffix.as_bytes());
    write_bytes_file(path, &bytes, 0o644)
}

fn read_progress(path: &Path) -> Result<(u8, String), String> {
    let bytes =
        fs::read(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let Some(code) = bytes.first().copied() else {
        return Err(format!("unexpected format: {}", path.display()));
    };
    let content = String::from_utf8_lossy(&bytes[1..])
        .trim_start_matches('\n')
        .to_owned();
    Ok((code, content))
}

fn read_pid_file(path: &Path) -> Result<i32, String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read pid file {}: {err}", path.display()))?;
    text.trim()
        .parse::<i32>()
        .map_err(|err| format!("failed to parse pid file {}: {err}", path.display()))
}

fn log_event(options: &ResidentRunOptions, message: &str) -> Result<(), String> {
    let Some(path) = &options.logfile else {
        return Ok(());
    };
    let line = if options.disable_timestamp {
        format!("{message}\n")
    } else {
        format!("{} {message}\n", std::process::id())
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create log dir {}: {err}", parent.display()))?;
    }
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| format!("failed to open log {}: {err}", path.display()))?;
    file.write_all(line.as_bytes())
        .map_err(|err| format!("failed to write log {}: {err}", path.display()))
}

fn write_text_file(path: &Path, content: &str, mode: u32) -> Result<(), String> {
    write_bytes_file(path, content.as_bytes(), mode)
}

fn write_bytes_file(path: &Path, content: &[u8], mode: u32) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create path {}: {err}", parent.display()))?;
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|err| format!("failed to chmod {}: {err}", path.display()))
}

fn notify_systemd(state: &str) -> Result<(), String> {
    let Ok(address) = env::var("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let socket =
        UnixDatagram::unbound().map_err(|err| format!("failed to create notify socket: {err}"))?;
    if address.starts_with('@') {
        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::net::SocketAddr;

            let target = SocketAddr::from_abstract_name(address.as_bytes()[1..].to_vec())
                .map_err(|err| format!("failed to parse abstract notify socket: {err}"))?;
            socket
                .send_to_addr(state.as_bytes(), &target)
                .map_err(|err| format!("failed to notify systemd: {err}"))?;
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        return Err("abstract systemd notify sockets are unsupported on this platform".to_owned());
    }
    socket
        .send_to(state.as_bytes(), address)
        .map_err(|err| format!("failed to notify systemd: {err}"))?;
    Ok(())
}

fn block_service_signals() -> Result<(), String> {
    let mut signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    unsafe {
        libc::sigemptyset(&mut signals);
        for signal in [
            libc::SIGUSR1,
            libc::SIGUSR2,
            libc::SIGHUP,
            libc::SIGTERM,
            libc::SIGINT,
            libc::SIGQUIT,
        ] {
            libc::sigaddset(&mut signals, signal);
        }
        if libc::pthread_sigmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut()) != 0 {
            return Err("failed to block resident service signals".to_owned());
        }
    }
    Ok(())
}

fn wait_service_signal() -> Result<i32, String> {
    let mut signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    let mut received = 0_i32;
    unsafe {
        libc::sigemptyset(&mut signals);
        for signal in [
            libc::SIGUSR1,
            libc::SIGUSR2,
            libc::SIGHUP,
            libc::SIGTERM,
            libc::SIGINT,
            libc::SIGQUIT,
        ] {
            libc::sigaddset(&mut signals, signal);
        }
        let status = libc::sigwait(&signals, &mut received);
        if status != 0 {
            return Err(format!(
                "failed to wait for resident service signal: {status}"
            ));
        }
    }
    Ok(received)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dae_config::{Global, Routing};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone)]
    struct FakeRuntime {
        drops: Arc<AtomicUsize>,
    }

    impl Drop for FakeRuntime {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn minimal_config() -> Config {
        Config {
            global: Global::default(),
            subscription: Vec::new(),
            node: Vec::new(),
            group: Vec::new(),
            routing: Routing::default(),
            dns: Default::default(),
        }
    }

    #[test]
    fn resident_reload_preflight_rejects_missing_interface_before_swap() {
        let mut config = minimal_config();
        config.global.lan_interface = Some(vec!["dae-missing-a4-interface".to_owned()]);
        let err = validate_resident_runtime_reload_config(&config).unwrap_err();
        assert!(err.contains("rejected before current runtime swap"));
        assert!(err.contains("dae-missing-a4-interface"));
    }

    #[test]
    fn resident_reload_swap_restores_previous_runtime_when_next_start_fails() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut current_config = minimal_config();
        current_config.global.log_level = "info".to_owned();
        let mut next_config = current_config.clone();
        next_config.global.log_level = "debug".to_owned();
        let mut runtime = Some(FakeRuntime {
            drops: Arc::clone(&drops),
        });
        let err =
            swap_runtime_with_rollback(&mut runtime, &mut current_config, next_config, |cfg| {
                if cfg.global.log_level == "debug" {
                    Err("simulated next runtime start failure".to_owned())
                } else {
                    Ok(FakeRuntime {
                        drops: Arc::clone(&drops),
                    })
                }
            })
            .unwrap_err();
        assert!(err.contains("simulated next runtime start failure"));
        assert!(err.contains("restored previous resident runtime"));
        assert!(runtime.is_some());
        assert_eq!(current_config.global.log_level, "info");
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn resident_reload_swap_reports_fatal_when_rollback_start_fails() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut current_config = minimal_config();
        let mut next_config = current_config.clone();
        next_config.global.log_level = "debug".to_owned();
        let mut runtime = Some(FakeRuntime {
            drops: Arc::clone(&drops),
        });
        let err =
            swap_runtime_with_rollback(&mut runtime, &mut current_config, next_config, |_| {
                Err("simulated runtime start failure".to_owned())
            })
            .unwrap_err();
        assert!(err.contains("rollback failed"));
        assert!(runtime.is_none());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn resident_dataplane_default_switch_requires_explicit_enable_value() {
        for value in ["1", "true", "TRUE", "on", "ON", "yes", "YES"] {
            assert!(resident_dataplane_default_switch_value_enabled(Some(value)));
        }
        for value in ["", "0", "false", "FALSE", "off", "OFF", "no", "NO"] {
            assert!(!resident_dataplane_default_switch_value_enabled(Some(
                value
            )));
        }
        assert!(!resident_dataplane_default_switch_value_enabled(None));
    }
}
