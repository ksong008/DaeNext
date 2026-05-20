use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use dae_engine::{
    DnsObservabilityStats, Engine, EngineOptions, RuntimeOverview, RuntimeStatsSnapshot,
    RuntimeTrafficSample, route_aware_dial_target,
};
use serde_json::{Value, json};

use crate::runner::RunnerOutput;
use crate::runtime_host_preflight::run_stage22_host_preflight;
use crate::runtime_live_plan::run_stage22_live_plan;
use crate::runtime_stage26_candidate::run_stage26_candidate_plan;
use crate::runtime_stage27_candidate::run_stage27_candidate;
use crate::runtime_stage29_preflight::run_stage29_host_preflight;
use crate::runtime_stage30_attach_cleanup::run_stage30_attach_cleanup;
use crate::runtime_stage31_34_gates::{
    run_stage31_ebpf_attach_admission, run_stage32_active_traffic_admission,
    run_stage33_reload_rollback_admission, run_stage34_benchmark_admission,
};
use crate::runtime_stage35_36_gates::{
    run_stage35_real_ebpf_attach_admission, run_stage36_listen_socket_map_admission,
};
use crate::runtime_stage37_gate::run_stage37_loaded_listen_socket_map_admission;
use crate::runtime_stage38_gate::run_stage38_production_dae_attach_admission;
use crate::runtime_stage39_gate::run_stage39_transparent_listener_admission;
use crate::runtime_stage40_gate::run_stage40_param_aware_object_admission;
use crate::runtime_stage41_48_gates::{
    run_stage41_param_object_image_admission, run_stage42_param_object_load_admission,
    run_stage43_production_param_listener_admission, run_stage44_active_tcp_tproxy_admission,
    run_stage45_active_udp_tproxy_admission, run_stage46_active_dns_tproxy_admission,
    run_stage47_outbound_true_dataplane_admission, run_stage48_true_daemon_benchmark_admission,
};
use crate::runtime_stage49_gate::run_stage49_production_param_listener_admission;
use crate::runtime_stage50_tcp_gate::{
    run_stage50_active_tcp_tproxy_ingress_admission,
    run_stage51_active_tcp_route_dial_relay_admission,
    run_stage52_active_tcp_route_table_group_relay_admission,
    run_stage53_active_udp_tproxy_endpoint_admission,
    run_stage54_active_dns_tproxy_cache_admission,
};
use crate::runtime_stage55_outbound_gate::run_stage55_socks5_outbound_true_dataplane_admission;
use crate::runtime_stage56_outbound_gate::run_stage56_socks5_udp_associate_dataplane_admission;
use crate::runtime_stage57_outbound_gate::run_stage57_http_connect_dataplane_admission;
use crate::runtime_stage58_outbound_gate::run_stage58_shadowsocks_aead_tcp_dataplane_admission;
use crate::runtime_stage59_outbound_gate::run_stage59_shadowsocks_aead_udp_dataplane_admission;
use crate::runtime_stage60_outbound_gate::run_stage60_trojan_tcp_dataplane_admission;
use crate::runtime_stage61_outbound_gate::run_stage61_trojan_udp_over_tcp_dataplane_admission;
use crate::runtime_stage62_outbound_gate::run_stage62_vless_tcp_dataplane_admission;
use crate::runtime_stage63_outbound_gate::run_stage63_vless_udp_over_tcp_dataplane_admission;
use crate::runtime_stage64_outbound_gate::run_stage64_vless_mux_dataplane_admission;
use crate::runtime_stage65_outbound_gate::run_stage65_vmess_aead_tcp_dataplane_admission;
use crate::runtime_stage66_outbound_gate::run_stage66_vmess_aead_udp_over_tcp_dataplane_admission;
use crate::runtime_stage67_outbound_gate::run_stage67_vmess_packet_addr_udp_dataplane_admission;
use crate::runtime_stage68_outbound_gate::run_stage68_vmess_mux_dataplane_admission;
use crate::runtime_stage69_outbound_gate::run_stage69_vmess_websocket_dataplane_admission;
use crate::runtime_stage70_outbound_gate::run_stage70_vmess_httpupgrade_dataplane_admission;
use crate::runtime_stage71_outbound_gate::run_stage71_vmess_grpc_hunk_dataplane_admission;
use crate::runtime_stage72_outbound_gate::run_stage72_vmess_meek_polling_dataplane_admission;
use crate::runtime_stage73_outbound_gate::run_stage73_vmess_http_transport_dataplane_admission;
use crate::runtime_stage74_outbound_gate::run_stage74_vless_websocket_dataplane_admission;
use crate::runtime_stage75_outbound_gate::run_stage75_vless_httpupgrade_dataplane_admission;
use crate::runtime_stage76_outbound_gate::run_stage76_vless_grpc_hunk_dataplane_admission;
use crate::runtime_stage77_outbound_gate::run_stage77_vless_meek_polling_dataplane_admission;
use crate::runtime_stage78_outbound_gate::run_stage78_vless_http_transport_dataplane_admission;
use crate::runtime_stage79_outbound_gate::run_stage79_vless_xhttp_packet_dataplane_admission;
use crate::runtime_stage80_outbound_gate::run_stage80_vless_xhttp_xmux_dataplane_admission;
use crate::runtime_stage81_shared_tls_gate::run_stage81_shared_tls_underlay_dataplane_admission;
use crate::runtime_stage82_https_proxy_gate::run_stage82_https_proxy_tls_dataplane_admission;
use crate::runtime_stage83_trojan_tls_gate::run_stage83_trojan_tls_dataplane_admission;
use crate::runtime_stage84_trojan_go_wss_gate::run_stage84_trojan_go_wss_dataplane_admission;
use crate::runtime_stage85_trojan_go_httpupgrade_gate::run_stage85_trojan_go_httpupgrade_dataplane_admission;
use crate::runtime_stage86_trojan_go_grpc_gate::run_stage86_trojan_go_grpc_dataplane_admission;
use crate::runtime_stage87_trojan_go_inner_shadowsocks_gate::run_stage87_trojan_go_inner_shadowsocks_dataplane_admission;
use crate::runtime_stage88_ss2022_tcp_gate::run_stage88_ss2022_tcp_dataplane_admission;
use crate::runtime_stage89_ss2022_multi_psk_gate::run_stage89_ss2022_multi_psk_dataplane_admission;
use crate::runtime_stage90_ss2022_udp_gate::run_stage90_ss2022_udp_dataplane_admission;
use crate::runtime_stage91_ss2022_protocol_gate::run_stage91_ss2022_protocol_admission;
use crate::runtime_stage92_sip003_simple_obfs_http_gate::run_stage92_sip003_simple_obfs_http_dataplane_admission;
use crate::runtime_stage93_sip003_simple_obfs_tls_gate::run_stage93_sip003_simple_obfs_tls_dataplane_admission;
use crate::runtime_stage94_sip003_v2ray_plugin_gate::run_stage94_sip003_v2ray_plugin_dataplane_admission;
use crate::runtime_stage95_shadowsocksr_gate::run_stage95_shadowsocksr_three_layer_dataplane_admission;
use crate::runtime_stage96_protocol_matrix_gate::run_stage96_protocol_matrix_recertification;
use crate::runtime_stage97_trojan_go_grpc_http2_gate::run_stage97_trojan_go_grpc_http2_tls_lifecycle_admission;
use crate::runtime_stage98_trojan_go_grpc_cache_gate::run_stage98_trojan_go_grpc_cache_cancellation_admission;
use crate::runtime_stage99_trojan_go_recertification_gate::run_stage99_trojan_go_shared_transport_recertification;
use crate::runtime_stage100_trojan_go_tls_fragment_gate::run_stage100_trojan_go_tls_fragment_admission;
use crate::runtime_stage101_trojan_go_utls_fingerprint_gate::run_stage101_trojan_go_utls_fingerprint_readiness;
use crate::runtime_stage102_reality_session_mutation_gate::run_stage102_reality_session_id_mutation_readiness;
use crate::runtime_stage103_trojan_go_combination_gate::run_stage103_trojan_go_combination_admission;

pub(crate) fn run_runtime(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("dry-run-smoke") => run_dry_run_smoke(),
        Some("route-target") => run_route_target(&args[1..]),
        Some("overview-basic") => run_overview_basic(),
        Some("stage22-smoke") => run_stage22_smoke(),
        Some("stage22-host-preflight") => run_stage22_host_preflight(&args[1..]),
        Some("stage22-live-plan") => run_stage22_live_plan(&args[1..]),
        Some("stage26-candidate-plan") => run_stage26_candidate_plan(&args[1..]),
        Some("stage27-run-candidate") => run_stage27_candidate(&args[1..]),
        Some("stage29-host-preflight") => run_stage29_host_preflight(&args[1..]),
        Some("stage30-attach-cleanup") => run_stage30_attach_cleanup(&args[1..]),
        Some("stage31-ebpf-attach-admission") => run_stage31_ebpf_attach_admission(&args[1..]),
        Some("stage32-active-traffic-admission") => {
            run_stage32_active_traffic_admission(&args[1..])
        }
        Some("stage33-reload-rollback-admission") => {
            run_stage33_reload_rollback_admission(&args[1..])
        }
        Some("stage34-benchmark-admission") => run_stage34_benchmark_admission(&args[1..]),
        Some("stage35-real-ebpf-attach-admission") => {
            run_stage35_real_ebpf_attach_admission(&args[1..])
        }
        Some("stage36-listen-socket-map-admission") => {
            run_stage36_listen_socket_map_admission(&args[1..])
        }
        Some("stage37-loaded-listen-socket-map-admission") => {
            run_stage37_loaded_listen_socket_map_admission(&args[1..])
        }
        Some("stage38-production-dae-attach-admission") => {
            run_stage38_production_dae_attach_admission(&args[1..])
        }
        Some("stage39-transparent-listener-admission") => {
            run_stage39_transparent_listener_admission(&args[1..])
        }
        Some("stage40-param-aware-object-admission") => {
            run_stage40_param_aware_object_admission(&args[1..])
        }
        Some("stage41-param-object-image-admission") => {
            run_stage41_param_object_image_admission(&args[1..])
        }
        Some("stage42-param-object-load-admission") => {
            run_stage42_param_object_load_admission(&args[1..])
        }
        Some("stage43-production-param-listener-admission") => {
            run_stage43_production_param_listener_admission(&args[1..])
        }
        Some("stage44-active-tcp-tproxy-admission") => {
            run_stage44_active_tcp_tproxy_admission(&args[1..])
        }
        Some("stage45-active-udp-tproxy-admission") => {
            run_stage45_active_udp_tproxy_admission(&args[1..])
        }
        Some("stage46-active-dns-tproxy-admission") => {
            run_stage46_active_dns_tproxy_admission(&args[1..])
        }
        Some("stage47-outbound-true-dataplane-admission") => {
            run_stage47_outbound_true_dataplane_admission(&args[1..])
        }
        Some("stage48-true-daemon-benchmark-admission") => {
            run_stage48_true_daemon_benchmark_admission(&args[1..])
        }
        Some("stage49-production-param-listener-admission") => {
            run_stage49_production_param_listener_admission(&args[1..])
        }
        Some("stage50-active-tcp-tproxy-ingress-admission") => {
            run_stage50_active_tcp_tproxy_ingress_admission(&args[1..])
        }
        Some("stage51-active-tcp-route-dial-relay-admission") => {
            run_stage51_active_tcp_route_dial_relay_admission(&args[1..])
        }
        Some("stage52-active-tcp-route-table-group-relay-admission") => {
            run_stage52_active_tcp_route_table_group_relay_admission(&args[1..])
        }
        Some("stage53-active-udp-tproxy-endpoint-admission") => {
            run_stage53_active_udp_tproxy_endpoint_admission(&args[1..])
        }
        Some("stage54-active-dns-tproxy-cache-admission") => {
            run_stage54_active_dns_tproxy_cache_admission(&args[1..])
        }
        Some("stage55-socks5-outbound-true-dataplane-admission") => {
            run_stage55_socks5_outbound_true_dataplane_admission(&args[1..])
        }
        Some("stage56-socks5-udp-associate-dataplane-admission") => {
            run_stage56_socks5_udp_associate_dataplane_admission(&args[1..])
        }
        Some("stage57-http-connect-dataplane-admission") => {
            run_stage57_http_connect_dataplane_admission(&args[1..])
        }
        Some("stage58-shadowsocks-aead-tcp-dataplane-admission") => {
            run_stage58_shadowsocks_aead_tcp_dataplane_admission(&args[1..])
        }
        Some("stage59-shadowsocks-aead-udp-dataplane-admission") => {
            run_stage59_shadowsocks_aead_udp_dataplane_admission(&args[1..])
        }
        Some("stage60-trojan-tcp-dataplane-admission") => {
            run_stage60_trojan_tcp_dataplane_admission(&args[1..])
        }
        Some("stage61-trojan-udp-over-tcp-dataplane-admission") => {
            run_stage61_trojan_udp_over_tcp_dataplane_admission(&args[1..])
        }
        Some("stage62-vless-tcp-dataplane-admission") => {
            run_stage62_vless_tcp_dataplane_admission(&args[1..])
        }
        Some("stage63-vless-udp-over-tcp-dataplane-admission") => {
            run_stage63_vless_udp_over_tcp_dataplane_admission(&args[1..])
        }
        Some("stage64-vless-mux-dataplane-admission") => {
            run_stage64_vless_mux_dataplane_admission(&args[1..])
        }
        Some("stage65-vmess-aead-tcp-dataplane-admission") => {
            run_stage65_vmess_aead_tcp_dataplane_admission(&args[1..])
        }
        Some("stage66-vmess-aead-udp-over-tcp-dataplane-admission") => {
            run_stage66_vmess_aead_udp_over_tcp_dataplane_admission(&args[1..])
        }
        Some("stage67-vmess-packet-addr-udp-dataplane-admission") => {
            run_stage67_vmess_packet_addr_udp_dataplane_admission(&args[1..])
        }
        Some("stage68-vmess-mux-dataplane-admission") => {
            run_stage68_vmess_mux_dataplane_admission(&args[1..])
        }
        Some("stage69-vmess-websocket-dataplane-admission") => {
            run_stage69_vmess_websocket_dataplane_admission(&args[1..])
        }
        Some("stage70-vmess-httpupgrade-dataplane-admission") => {
            run_stage70_vmess_httpupgrade_dataplane_admission(&args[1..])
        }
        Some("stage71-vmess-grpc-hunk-dataplane-admission") => {
            run_stage71_vmess_grpc_hunk_dataplane_admission(&args[1..])
        }
        Some("stage72-vmess-meek-polling-dataplane-admission") => {
            run_stage72_vmess_meek_polling_dataplane_admission(&args[1..])
        }
        Some("stage73-vmess-http-transport-dataplane-admission") => {
            run_stage73_vmess_http_transport_dataplane_admission(&args[1..])
        }
        Some("stage74-vless-websocket-dataplane-admission") => {
            run_stage74_vless_websocket_dataplane_admission(&args[1..])
        }
        Some("stage75-vless-httpupgrade-dataplane-admission") => {
            run_stage75_vless_httpupgrade_dataplane_admission(&args[1..])
        }
        Some("stage76-vless-grpc-hunk-dataplane-admission") => {
            run_stage76_vless_grpc_hunk_dataplane_admission(&args[1..])
        }
        Some("stage77-vless-meek-polling-dataplane-admission") => {
            run_stage77_vless_meek_polling_dataplane_admission(&args[1..])
        }
        Some("stage78-vless-http-transport-dataplane-admission") => {
            run_stage78_vless_http_transport_dataplane_admission(&args[1..])
        }
        Some("stage79-vless-xhttp-packet-dataplane-admission") => {
            run_stage79_vless_xhttp_packet_dataplane_admission(&args[1..])
        }
        Some("stage80-vless-xhttp-xmux-dataplane-admission") => {
            run_stage80_vless_xhttp_xmux_dataplane_admission(&args[1..])
        }
        Some("stage81-shared-tls-underlay-dataplane-admission") => {
            run_stage81_shared_tls_underlay_dataplane_admission(&args[1..])
        }
        Some("stage82-https-proxy-tls-dataplane-admission") => {
            run_stage82_https_proxy_tls_dataplane_admission(&args[1..])
        }
        Some("stage83-trojan-tls-dataplane-admission") => {
            run_stage83_trojan_tls_dataplane_admission(&args[1..])
        }
        Some("stage84-trojan-go-wss-dataplane-admission") => {
            run_stage84_trojan_go_wss_dataplane_admission(&args[1..])
        }
        Some("stage85-trojan-go-httpupgrade-dataplane-admission") => {
            run_stage85_trojan_go_httpupgrade_dataplane_admission(&args[1..])
        }
        Some("stage86-trojan-go-grpc-dataplane-admission") => {
            run_stage86_trojan_go_grpc_dataplane_admission(&args[1..])
        }
        Some("stage87-trojan-go-inner-shadowsocks-dataplane-admission") => {
            run_stage87_trojan_go_inner_shadowsocks_dataplane_admission(&args[1..])
        }
        Some("stage88-ss2022-tcp-dataplane-admission") => {
            run_stage88_ss2022_tcp_dataplane_admission(&args[1..])
        }
        Some("stage89-ss2022-multi-psk-tcp-dataplane-admission") => {
            run_stage89_ss2022_multi_psk_dataplane_admission(&args[1..])
        }
        Some("stage90-ss2022-udp-replay-dataplane-admission") => {
            run_stage90_ss2022_udp_dataplane_admission(&args[1..])
        }
        Some("stage91-ss2022-protocol-wide-admission") => {
            run_stage91_ss2022_protocol_admission(&args[1..])
        }
        Some("stage92-sip003-simple-obfs-http-dataplane-admission") => {
            run_stage92_sip003_simple_obfs_http_dataplane_admission(&args[1..])
        }
        Some("stage93-sip003-simple-obfs-tls-dataplane-admission") => {
            run_stage93_sip003_simple_obfs_tls_dataplane_admission(&args[1..])
        }
        Some("stage94-sip003-v2ray-plugin-dataplane-admission") => {
            run_stage94_sip003_v2ray_plugin_dataplane_admission(&args[1..])
        }
        Some("stage95-shadowsocksr-three-layer-dataplane-admission") => {
            run_stage95_shadowsocksr_three_layer_dataplane_admission(&args[1..])
        }
        Some("stage96-protocol-matrix-recertification") => {
            run_stage96_protocol_matrix_recertification(&args[1..])
        }
        Some("stage97-trojan-go-grpc-http2-tls-lifecycle-admission") => {
            run_stage97_trojan_go_grpc_http2_tls_lifecycle_admission(&args[1..])
        }
        Some("stage98-trojan-go-grpc-cache-cancellation-admission") => {
            run_stage98_trojan_go_grpc_cache_cancellation_admission(&args[1..])
        }
        Some("stage99-trojan-go-shared-transport-recertification") => {
            run_stage99_trojan_go_shared_transport_recertification(&args[1..])
        }
        Some("stage100-trojan-go-tls-fragment-admission") => {
            run_stage100_trojan_go_tls_fragment_admission(&args[1..])
        }
        Some("stage101-trojan-go-utls-fingerprint-readiness") => {
            run_stage101_trojan_go_utls_fingerprint_readiness(&args[1..])
        }
        Some("stage102-reality-session-id-mutation-readiness") => {
            run_stage102_reality_session_id_mutation_readiness(&args[1..])
        }
        Some("stage103-trojan-go-wss-tls-fragment-inner-ss-combination-admission") => {
            run_stage103_trojan_go_combination_admission(&args[1..])
        }
        Some(subcommand) => {
            RunnerOutput::usage(format!("unsupported runtime subcommand: {subcommand}"))
        }
        None => RunnerOutput::usage("missing runtime subcommand"),
    }
}

fn run_dry_run_smoke() -> RunnerOutput {
    let engine = Arc::new(Engine::new(EngineOptions::default()));
    let runner = Arc::clone(&engine);
    let handle = std::thread::spawn(move || runner.run(true));
    if let Err(err) = engine.reload_with_timeout(Duration::from_secs(1)) {
        return RunnerOutput::stdout_error(err.to_string());
    }
    if let Err(err) = engine.stop(Duration::from_secs(1)) {
        return RunnerOutput::stdout_error(err.to_string());
    }
    match handle.join() {
        Ok(Ok(())) => RunnerOutput::ok(String::new()),
        Ok(Err(err)) => RunnerOutput::stdout_error(err.to_string()),
        Err(_) => RunnerOutput::stdout_error("runtime thread panicked"),
    }
}

fn run_route_target(args: &[String]) -> RunnerOutput {
    let mut host = None;
    let mut port = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--host" => host = iter.next().map(String::as_str),
            "--port" => port = iter.next().map(String::as_str),
            _ if arg.starts_with("--host=") => {
                host = arg.split_once('=').map(|(_, value)| value);
            }
            _ if arg.starts_with("--port=") => {
                port = arg.split_once('=').map(|(_, value)| value);
            }
            _ => {
                return RunnerOutput::usage(format!(
                    "unsupported runtime route-target argument: {arg}"
                ));
            }
        }
    }
    let Some(host) = host else {
        return RunnerOutput::usage("missing runtime route-target --host");
    };
    let Some(port) = port else {
        return RunnerOutput::usage("missing runtime route-target --port");
    };
    match route_aware_dial_target(host, port) {
        Ok(target) => RunnerOutput::ok(format!(
            "{{\"domain\":{},\"dest\":{},\"dest_is_unspecified\":{}}}\n",
            json_string(&target.domain),
            json_string(&target.dest.to_string()),
            target.dest_is_unspecified()
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

fn run_overview_basic() -> RunnerOutput {
    RunnerOutput::ok(format!("{}\n", overview_basic_value()))
}

fn run_stage22_smoke() -> RunnerOutput {
    let dry = run_dry_run_smoke();
    if dry.exit_code != 0 {
        return dry;
    }
    let target = match route_aware_dial_target("example.com", "443") {
        Ok(target) => target,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let overview = overview_basic_value();
    let smoke = json!({
        "name": "stage22-runtime-smoke-helper",
        "evidence_class": "opt-in-helper-smoke",
        "default_switch_allowed": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "default_path_mutated": false,
        "live_daemon_started": false,
        "dry_runtime_reload_stop": true,
        "route_aware": {
            "host": "example.com",
            "port": "443",
            "domain": target.domain,
            "dest": target.dest.to_string(),
            "dest_is_unspecified": target.dest_is_unspecified(),
            "system_dns_resolution": false,
        },
        "runtime_overview_without_control_plane": true,
        "overview": {
            "active_connections": overview["active_connections"],
            "udp_sessions": overview["udp_sessions"],
            "udp_task_queues": overview["udp_task_queues"],
            "udp_task_drop_total": overview["udp_task_drop_total"],
            "dns_cache_hit_total": overview["dns_cache_hit_total"],
            "samples": overview["samples"],
        },
        "remaining_runtime_evidence": [
            "daemon live run smoke",
            "active TCP traffic with mark and mptcp",
            "active UDP and DNS UDP/53 traffic",
            "reload success and rollback under injected failure",
            "daemon runtime Go/Rust benchmark",
        ],
    });
    RunnerOutput::ok(format!("{}\n", smoke))
}

fn overview_basic_value() -> Value {
    let overview = RuntimeOverview::from_snapshot(
        RuntimeStatsSnapshot {
            updated_at_unix: 1_700_000_300,
            upload_rate: 10,
            download_rate: 20,
            upload_total: 30,
            download_total: 40,
            active_connections: 0,
            udp_sessions: 0,
            udp_task_queues: 99,
            udp_task_drop_total: 88,
            packet_sniffer_sessions: 77,
            rss_bytes: 50,
            heap_alloc_bytes: 60,
            goroutines: 70,
            dns: DnsObservabilityStats {
                dns_cache_hit_total: 101,
                dns_cache_expired_removal_total: 102,
                dns_udp_retry_total: 103,
                dns_truncated_tcp_fallback_total: 104,
                dns_doh_status_failure_total: 105,
                dns_doh_content_type_failure_total: 106,
                dns_upstream_refresh_success_total: 107,
                dns_upstream_refresh_failure_total: 108,
                dns_upstream_refresh_stale_reuse_total: 109,
            },
            samples: vec![RuntimeTrafficSample {
                timestamp_unix: 1_700_000_300,
                upload_rate: 11,
                download_rate: 22,
            }],
        },
        None,
    );
    json!({
        "updated_at_unix": overview.updated_at_unix,
        "upload_rate": overview.upload_rate,
        "download_rate": overview.download_rate,
        "upload_total": overview.upload_total,
        "download_total": overview.download_total,
        "active_connections": overview.active_connections,
        "udp_sessions": overview.udp_sessions,
        "udp_task_queues": overview.udp_task_queues,
        "udp_task_drop_total": overview.udp_task_drop_total,
        "packet_sniffer_sessions": overview.packet_sniffer_sessions,
        "rss_bytes": overview.rss_bytes,
        "heap_alloc_bytes": overview.heap_alloc_bytes,
        "goroutines": overview.goroutines,
        "dns_cache_hit_total": overview.dns.dns_cache_hit_total,
        "dns_cache_expired_removal_total": overview.dns.dns_cache_expired_removal_total,
        "dns_udp_retry_total": overview.dns.dns_udp_retry_total,
        "dns_truncated_tcp_fallback_total": overview.dns.dns_truncated_tcp_fallback_total,
        "dns_doh_status_failure_total": overview.dns.dns_doh_status_failure_total,
        "dns_doh_content_type_failure_total": overview.dns.dns_doh_content_type_failure_total,
        "dns_upstream_refresh_success_total": overview.dns.dns_upstream_refresh_success_total,
        "dns_upstream_refresh_failure_total": overview.dns.dns_upstream_refresh_failure_total,
        "dns_upstream_refresh_stale_reuse_total": overview.dns.dns_upstream_refresh_stale_reuse_total,
        "samples": overview.samples.iter().map(|sample| {
            json!({
                "timestamp_unix": sample.timestamp_unix,
                "upload_rate": sample.upload_rate,
                "download_rate": sample.download_rate,
            })
        }).collect::<Vec<_>>(),
    })
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                write!(out, "\\u{:04x}", ch as u32).unwrap();
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}
