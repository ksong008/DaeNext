use std::fs;
use std::path::{Path, PathBuf};

use dae_ebpf_support::{map_ids, open_live_loaded_tproxy_listen_socket_map_in_netns};
use serde_json::{Value, json};

mod active_dns;
mod active_tcp;
mod active_udp;
mod command;
mod reload_runtime;
mod report;
mod resident;
mod topology;
mod udp_io;

use active_dns::{
    ActiveDnsEvidence, DEFAULT_ACTIVE_DNS_QNAME, DEFAULT_ACTIVE_DNS_TARGET_IP,
    DEFAULT_ACTIVE_DNS_TARGET_PORT, DEFAULT_ACTIVE_DNS_UPSTREAM_IP,
    DEFAULT_ACTIVE_DNS_UPSTREAM_PORT, push_active_dns_preflight_checks, run_active_dns_probe,
};
use active_tcp::{
    ActiveTcpEvidence, DEFAULT_ACTIVE_TCP_CLIENT_IP, DEFAULT_ACTIVE_TCP_MPTCP,
    DEFAULT_ACTIVE_TCP_SO_MARK, DEFAULT_ACTIVE_TCP_TARGET_IP, DEFAULT_ACTIVE_TCP_TARGET_PORT,
    attach_lan_program, cleanup_active_tcp_resources, push_active_tcp_preflight_checks,
    run_active_tcp_probe, setup_client_topology, setup_production_ipv4_datapath,
    show_host_program_stats, show_lan_program, show_lan_program_stats, show_peer_program_stats,
    update_routing_map,
};
use active_udp::{
    ActiveUdpEvidence, DEFAULT_ACTIVE_UDP_TARGET_IP, DEFAULT_ACTIVE_UDP_TARGET_PORT,
    active_udp_loopback_target_present, add_active_udp_loopback_target,
    delete_active_udp_loopback_target, push_active_udp_preflight_checks, run_active_udp_probe,
};
use command::{
    bpf_dae_snapshot, ensure_safe_run_root, path_string, runtime_resource_leftovers,
    wait_for_loaded_map_cleanup,
};
use reload_runtime::{ReloadRuntimeEvidence, run_reload_runtime_parity_probe};
use report::{live_handoff_json, report_value, socket_options_verified};
pub use resident::{ResidentProductionRuntime, start_resident_production_runtime};
use topology::{
    attach_host_program, attach_peer_program, cleanup_production_topology, preflight_checks,
    read_topology_values, setup_production_topology, show_host_program, show_peer_program,
    write_param_image,
};

const DEFAULT_SOURCE_OBJECT: &str = "control/bpf_bpfel.o";
const DEFAULT_PEER_SECTION: &str = "tc/dae0peer_ingress";
const DEFAULT_HOST_SECTION: &str = "tc/dae0_ingress";
const DEFAULT_TPROXY_PORT: u16 = 12345;
const DEFAULT_DAE_NETNS_ID: u32 = 49;
const FILTER_PREF: &str = "49491";
const PRODUCTION_NETNS: &str = "daens";
const PRODUCTION_HOST_IFACE: &str = "dae0";
const PRODUCTION_PEER_IFACE: &str = "dae0peer";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionRuntimeOwnerOptions {
    pub execute: bool,
    pub ack_root_gate: bool,
    pub source_object: PathBuf,
    pub tproxy_port: u16,
    pub dae_netns_id: u32,
    pub peer_section: String,
    pub host_section: String,
    pub execute_active_tcp: bool,
    pub active_tcp_target_ip: String,
    pub active_tcp_client_ip: String,
    pub active_tcp_target_port: u16,
    pub active_tcp_so_mark: u32,
    pub active_tcp_mptcp: bool,
    pub execute_active_tcp_relay: bool,
    pub active_tcp_upstream_mptcp: bool,
    pub active_tcp_benchmark_iters: u32,
    pub execute_active_udp: bool,
    pub active_udp_target_ip: String,
    pub active_udp_target_port: u16,
    pub active_udp_benchmark_iters: u32,
    pub execute_active_dns: bool,
    pub active_dns_target_ip: String,
    pub active_dns_target_port: u16,
    pub active_dns_upstream_ip: String,
    pub active_dns_upstream_port: u16,
    pub active_dns_qname: String,
    pub active_dns_benchmark_iters: u32,
    pub execute_reload_runtime_parity: bool,
}

impl Default for ProductionRuntimeOwnerOptions {
    fn default() -> Self {
        Self {
            execute: false,
            ack_root_gate: false,
            source_object: PathBuf::from(DEFAULT_SOURCE_OBJECT),
            tproxy_port: DEFAULT_TPROXY_PORT,
            dae_netns_id: DEFAULT_DAE_NETNS_ID,
            peer_section: DEFAULT_PEER_SECTION.to_owned(),
            host_section: DEFAULT_HOST_SECTION.to_owned(),
            execute_active_tcp: false,
            active_tcp_target_ip: DEFAULT_ACTIVE_TCP_TARGET_IP.to_owned(),
            active_tcp_client_ip: DEFAULT_ACTIVE_TCP_CLIENT_IP.to_owned(),
            active_tcp_target_port: DEFAULT_ACTIVE_TCP_TARGET_PORT,
            active_tcp_so_mark: DEFAULT_ACTIVE_TCP_SO_MARK,
            active_tcp_mptcp: DEFAULT_ACTIVE_TCP_MPTCP,
            execute_active_tcp_relay: false,
            active_tcp_upstream_mptcp: true,
            active_tcp_benchmark_iters: 5,
            execute_active_udp: false,
            active_udp_target_ip: DEFAULT_ACTIVE_UDP_TARGET_IP.to_owned(),
            active_udp_target_port: DEFAULT_ACTIVE_UDP_TARGET_PORT,
            active_udp_benchmark_iters: 5,
            execute_active_dns: false,
            active_dns_target_ip: DEFAULT_ACTIVE_DNS_TARGET_IP.to_owned(),
            active_dns_target_port: DEFAULT_ACTIVE_DNS_TARGET_PORT,
            active_dns_upstream_ip: DEFAULT_ACTIVE_DNS_UPSTREAM_IP.to_owned(),
            active_dns_upstream_port: DEFAULT_ACTIVE_DNS_UPSTREAM_PORT,
            active_dns_qname: DEFAULT_ACTIVE_DNS_QNAME.to_owned(),
            active_dns_benchmark_iters: 5,
            execute_reload_runtime_parity: false,
        }
    }
}

pub fn production_runtime_owner_report(
    run_root: &Path,
    options: &ProductionRuntimeOwnerOptions,
) -> Result<Value, String> {
    validate_options(options)?;
    ensure_safe_run_root(run_root)?;
    if options.execute && !options.source_object.is_file() {
        return Err(format!(
            "production runtime owner source object does not exist: {}",
            path_string(&options.source_object)
        ));
    }

    let artifact_dir = run_root.join("run").join("production-runtime-owner");
    let manifest_file = artifact_dir.join("production-runtime-owner.json");
    let param_object = artifact_dir.join("bpf_bpfel.param.o");
    let mut checks = preflight_checks(options);
    push_active_tcp_preflight_checks(&mut checks, options);
    push_active_udp_preflight_checks(&mut checks, options);
    push_active_dns_preflight_checks(&mut checks, options);

    if !options.execute {
        return Ok(report_value(
            options,
            &artifact_dir,
            &manifest_file,
            &param_object,
            checks,
            ExecutionEvidence::default(),
        ));
    }

    let blockers = checks
        .iter()
        .filter(|check| check["status"].as_str() != Some("pass"))
        .filter_map(|check| check["blocker"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    if !blockers.is_empty() {
        return Err(format!(
            "production runtime owner preflight failed: {}",
            blockers.join("; ")
        ));
    }

    fs::create_dir_all(&artifact_dir).map_err(|err| {
        format!(
            "failed to create production runtime owner artifact dir {}: {err}",
            path_string(&artifact_dir)
        )
    })?;
    let evidence = execute_owner_smoke(options, &param_object)?;
    let report = report_value(
        options,
        &artifact_dir,
        &manifest_file,
        &param_object,
        checks,
        evidence,
    );
    let encoded = serde_json::to_vec_pretty(&report)
        .map_err(|err| format!("failed to encode production runtime owner report: {err}"))?;
    fs::write(&manifest_file, encoded).map_err(|err| {
        format!(
            "failed to write production runtime owner manifest {}: {err}",
            path_string(&manifest_file)
        )
    })?;
    if report["daemon_owned_production_runtime_owner_smoke_passed"]
        .as_bool()
        .unwrap_or(false)
    {
        Ok(report)
    } else {
        Err(format!(
            "production runtime owner smoke failed; manifest={}",
            path_string(&manifest_file)
        ))
    }
}

fn validate_options(options: &ProductionRuntimeOwnerOptions) -> Result<(), String> {
    if options.tproxy_port == 0 {
        return Err("production runtime owner tproxy port must be non-zero".to_owned());
    }
    if options.dae_netns_id == 0 {
        return Err("production runtime owner dae netns id must be non-zero".to_owned());
    }
    if options.execute_active_tcp && !options.execute {
        return Err(
            "production runtime active TCP requires --execute-production-runtime-owner".to_owned(),
        );
    }
    if options.execute_active_tcp_relay && !options.execute_active_tcp {
        return Err(
            "production runtime active TCP relay requires --execute-production-runtime-active-tcp"
                .to_owned(),
        );
    }
    if options.execute_active_udp && !options.execute_active_tcp {
        return Err(
            "production runtime active UDP requires --execute-production-runtime-active-tcp"
                .to_owned(),
        );
    }
    if options.execute_active_dns && !options.execute_active_udp {
        return Err(
            "production runtime active DNS requires --execute-production-runtime-active-udp"
                .to_owned(),
        );
    }
    if options.execute_reload_runtime_parity && !options.execute_active_tcp {
        return Err(
            "production reload/runtime parity requires --execute-production-runtime-active-tcp"
                .to_owned(),
        );
    }
    if options.active_tcp_target_port == 0 {
        return Err("production runtime active TCP target port must be non-zero".to_owned());
    }
    if options.active_tcp_benchmark_iters == 0 {
        return Err(
            "production runtime active TCP benchmark iterations must be non-zero".to_owned(),
        );
    }
    if options.active_udp_target_port == 0 {
        return Err("production runtime active UDP target port must be non-zero".to_owned());
    }
    if options.active_udp_benchmark_iters == 0 {
        return Err(
            "production runtime active UDP benchmark iterations must be non-zero".to_owned(),
        );
    }
    if options.active_dns_target_port != 53 {
        return Err("production runtime active DNS target port must be UDP/53".to_owned());
    }
    if options.active_dns_upstream_port == 0 {
        return Err("production runtime active DNS upstream port must be non-zero".to_owned());
    }
    if options.active_dns_benchmark_iters == 0 {
        return Err(
            "production runtime active DNS benchmark iterations must be non-zero".to_owned(),
        );
    }
    if options.execute && !options.ack_root_gate {
        return Err(
            "production runtime owner requires --ack-root-gate with --execute-production-runtime-owner"
                .to_owned(),
        );
    }
    Ok(())
}

#[derive(Default)]
struct ExecutionEvidence {
    executed_steps: Vec<Value>,
    cleanup_steps: Vec<Value>,
    topology_values: Value,
    param_image: Value,
    peer_attach_show: Value,
    host_attach_show: Value,
    loaded_map_handoff: Value,
    before_map_ids: Vec<u32>,
    after_map_ids: Vec<u32>,
    discovered_map_id: Option<u32>,
    discovered_routing_map_id: Option<u32>,
    loaded_map_cleaned: bool,
    leftovers_after_cleanup: Vec<String>,
    sys_fs_bpf_dae_mutated: bool,
    socket_options_verified: bool,
    active_tcp: ActiveTcpEvidence,
    active_udp: ActiveUdpEvidence,
    active_dns: ActiveDnsEvidence,
    reload_runtime: ReloadRuntimeEvidence,
    owner_smoke_passed: bool,
}

fn execute_owner_smoke(
    options: &ProductionRuntimeOwnerOptions,
    param_object: &Path,
) -> Result<ExecutionEvidence, String> {
    let before_pin_snapshot = bpf_dae_snapshot();
    let before_map_ids = map_ids()
        .map_err(|err| format!("production runtime owner cannot snapshot BPF map ids: {err}"))?;
    let mut evidence = ExecutionEvidence {
        before_map_ids: before_map_ids.clone(),
        ..ExecutionEvidence::default()
    };

    let mut ok = true;
    ok &= setup_production_topology(&mut evidence.executed_steps, options);
    if options.execute_active_tcp {
        ok &= setup_client_topology(&mut evidence.executed_steps, options);
    }
    let (topology_values, dae0_ifindex, dae0_mac, dae0peer_mac) =
        read_topology_values(&mut evidence.executed_steps, options);
    evidence.topology_values = topology_values;
    ok &= dae0_ifindex.is_some() && dae0peer_mac.is_some();
    if options.execute_active_tcp {
        if let Some(dae0_mac) = dae0_mac {
            ok &= setup_production_ipv4_datapath(&mut evidence.executed_steps, dae0_mac);
        } else {
            ok = false;
        }
    }

    evidence.param_image = match (dae0_ifindex, dae0peer_mac) {
        (Some(dae0_ifindex), Some(dae0peer_mac)) => {
            write_param_image(options, param_object, dae0_ifindex, dae0peer_mac)
        }
        _ => json!({
            "status": "skipped",
            "path": path_string(param_object),
            "reason": "topology runtime PARAM values were not available",
        }),
    };
    ok &= evidence.param_image["status"].as_str() == Some("pass")
        && evidence.param_image["rewritten_param_matches"]
            .as_bool()
            .unwrap_or(false);

    if ok {
        ok &= attach_peer_program(&mut evidence.executed_steps, options, param_object);
    }
    evidence.peer_attach_show = show_peer_program(&mut evidence.executed_steps);

    let mut live_handoff = None;
    if ok {
        match open_live_loaded_tproxy_listen_socket_map_in_netns(
            &before_map_ids,
            options.tproxy_port,
            PRODUCTION_NETNS,
        ) {
            Ok(handoff) => {
                evidence.socket_options_verified =
                    socket_options_verified(&handoff.tcp_options, &handoff.udp_options);
                evidence.discovered_map_id = Some(handoff.map.id);
                evidence.loaded_map_handoff = live_handoff_json(&handoff);
                live_handoff = Some(handoff);
            }
            Err(err) => {
                ok = false;
                evidence.loaded_map_handoff = json!({
                    "status": "fail",
                    "error": err.to_string(),
                });
            }
        }
    } else {
        evidence.loaded_map_handoff = json!({
            "status": "skipped",
            "reason": "peer PARAM-aware attach did not pass",
        });
    }
    ok &= evidence.socket_options_verified;

    if options.execute_active_tcp && ok {
        let before_lan_map_ids = map_ids().unwrap_or_default();
        ok &= attach_lan_program(&mut evidence.executed_steps, options, param_object);
        evidence.active_tcp.lan_attach_show = show_lan_program(&mut evidence.executed_steps);
        match update_routing_map(&before_lan_map_ids, options.active_tcp_so_mark) {
            Ok((value, id)) => {
                evidence.active_tcp.route_map_update = value;
                evidence.active_tcp.discovered_routing_map_id = Some(id);
                evidence.discovered_routing_map_id = Some(id);
            }
            Err(err) => {
                ok = false;
                evidence.active_tcp.route_map_update = json!({"status": "fail", "error": err});
            }
        }
    }

    if ok {
        ok &= attach_host_program(&mut evidence.executed_steps, options, param_object);
    }
    evidence.host_attach_show = show_host_program(&mut evidence.executed_steps);

    if options.execute_active_tcp {
        evidence.active_tcp.enabled = true;
        if ok {
            let listener = live_handoff
                .as_ref()
                .and_then(|handoff| handoff.listeners.tcp_listener.try_clone().ok());
            match listener {
                Some(listener) => {
                    let relay_listener = if options.execute_active_tcp_relay {
                        listener.try_clone().ok()
                    } else {
                        None
                    };
                    let (
                        tcp_accept,
                        client_traffic,
                        original_destination_observed,
                        tcp_reply_path_succeeded,
                    ) = run_active_tcp_probe(listener, options);
                    evidence.active_tcp.tcp_accept = tcp_accept;
                    evidence.active_tcp.client_traffic = client_traffic;
                    evidence.active_tcp.original_destination_observed =
                        original_destination_observed;
                    evidence.active_tcp.tcp_reply_path_succeeded = tcp_reply_path_succeeded;
                    evidence.active_tcp.passed = evidence.active_tcp.tcp_accept["status"].as_str()
                        == Some("pass")
                        && evidence.active_tcp.client_traffic["status"].as_str() == Some("pass")
                        && original_destination_observed
                        && tcp_reply_path_succeeded;
                    if let Some(relay_listener) = relay_listener {
                        let (
                            relay_accept,
                            upstream,
                            relay_client_traffic,
                            outbound_dial,
                            benchmark,
                            relay_original_destination_observed,
                            outbound_relay_succeeded,
                            so_mark_observed,
                            mptcp_observed,
                        ) = active_tcp::run_active_tcp_relay_probe(relay_listener, options);
                        evidence.active_tcp.relay_accept = relay_accept;
                        evidence.active_tcp.upstream = upstream;
                        evidence.active_tcp.relay_client_traffic = relay_client_traffic;
                        evidence.active_tcp.outbound_dial = outbound_dial;
                        evidence.active_tcp.relay_benchmark = benchmark;
                        evidence.active_tcp.relay_original_destination_observed =
                            relay_original_destination_observed;
                        evidence.active_tcp.outbound_relay_succeeded = outbound_relay_succeeded;
                        evidence.active_tcp.so_mark_observed = so_mark_observed;
                        evidence.active_tcp.mptcp_observed = mptcp_observed;
                        evidence.active_tcp.relay_passed =
                            evidence.active_tcp.relay_accept["status"].as_str() == Some("pass")
                                && evidence.active_tcp.upstream["status"].as_str() == Some("pass")
                                && evidence.active_tcp.relay_client_traffic["status"].as_str()
                                    == Some("pass")
                                && relay_original_destination_observed
                                && outbound_relay_succeeded
                                && so_mark_observed
                                && (!options.active_tcp_mptcp || mptcp_observed);
                        evidence.active_tcp.passed &=
                            !options.execute_active_tcp_relay || evidence.active_tcp.relay_passed;
                    } else if options.execute_active_tcp_relay {
                        evidence.active_tcp.relay_accept = json!({
                            "status": "fail",
                            "error": "failed to clone tproxy TCP listener for relay",
                        });
                        evidence.active_tcp.passed = false;
                    }
                }
                None => {
                    evidence.active_tcp.tcp_accept =
                        json!({"status": "fail", "error": "failed to clone tproxy TCP listener"});
                }
            }
        } else {
            evidence.active_tcp.tcp_accept = json!({
                "status": "skipped",
                "reason": "BPF attach or routing map update did not pass",
            });
        }
        evidence.active_tcp.post_traffic_peer_stats =
            show_peer_program_stats(&mut evidence.executed_steps);
        evidence.active_tcp.post_traffic_lan_stats =
            show_lan_program_stats(&mut evidence.executed_steps);
        evidence.active_tcp.post_traffic_host_stats =
            show_host_program_stats(&mut evidence.executed_steps);
        ok &= evidence.active_tcp.passed;
    }

    if options.execute_active_udp {
        if ok {
            ok &= add_active_udp_loopback_target(&mut evidence.executed_steps, options);
            let udp_socket = live_handoff
                .as_ref()
                .and_then(|handoff| handoff.listeners.udp_socket.try_clone().ok());
            match udp_socket {
                Some(udp_socket) => {
                    evidence.active_udp = run_active_udp_probe(udp_socket, options);
                    ok &= evidence.active_udp.passed;
                }
                None => {
                    evidence.active_udp = ActiveUdpEvidence {
                        enabled: true,
                        udp_receive: json!({
                            "status": "fail",
                            "error": "failed to clone tproxy UDP socket for active UDP",
                        }),
                        ..ActiveUdpEvidence::default()
                    };
                    ok = false;
                }
            }
        } else {
            evidence.active_udp = ActiveUdpEvidence {
                enabled: true,
                udp_receive: json!({
                    "status": "skipped",
                    "reason": "production owner or active TCP evidence did not pass before active UDP",
                }),
                ..ActiveUdpEvidence::default()
            };
        }
        evidence.active_udp.post_traffic_peer_stats =
            show_peer_program_stats(&mut evidence.executed_steps);
        evidence.active_udp.post_traffic_lan_stats =
            show_lan_program_stats(&mut evidence.executed_steps);
        evidence.active_udp.post_traffic_host_stats =
            show_host_program_stats(&mut evidence.executed_steps);
    }

    if options.execute_active_dns {
        if ok {
            let udp_socket = live_handoff
                .as_ref()
                .and_then(|handoff| handoff.listeners.udp_socket.try_clone().ok());
            match udp_socket {
                Some(udp_socket) => {
                    evidence.active_dns = run_active_dns_probe(udp_socket, options);
                    ok &= evidence.active_dns.passed;
                }
                None => {
                    evidence.active_dns = ActiveDnsEvidence {
                        enabled: true,
                        dns_receive: json!({
                            "status": "fail",
                            "error": "failed to clone tproxy UDP socket for active DNS",
                        }),
                        ..ActiveDnsEvidence::default()
                    };
                    ok = false;
                }
            }
        } else {
            evidence.active_dns = ActiveDnsEvidence {
                enabled: true,
                dns_receive: json!({
                    "status": "skipped",
                    "reason": "production owner, active TCP, or active UDP evidence did not pass before active DNS",
                }),
                ..ActiveDnsEvidence::default()
            };
        }
        evidence.active_dns.post_traffic_peer_stats =
            show_peer_program_stats(&mut evidence.executed_steps);
        evidence.active_dns.post_traffic_lan_stats =
            show_lan_program_stats(&mut evidence.executed_steps);
        evidence.active_dns.post_traffic_host_stats =
            show_host_program_stats(&mut evidence.executed_steps);
    }

    if options.execute_reload_runtime_parity {
        if ok {
            match live_handoff.as_ref() {
                Some(handoff) => {
                    let post_reload_tcp_listener = handoff.listeners.tcp_listener.try_clone().ok();
                    let artifact_dir = param_object.parent().unwrap_or_else(|| Path::new("/tmp"));
                    evidence.reload_runtime = run_reload_runtime_parity_probe(
                        handoff,
                        options,
                        artifact_dir,
                        post_reload_tcp_listener,
                    );
                    ok &= evidence.reload_runtime.passed;
                }
                None => {
                    evidence.reload_runtime = ReloadRuntimeEvidence {
                        enabled: true,
                        listener_reuse: json!({
                            "status": "fail",
                            "error": "live production listener/sockmap handoff was unavailable",
                        }),
                        ..ReloadRuntimeEvidence::default()
                    };
                    ok = false;
                }
            }
        } else {
            evidence.reload_runtime = ReloadRuntimeEvidence {
                enabled: true,
                listener_reuse: json!({
                    "status": "skipped",
                    "reason": "production owner or active TCP evidence did not pass before reload/runtime parity",
                }),
                ..ReloadRuntimeEvidence::default()
            };
        }
    }

    let peer_output = evidence.peer_attach_show["stdout"]
        .as_str()
        .unwrap_or_default();
    let host_output = evidence.host_attach_show["stdout"]
        .as_str()
        .unwrap_or_default();
    let attach_outputs_passed = evidence.peer_attach_show["status"].as_str() == Some("pass")
        && peer_output.contains(&options.peer_section)
        && peer_output.contains("tproxy_dae0peer")
        && evidence.host_attach_show["status"].as_str() == Some("pass")
        && host_output.contains(&options.host_section)
        && host_output.contains("tproxy_dae0_ing");

    drop(live_handoff);
    if options.execute_active_udp {
        delete_active_udp_loopback_target(&mut evidence.cleanup_steps, options);
    }
    if options.execute_active_tcp {
        cleanup_active_tcp_resources(&mut evidence.cleanup_steps);
    }
    cleanup_production_topology(&mut evidence.cleanup_steps);
    let after_pin_snapshot = bpf_dae_snapshot();
    let (after_map_ids, loaded_map_cleaned) = wait_for_loaded_map_cleanup(&[
        evidence.discovered_map_id,
        evidence.discovered_routing_map_id,
    ]);
    evidence.after_map_ids = after_map_ids;
    evidence.loaded_map_cleaned = loaded_map_cleaned;
    evidence.leftovers_after_cleanup = runtime_resource_leftovers(options.execute_active_tcp);
    if options.execute_active_udp
        && active_udp_loopback_target_present(&options.active_udp_target_ip)
    {
        evidence.leftovers_after_cleanup.push(format!(
            "loopback-target:{}/32",
            options.active_udp_target_ip
        ));
    }
    evidence.sys_fs_bpf_dae_mutated = before_pin_snapshot != after_pin_snapshot;
    evidence.owner_smoke_passed = ok
        && attach_outputs_passed
        && loaded_map_cleaned
        && evidence.leftovers_after_cleanup.is_empty()
        && !evidence.sys_fs_bpf_dae_mutated;
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_runtime_owner_report_is_read_only_by_default() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-production-runtime-default-{}",
            std::process::id()
        ));
        let report =
            production_runtime_owner_report(&root, &ProductionRuntimeOwnerOptions::default())
                .unwrap();
        assert!(
            !report["daemon_owned_production_runtime_owner_executed"]
                .as_bool()
                .unwrap()
        );
        assert!(
            !report["daemon_owned_production_runtime_owner_smoke_passed"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(
            report["production_runtime_owner_scope"].as_str().unwrap(),
            "not-executed"
        );
        assert!(!report["production_dataplane_admitted"].as_bool().unwrap());
        assert!(
            !report["production_runtime_active_tcp_executed"]
                .as_bool()
                .unwrap()
        );
        assert!(
            !report["production_runtime_active_tcp_passed"]
                .as_bool()
                .unwrap()
        );
        assert!(
            !report["production_runtime_active_udp_executed"]
                .as_bool()
                .unwrap()
        );
        assert!(
            !report["production_runtime_active_dns_executed"]
                .as_bool()
                .unwrap()
        );
        assert!(
            !report["production_reload_runtime_parity_executed"]
                .as_bool()
                .unwrap()
        );
        assert!(!report["reload_runtime_parity_admitted"].as_bool().unwrap());
        assert!(!report["default_switch_allowed"].as_bool().unwrap());
    }

    #[test]
    fn production_runtime_owner_execute_requires_root_gate_ack() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-production-runtime-noack-{}",
            std::process::id()
        ));
        let options = ProductionRuntimeOwnerOptions {
            execute: true,
            ..ProductionRuntimeOwnerOptions::default()
        };
        let err = production_runtime_owner_report(&root, &options).unwrap_err();
        assert!(err.contains("--ack-root-gate"));
    }

    #[test]
    fn production_runtime_owner_rejects_zero_tproxy_port() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-production-runtime-zero-port-{}",
            std::process::id()
        ));
        let options = ProductionRuntimeOwnerOptions {
            tproxy_port: 0,
            ..ProductionRuntimeOwnerOptions::default()
        };
        let err = production_runtime_owner_report(&root, &options).unwrap_err();
        assert!(err.contains("tproxy port"));
    }

    #[test]
    fn production_runtime_active_tcp_requires_owner_execution() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-production-runtime-active-tcp-without-owner-{}",
            std::process::id()
        ));
        let options = ProductionRuntimeOwnerOptions {
            ack_root_gate: true,
            execute_active_tcp: true,
            ..ProductionRuntimeOwnerOptions::default()
        };
        let err = production_runtime_owner_report(&root, &options).unwrap_err();
        assert!(err.contains("--execute-production-runtime-owner"));
    }

    #[test]
    fn production_runtime_active_tcp_relay_requires_active_tcp() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-production-runtime-active-tcp-relay-without-tcp-{}",
            std::process::id()
        ));
        let options = ProductionRuntimeOwnerOptions {
            execute: true,
            ack_root_gate: true,
            execute_active_tcp_relay: true,
            ..ProductionRuntimeOwnerOptions::default()
        };
        let err = production_runtime_owner_report(&root, &options).unwrap_err();
        assert!(err.contains("--execute-production-runtime-active-tcp"));
    }

    #[test]
    fn production_runtime_active_udp_requires_active_tcp() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-production-runtime-active-udp-without-tcp-{}",
            std::process::id()
        ));
        let options = ProductionRuntimeOwnerOptions {
            execute: true,
            ack_root_gate: true,
            execute_active_udp: true,
            ..ProductionRuntimeOwnerOptions::default()
        };
        let err = production_runtime_owner_report(&root, &options).unwrap_err();
        assert!(err.contains("--execute-production-runtime-active-tcp"));
    }

    #[test]
    fn production_runtime_active_dns_requires_active_udp() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-production-runtime-active-dns-without-udp-{}",
            std::process::id()
        ));
        let options = ProductionRuntimeOwnerOptions {
            execute: true,
            ack_root_gate: true,
            execute_active_tcp: true,
            execute_active_dns: true,
            ..ProductionRuntimeOwnerOptions::default()
        };
        let err = production_runtime_owner_report(&root, &options).unwrap_err();
        assert!(err.contains("--execute-production-runtime-active-udp"));
    }

    #[test]
    fn production_runtime_active_dns_requires_udp53_target() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-production-runtime-active-dns-non53-{}",
            std::process::id()
        ));
        let options = ProductionRuntimeOwnerOptions {
            active_dns_target_port: 5353,
            ..ProductionRuntimeOwnerOptions::default()
        };
        let err = production_runtime_owner_report(&root, &options).unwrap_err();
        assert!(err.contains("UDP/53"));
    }

    #[test]
    fn production_reload_runtime_parity_requires_active_tcp() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-production-runtime-reload-without-tcp-{}",
            std::process::id()
        ));
        let options = ProductionRuntimeOwnerOptions {
            execute: true,
            ack_root_gate: true,
            execute_reload_runtime_parity: true,
            ..ProductionRuntimeOwnerOptions::default()
        };
        let err = production_runtime_owner_report(&root, &options).unwrap_err();
        assert!(err.contains("--execute-production-runtime-active-tcp"));
    }
}
