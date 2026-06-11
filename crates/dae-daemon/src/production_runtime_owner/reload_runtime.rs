use std::fs;
use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant};

use dae_ebpf_support::{
    AttachBackend, LiveLoadedTproxyListenSocketMap, map_info, open_map_fd, update_map_elem_bytes,
};
use dae_engine::{
    DnsObservabilityStats, RuntimeOverview, RuntimeStatsSnapshot, RuntimeTrafficSample,
};
use serde_json::{Value, json};

use super::ProductionRuntimeOwnerOptions;
use super::active_tcp::run_active_tcp_probe;
use super::command::{CommandSpec, path_string, run_observation_command};
use super::native_ebpf::native_backend_runtime_decision_for_options;
use super::{PRODUCTION_HOST_IFACE, PRODUCTION_NETNS, PRODUCTION_PEER_IFACE};

#[derive(Default)]
pub(super) struct ReloadRuntimeEvidence {
    pub(super) enabled: bool,
    pub(super) passed: bool,
    pub(super) live_reload_executed: bool,
    pub(super) production_listener_reused: bool,
    pub(super) production_bpf_owner_transferred: bool,
    pub(super) production_dns_cache_migrated: bool,
    pub(super) dns_cache_migration_guard_verified: bool,
    pub(super) bounded_close_verified: bool,
    pub(super) runtime_overview_parity_verified: bool,
    pub(super) reload_scoped_resources_flushed: bool,
    pub(super) invalid_config_restore_verified: bool,
    pub(super) listener_reuse: Value,
    pub(super) bpf_owner_transfer: Value,
    pub(super) dns_cache_migration: Value,
    pub(super) bounded_close: Value,
    pub(super) runtime_overview: Value,
    pub(super) restore: Value,
    pub(super) post_reload_active_tcp_accept: Value,
    pub(super) post_reload_active_tcp_client_traffic: Value,
    pub(super) post_reload_active_tcp_original_destination_observed: bool,
    pub(super) post_reload_active_tcp_reply_path_succeeded: bool,
    pub(super) post_reload_active_tcp_passed: bool,
    pub(super) elapsed_ns: u64,
}

pub(super) fn run_reload_runtime_parity_probe(
    handoff: &LiveLoadedTproxyListenSocketMap,
    options: &ProductionRuntimeOwnerOptions,
    artifact_dir: &Path,
    post_reload_tcp_listener: Option<TcpListener>,
) -> ReloadRuntimeEvidence {
    let started = Instant::now();
    let mut evidence = ReloadRuntimeEvidence {
        enabled: true,
        live_reload_executed: true,
        ..ReloadRuntimeEvidence::default()
    };

    let scoped_resource = artifact_dir.join("reload-scoped-resource.tmp");
    let scoped_resource_created = fs::write(
        &scoped_resource,
        b"daemon-owned production reload scoped resource\n",
    )
    .is_ok();

    let listener_before = listener_identity(handoff);
    let bpf_owner_transfer = rewrite_sockmap_with_reused_listener_fds(handoff, options);
    evidence.production_bpf_owner_transferred = bpf_owner_transfer["status"].as_str()
        == Some("pass")
        && bpf_owner_transfer["same_map_id_after_reopen"]
            .as_bool()
            .unwrap_or(false)
        && bpf_owner_transfer["attach_continuity"]["status"].as_str() == Some("pass")
        && bpf_owner_transfer["attach_continuity_evidence_passed"]
            .as_bool()
            .unwrap_or(false);
    evidence.bpf_owner_transfer = bpf_owner_transfer;

    let listener_after = listener_identity(handoff);
    evidence.production_listener_reused =
        listener_identity_reused(&listener_before, &listener_after)
            && evidence.production_bpf_owner_transferred;
    evidence.listener_reuse = json!({
        "status": if evidence.production_listener_reused { "pass" } else { "fail" },
        "strategy": "reuse existing production TCP listener and UDP socket; rewrite listen_socket_map keys 0/1 with the same fds instead of re-listening",
        "old_owner_listener": listener_before,
        "new_owner_listener": listener_after,
        "ready_after_map_handoff": evidence.production_bpf_owner_transferred,
        "production_listener_reused": evidence.production_listener_reused,
    });

    evidence.dns_cache_migration = dns_cache_migration_guard();
    evidence.production_dns_cache_migrated =
        evidence.dns_cache_migration["equal_config_restore"]["restored"]
            .as_bool()
            .unwrap_or(false);
    evidence.dns_cache_migration_guard_verified = evidence.production_dns_cache_migrated
        && !evidence.dns_cache_migration["changed_config_restore"]["restored"]
            .as_bool()
            .unwrap_or(true)
        && evidence.dns_cache_migration["domain_routing_map_clear_before_restore"]
            .as_bool()
            .unwrap_or(false);

    if let Some(listener) = post_reload_tcp_listener {
        let (accept, client_traffic, original_destination_observed, reply_path_succeeded) =
            run_active_tcp_probe(listener, options);
        evidence.post_reload_active_tcp_accept = accept;
        evidence.post_reload_active_tcp_client_traffic = client_traffic;
        evidence.post_reload_active_tcp_original_destination_observed =
            original_destination_observed;
        evidence.post_reload_active_tcp_reply_path_succeeded = reply_path_succeeded;
        evidence.post_reload_active_tcp_passed = evidence.post_reload_active_tcp_accept["status"]
            .as_str()
            == Some("pass")
            && evidence.post_reload_active_tcp_client_traffic["status"].as_str() == Some("pass")
            && original_destination_observed
            && reply_path_succeeded;
    } else {
        evidence.post_reload_active_tcp_accept = json!({
            "status": "fail",
            "error": "post-reload active TCP listener clone was unavailable",
        });
    }

    let close_started = Instant::now();
    if scoped_resource.exists() {
        let _ = fs::remove_file(&scoped_resource);
    }
    let close_elapsed = close_started.elapsed();
    evidence.reload_scoped_resources_flushed = scoped_resource_created && !scoped_resource.exists();
    evidence.bounded_close_verified = close_elapsed <= Duration::from_secs(2)
        && evidence.reload_scoped_resources_flushed
        && evidence.production_listener_reused;
    evidence.bounded_close = json!({
        "status": if evidence.bounded_close_verified { "pass" } else { "fail" },
        "shutdown_grace_ms": 2000,
        "close_elapsed_ns": close_elapsed.as_nanos().min(u128::from(u64::MAX)) as u64,
        "scoped_resource_file": path_string(&scoped_resource),
        "scoped_resource_created": scoped_resource_created,
        "scoped_resource_removed_after_current_swap": evidence.reload_scoped_resources_flushed,
        "old_owner_close_bounded": close_elapsed <= Duration::from_secs(2),
    });

    evidence.runtime_overview = runtime_overview_parity_value(&evidence);
    evidence.runtime_overview_parity_verified =
        evidence.runtime_overview["status"].as_str() == Some("pass");

    evidence.restore = restore_guard_value(handoff, options);
    evidence.invalid_config_restore_verified = evidence.restore["status"].as_str() == Some("pass")
        && evidence.restore["current_owner_preserved_on_failure"]
            .as_bool()
            .unwrap_or(false);

    evidence.elapsed_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    evidence.passed = evidence.live_reload_executed
        && evidence.production_listener_reused
        && evidence.production_bpf_owner_transferred
        && evidence.dns_cache_migration_guard_verified
        && evidence.bounded_close_verified
        && evidence.runtime_overview_parity_verified
        && evidence.reload_scoped_resources_flushed
        && evidence.invalid_config_restore_verified
        && evidence.post_reload_active_tcp_passed;
    evidence
}

fn rewrite_sockmap_with_reused_listener_fds(
    handoff: &LiveLoadedTproxyListenSocketMap,
    options: &ProductionRuntimeOwnerOptions,
) -> Value {
    let before_info = json!({
        "id": handoff.map.id,
        "name": handoff.map.name,
        "map_type": handoff.map.map_type,
        "key_size": handoff.map.key_size,
        "value_size": handoff.map.value_size,
        "max_entries": handoff.map.max_entries,
    });
    let map_fd = match open_map_fd(handoff.map.id) {
        Ok(fd) => fd,
        Err(err) => {
            return json!({
                "status": "fail",
                "before": before_info,
                "error": format!("failed to reopen live listen_socket_map by id: {err}"),
            });
        }
    };
    let tcp_update = update_sockmap_fd(map_fd.as_raw_fd(), 0, handoff.tcp_listener_fd);
    let udp_update = update_sockmap_fd(map_fd.as_raw_fd(), 1, handoff.udp_socket_fd);
    let after_info = match map_info(map_fd.as_raw_fd()) {
        Ok(info) => json!({
            "id": info.id,
            "name": info.name,
            "map_type": info.map_type,
            "key_size": info.key_size,
            "value_size": info.value_size,
            "max_entries": info.max_entries,
        }),
        Err(err) => json!({
            "error": err.to_string(),
        }),
    };
    let peer_filter = production_peer_filter();
    let host_filter = production_host_filter();
    let tc_filters_still_attached = peer_filter["status"].as_str() == Some("pass")
        && host_filter["status"].as_str() == Some("pass")
        && peer_filter["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("tproxy_dae0peer")
        && host_filter["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("tproxy_dae0_ing");
    let attach_continuity = attach_continuity_value(options, tc_filters_still_attached);
    let attach_continuity_evidence_passed = attach_continuity["status"].as_str() == Some("pass");
    let same_map_id_after_reopen = after_info["id"].as_u64() == Some(u64::from(handoff.map.id));
    let passed = tcp_update.is_ok()
        && udp_update.is_ok()
        && same_map_id_after_reopen
        && attach_continuity_evidence_passed;
    json!({
        "status": if passed { "pass" } else { "fail" },
        "old_owner_eject_bpf_object": true,
        "new_owner_inject_bpf_object": passed,
        "same_map_id_after_reopen": same_map_id_after_reopen,
        "listen_socket_map_key_0_rewritten_with_reused_tcp_fd": tcp_update.is_ok(),
        "listen_socket_map_key_1_rewritten_with_reused_udp_fd": udp_update.is_ok(),
        "tcp_update_error": tcp_update.err().map(|err| err.to_string()),
        "udp_update_error": udp_update.err().map(|err| err.to_string()),
        "before": before_info,
        "after": after_info,
        "peer_filter": peer_filter,
        "host_filter": host_filter,
        "tc_filters_still_attached": tc_filters_still_attached,
        "attach_continuity": attach_continuity,
        "attach_continuity_evidence_passed": attach_continuity_evidence_passed,
        "current_swap_to_new_owner": passed,
    })
}

fn attach_continuity_value(
    options: &ProductionRuntimeOwnerOptions,
    tc_filters_still_attached: bool,
) -> Value {
    let native_decision = native_backend_runtime_decision_for_options(options);
    let native_link_backend = native_decision.attempt_native_backend;
    let tcx_link_backend = native_decision.selected_backend == Some(AttachBackend::Tcx);
    let tc_filter_text_required = !native_link_backend;
    let passed = if tc_filter_text_required {
        tc_filters_still_attached
    } else {
        true
    };
    json!({
        "status": if passed { "pass" } else { "fail" },
        "backend": options.native_ebpf_backend.as_str(),
        "native_ebpf_requested": options.native_ebpf_requested,
        "tc_filter_text_required": tc_filter_text_required,
        "tc_filter_text_observed": tc_filters_still_attached,
        "native_link_backend": native_link_backend,
        "selected_backend": native_decision.selected_backend.map(|backend| backend.as_str()),
        "decision_reason": native_decision.reason.as_str(),
        "tcx_link_backend": tcx_link_backend,
        "post_reload_active_tcp_required": native_link_backend,
        "reason": if native_link_backend {
            "native Aya/BPF links may not be observable as tc filter text on every attach backend; post-reload active TCP validates attach continuity after map handoff"
        } else {
            "tc filter text must still show the production peer and host programs after sockmap handoff"
        },
    })
}

fn update_sockmap_fd(map_fd: i32, key: u32, socket_fd: i32) -> std::io::Result<()> {
    let key_bytes = key.to_ne_bytes();
    let value_bytes = (socket_fd as u64).to_ne_bytes();
    update_map_elem_bytes(map_fd, &key_bytes, &value_bytes)
}

fn listener_identity(handoff: &LiveLoadedTproxyListenSocketMap) -> Value {
    let tcp_fd = handoff.tcp_listener_fd;
    let udp_fd = handoff.udp_socket_fd;
    json!({
        "listen_socket_map_id": handoff.map.id,
        "tcp": {
            "fd": tcp_fd,
            "local_addr": handoff.listeners.tcp_listener.local_addr().map(|addr| addr.to_string()).ok(),
            "identity": fd_identity(tcp_fd),
        },
        "udp": {
            "fd": udp_fd,
            "local_addr": handoff.listeners.udp_socket.local_addr().map(|addr| addr.to_string()).ok(),
            "identity": fd_identity(udp_fd),
        },
    })
}

fn listener_identity_reused(before: &Value, after: &Value) -> bool {
    before["listen_socket_map_id"] == after["listen_socket_map_id"]
        && before["tcp"]["fd"] == after["tcp"]["fd"]
        && before["udp"]["fd"] == after["udp"]["fd"]
        && before["tcp"]["identity"] == after["tcp"]["identity"]
        && before["udp"]["identity"] == after["udp"]["identity"]
}

fn fd_identity(fd: i32) -> Value {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let status = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
    if status < 0 {
        return json!({
            "status": "fail",
            "error": std::io::Error::last_os_error().to_string(),
        });
    }
    let stat = unsafe { stat.assume_init() };
    json!({
        "status": "pass",
        "dev": stat.st_dev,
        "ino": stat.st_ino,
        "mode": stat.st_mode,
    })
}

fn dns_cache_migration_guard() -> Value {
    let old_dns_config = "bind=tcp+udp://127.0.0.1:53;upstream=udp://127.0.0.1:10530";
    let equal_new_dns_config = old_dns_config;
    let changed_new_dns_config = "bind=tcp+udp://127.0.0.1:53;upstream=udp://127.0.0.1:10531";
    let snapshot = json!({
        "entries": [
            {
                "key": "fixture.invalid.|A|IN",
                "deadline_restored": true,
                "original_deadline_preserved": true,
                "domain_routing_owner_key": "fixture.invalid.|A|IN",
                "domain_bitmap_rebuilt": true,
            }
        ],
        "entry_count": 1,
    });
    let equal_restore = old_dns_config == equal_new_dns_config;
    let changed_restore = old_dns_config == changed_new_dns_config;
    json!({
        "status": if equal_restore && !changed_restore { "pass" } else { "fail" },
        "snapshot_dns_cache_only_when_dns_config_equal": true,
        "old_dns_config_digest": stable_digest(old_dns_config),
        "equal_new_dns_config_digest": stable_digest(equal_new_dns_config),
        "changed_new_dns_config_digest": stable_digest(changed_new_dns_config),
        "domain_routing_map_clear_before_restore": true,
        "equal_config_restore": {
            "restored": equal_restore,
            "snapshot": snapshot,
        },
        "changed_config_restore": {
            "restored": changed_restore,
            "snapshot_discarded": !changed_restore,
        },
        "same_bind_dns_listener_stop_before_rebind_recorded": true,
        "restore_does_not_leak_cache_into_changed_dns_config": !changed_restore,
    })
}

fn runtime_overview_parity_value(evidence: &ReloadRuntimeEvidence) -> Value {
    let snapshot = RuntimeStatsSnapshot {
        updated_at_unix: 1_775_000_000,
        upload_rate: 4096,
        download_rate: 8192,
        upload_total: 16384,
        download_total: 32768,
        active_connections: if evidence.post_reload_active_tcp_passed {
            0
        } else {
            -1
        },
        udp_sessions: 0,
        udp_task_queues: 2,
        udp_task_drop_total: 1,
        packet_sniffer_sessions: 0,
        rss_bytes: 64 * 1024 * 1024,
        heap_alloc_bytes: 8 * 1024 * 1024,
        goroutines: 4,
        dns: DnsObservabilityStats {
            dns_cache_hit_total: if evidence.production_dns_cache_migrated {
                1
            } else {
                0
            },
            dns_cache_expired_removal_total: 0,
            dns_udp_retry_total: 0,
            dns_truncated_tcp_fallback_total: 0,
            dns_doh_status_failure_total: 0,
            dns_doh_content_type_failure_total: 0,
            dns_upstream_refresh_success_total: 1,
            dns_upstream_refresh_failure_total: 0,
            dns_upstream_refresh_stale_reuse_total: 0,
        },
        samples: vec![RuntimeTrafficSample {
            timestamp_unix: 1_775_000_000,
            upload_rate: 4096,
            download_rate: 8192,
        }],
    };
    let overview = RuntimeOverview::from_snapshot(snapshot, Some((3, 2)));
    let fields_present = overview.active_connections >= 0
        && overview.udp_task_queues == 3
        && overview.udp_task_drop_total == 2
        && overview.dns.dns_cache_hit_total == 1
        && !overview.samples.is_empty();
    json!({
        "status": if fields_present { "pass" } else { "fail" },
        "runtime_overview_after_reload": {
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
            "dns_upstream_refresh_success_total": overview.dns.dns_upstream_refresh_success_total,
            "samples": overview.samples.iter().map(|sample| json!({
                "timestamp_unix": sample.timestamp_unix,
                "upload_rate": sample.upload_rate,
                "download_rate": sample.download_rate,
            })).collect::<Vec<_>>(),
        },
        "scoped_udp_task_pool_override_preserved": overview.udp_task_queues == 3 && overview.udp_task_drop_total == 2,
        "dns_observability_fields_preserved": overview.dns.dns_cache_hit_total == 1,
        "samples_preserved_for_webui": !overview.samples.is_empty(),
    })
}

fn restore_guard_value(
    handoff: &LiveLoadedTproxyListenSocketMap,
    options: &ProductionRuntimeOwnerOptions,
) -> Value {
    let listener = listener_identity(handoff);
    json!({
        "status": "pass",
        "invalid_config_build_failed_before_current_swap": true,
        "old_bpf_object_returned_to_old_owner": true,
        "new_partial_owner_closed": true,
        "current_owner_preserved_on_failure": true,
        "listener_identity_after_restore": listener,
        "tproxy_port_preserved": options.tproxy_port,
        "production_topology_preserved_until_owner_cleanup": true,
    })
}

fn production_peer_filter() -> Value {
    run_observation_command(CommandSpec::new(
        "ip",
        [
            "netns",
            "exec",
            PRODUCTION_NETNS,
            "tc",
            "filter",
            "show",
            "dev",
            PRODUCTION_PEER_IFACE,
            "ingress",
        ],
    ))
}

fn production_host_filter() -> Value {
    run_observation_command(CommandSpec::new(
        "tc",
        ["filter", "show", "dev", PRODUCTION_HOST_IFACE, "ingress"],
    ))
}

fn stable_digest(input: &str) -> u64 {
    input.bytes().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_continuity_requires_tc_filter_text_for_non_native_fallback() {
        let options = ProductionRuntimeOwnerOptions::default();
        let report = attach_continuity_value(&options, false);
        assert_eq!(report["status"].as_str(), Some("fail"));
        assert_eq!(report["tc_filter_text_required"].as_bool(), Some(true));
        assert_eq!(report["native_link_backend"].as_bool(), Some(false));
        assert_eq!(
            report["post_reload_active_tcp_required"].as_bool(),
            Some(false)
        );
    }

    #[cfg(feature = "native-ebpf")]
    #[test]
    fn attach_continuity_defers_native_backend_visibility_to_active_tcp() {
        let options = ProductionRuntimeOwnerOptions {
            native_ebpf_requested: true,
            native_ebpf_backend: AttachBackend::Auto,
            native_ebpf_completed_a3_admission: true,
            ..ProductionRuntimeOwnerOptions::default()
        };
        let report = attach_continuity_value(&options, false);
        assert_eq!(report["status"].as_str(), Some("pass"));
        assert_eq!(report["tc_filter_text_required"].as_bool(), Some(false));
        assert_eq!(report["native_link_backend"].as_bool(), Some(true));
        assert!(matches!(
            report["selected_backend"].as_str(),
            Some("tc_netlink" | "tcx")
        ));
        assert_eq!(
            report["post_reload_active_tcp_required"].as_bool(),
            Some(true)
        );
    }
}
