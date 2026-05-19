use super::utils::remaining_blockers;
use super::*;

pub(super) fn stage33_report() -> Value {
    let reload = reload_model();
    let domain = domain_routing_model();
    let dns = dns_cache_model();
    json!({
        "name": "stage33-reload-rollback-dns-admission",
        "stage": "stage33",
        "evidence_class": "reload-rollback-dns-cache-domain-routing-model",
        "stage_complete": true,
        "reload_rollback_model_passed": reload["passed"],
        "dns_cache_snapshot_model_passed": dns["passed"],
        "domain_routing_owner_migration_passed": domain["passed"],
        "daemon_reload_signal_sent": false,
        "live_candidate_run_allowed": false,
        "actual_dae_ebpf_program_attach_executed": false,
        "active_tproxy_traffic_executed": false,
        "default_switch_allowed": false,
        "default_path_mutated": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "reload_model": reload,
        "domain_routing_model": domain,
        "dns_cache_model": dns,
        "remaining_blockers": remaining_blockers(),
    })
}

fn reload_model() -> Value {
    let mut flip = CoreFlip::default();
    let mut old = ReloadCoreState::new(false, &mut flip);
    old.eject_bpf();
    old.inject_bpf();
    let mut new_reload = ReloadCoreState::new(true, &mut flip);
    new_reload.eject_bpf();
    let passed = !old.bpf_ejected && new_reload.bpf_ejected && new_reload.flip == 1;
    json!({
        "passed": passed,
        "old_after_eject_inject": {
            "is_reload": old.is_reload,
            "bpf_ejected": old.bpf_ejected,
            "defer_func_count": old.defer_func_count,
            "flip": old.flip,
        },
        "new_reload_after_eject": {
            "is_reload": new_reload.is_reload,
            "bpf_ejected": new_reload.bpf_ejected,
            "defer_func_count": new_reload.defer_func_count,
            "flip": new_reload.flip,
        },
        "rollback_requires_old_bpf_inject": true,
    })
}

fn domain_routing_model() -> Value {
    let mut tracker = DomainRoutingTracker::default();
    tracker.sync_owner(
        "dns-cache-a",
        DomainRoutingOwnerSnapshot::new(&[3, 8], &["192.0.2.1", "2001:db8::1"]),
    );
    let after_a = tracker.view("after-a");
    tracker.sync_owner(
        "dns-cache-b",
        DomainRoutingOwnerSnapshot::new(&[4], &["192.0.2.1", "198.51.100.7"]),
    );
    let after_b = tracker.view("after-b");
    tracker.sync_owner("dns-cache-a", DomainRoutingOwnerSnapshot::default());
    let after_remove_a = tracker.view("after-remove-a");
    let shared_ip_after_b = after_b
        .ips
        .iter()
        .find(|ip| ip.ip == "192.0.2.1")
        .map(|ip| ip.merged.clone())
        .unwrap_or_default();
    let shared_ip_after_remove = after_remove_a
        .ips
        .iter()
        .find(|ip| ip.ip == "192.0.2.1")
        .map(|ip| ip.merged.clone())
        .unwrap_or_default();
    json!({
        "passed": shared_ip_after_b == vec![7, 8] && shared_ip_after_remove == vec![4],
        "after_a": domain_view_json(&after_a),
        "after_b": domain_view_json(&after_b),
        "after_remove_a": domain_view_json(&after_remove_a),
    })
}

fn domain_view_json(view: &dae_control::DomainRoutingView) -> Value {
    json!({
        "step": view.step,
        "owners": view.owners,
        "ips": view.ips.iter().map(|ip| {
            json!({
                "ip": ip.ip,
                "owners": ip.owners,
                "merged": ip.merged,
                "present": ip.present,
            })
        }).collect::<Vec<_>>(),
    })
}

fn dns_cache_model() -> Value {
    let key = DnsCacheKey::new("stage33.example.", 1, 1);
    let mut entry = DnsCacheEntry::new(1_700_000_060, 1_700_000_060);
    entry.domain_bitmap = vec![3, 8];
    entry.ips = vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 33))];
    entry.has_any_ip = true;
    let mut store = DnsCacheStore::new(8);
    store.insert(1_700_000_000, key.clone(), entry);
    let hit_before = store.lookup(1_700_000_030, &key, false).is_some();
    let mut snapshot = store.clone();
    let hit_after_snapshot = snapshot.lookup(1_700_000_040, &key, false).is_some();
    let expired_after_deadline = snapshot.lookup(1_700_000_061, &key, false).is_none();
    json!({
        "passed": hit_before && hit_after_snapshot && expired_after_deadline,
        "key": key.to_string(),
        "hit_before_reload": hit_before,
        "hit_after_snapshot": hit_after_snapshot,
        "expired_after_deadline": expired_after_deadline,
        "stats": {
            "hit_total": snapshot.stats().hit_total,
            "expired_removal_total": snapshot.stats().expired_removal_total,
            "remove_callback_total": snapshot.stats().remove_callback_total,
        }
    })
}
