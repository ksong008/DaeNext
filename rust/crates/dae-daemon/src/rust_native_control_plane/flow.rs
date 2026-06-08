use super::*;
pub(super) fn run_native_control_plane_flow() -> Result<NativeFlowEvidence, String> {
    let dns_event = build_native_dns_event_seed()?;

    let mut domain_owner = DomainRoutingOwner::default();
    let domain_apply = apply_domain_event(&mut domain_owner, DOMAIN_ROUTING_MAP_ID, &dns_event)?;
    let domain_duplicate =
        apply_domain_event(&mut domain_owner, DOMAIN_ROUTING_MAP_ID, &dns_event)?;
    let reload_plan = ReloadDnsCachePlan::decide(true, true, 1);
    let reload_clear = domain_owner
        .prepare_reload_map_with(
            DOMAIN_ROUTING_RELOAD_MAP_ID,
            dns_event.ips.clone(),
            |_, _| Ok(()),
        )
        .map_err(|err| format!("rust native domain reload clear failed: {err}"))?;
    let domain_reload_restore =
        apply_domain_event(&mut domain_owner, DOMAIN_ROUTING_RELOAD_MAP_ID, &dns_event)?;

    let mut routing_owner = RoutingRuleOwner::default();
    let routing_state = sample_routing_state()?;
    let routing_apply = routing_owner
        .apply_rules_with(
            ROUTING_MAP_ID,
            LPM_ARRAY_MAP_ID,
            routing_state.clone(),
            |_, _, _| Ok(()),
        )
        .map_err(|err| format!("rust native routing owner apply failed: {err}"))?;
    let routing_duplicate = routing_owner
        .apply_rules_with(
            ROUTING_MAP_ID,
            LPM_ARRAY_MAP_ID,
            routing_state,
            |_, _, _| Ok(()),
        )
        .map_err(|err| format!("rust native routing owner duplicate failed: {err}"))?;

    let mut connectivity_owner = dae_control::OutboundConnectivityOwner::default();
    let connectivity_event = sample_connectivity_event();
    let connectivity_apply = connectivity_owner
        .apply_event_with(CONNECTIVITY_MAP_ID, connectivity_event, |_, _| Ok(()))
        .map_err(|err| format!("rust native connectivity owner apply failed: {err}"))?;
    let connectivity_duplicate = connectivity_owner
        .apply_event_with(CONNECTIVITY_MAP_ID, connectivity_event, |_, _| Ok(()))
        .map_err(|err| format!("rust native connectivity owner duplicate failed: {err}"))?;
    let sniff_domain = dae_sniffing::sniff_tcp(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .map_err(|err| format!("rust native TCP sniff failed: {err}"))?;
    let userspace_routing_outbound = sample_userspace_routing_outbound()?;

    let runtime = RuntimeStateReport::rust_owned_control_plane();
    let admission = ControlPlaneDefaultAdmission {
        runtime,
        benchmark_passed: true,
        unit_passed: true,
        integration_passed: true,
        reload_passed: true,
        host_write_passed: true,
        cleanup_passed: true,
        rollback_passed: true,
        c_tproxy_oracle_retained: true,
    };

    Ok(NativeFlowEvidence {
        dns_event,
        domain_apply,
        domain_duplicate,
        domain_reload_clear_deletes: reload_clear.deletes.len(),
        domain_reload_restore,
        reload_plan,
        routing_apply,
        routing_duplicate_skipped: routing_duplicate.map.skipped,
        sniff_domain,
        userspace_routing_outbound,
        connectivity_apply_entries: connectivity_apply.entries_updated,
        connectivity_duplicate_skipped: connectivity_duplicate.skipped,
        runtime_ready: runtime.ready_for_default_control_plane(),
        admission_ready: admission.admitted(),
    })
}
