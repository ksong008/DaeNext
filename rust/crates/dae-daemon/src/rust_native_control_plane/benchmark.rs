use super::*;
pub(super) fn run_native_control_plane_benchmark(
    iterations: u32,
) -> Result<NativeBenchmarkEvidence, String> {
    if iterations == 0 {
        return Err(
            "rust-native-control-plane benchmark iterations must be greater than zero".into(),
        );
    }

    let dns_packet_to_domain_event_ns_per_op = measure_ns_per_op(iterations, || {
        build_native_dns_event_seed().map(|seed| seed.ips.len())
    })?;

    let duplicate_seed = build_native_dns_event_seed()?;
    let mut duplicate_owner = DomainRoutingOwner::default();
    apply_domain_event(&mut duplicate_owner, DOMAIN_ROUTING_MAP_ID, &duplicate_seed)?;
    let domain_routing_duplicate_ns_per_op = measure_ns_per_op(iterations, || {
        apply_domain_event(&mut duplicate_owner, DOMAIN_ROUTING_MAP_ID, &duplicate_seed)
            .map(|report| report.skipped)
    })?;

    let mut toggle_owner = DomainRoutingOwner::default();
    let mut toggle_a = duplicate_seed.clone();
    let mut toggle_b = duplicate_seed.clone();
    toggle_b
        .ips
        .push(ip_to_key("198.51.100.9".parse().unwrap()));
    let domain_routing_toggle_ns_per_op = measure_ns_per_op(iterations, || {
        let report_a = apply_domain_event(&mut toggle_owner, DOMAIN_ROUTING_MAP_ID, &toggle_a)?;
        let report_b = apply_domain_event(&mut toggle_owner, DOMAIN_ROUTING_MAP_ID, &toggle_b)?;
        Ok(report_a.entries_updated + report_b.entries_updated)
    })?;
    toggle_a.ips.clear();
    black_box(toggle_a);

    let reload_seed = build_native_dns_event_seed()?;
    let reload_transaction_ns_per_op = measure_ns_per_op(iterations, || {
        let mut owner = DomainRoutingOwner::default();
        apply_domain_event(&mut owner, DOMAIN_ROUTING_MAP_ID, &reload_seed)?;
        let plan = ReloadDnsCachePlan::decide(true, true, reload_seed.ips.len());
        let clear = owner
            .prepare_reload_map_with(
                DOMAIN_ROUTING_RELOAD_MAP_ID,
                reload_seed.ips.clone(),
                |_, _| Ok::<(), io::Error>(()),
            )
            .map_err(|err| format!("rust native reload benchmark clear failed: {err}"))?;
        let restore = apply_domain_event(&mut owner, DOMAIN_ROUTING_RELOAD_MAP_ID, &reload_seed)?;
        Ok(usize::from(plan.restore_cache) + clear.deletes.len() + restore.entries_updated)
    })?;

    let routing_state = sample_routing_state()?;
    let mut routing_owner = RoutingRuleOwner::default();
    routing_owner
        .apply_rules_with(
            ROUTING_MAP_ID,
            LPM_ARRAY_MAP_ID,
            routing_state.clone(),
            |_, _, _| Ok(()),
        )
        .map_err(|err| format!("rust native routing benchmark seed failed: {err}"))?;
    let routing_owner_duplicate_ns_per_op = measure_ns_per_op(iterations, || {
        routing_owner
            .apply_rules_with(
                ROUTING_MAP_ID,
                LPM_ARRAY_MAP_ID,
                routing_state.clone(),
                |_, _, _| Ok::<(), io::Error>(()),
            )
            .map(|report| report.map.skipped)
            .map_err(|err| format!("rust native routing benchmark duplicate failed: {err}"))
    })?;

    let mut connectivity_owner = dae_control::OutboundConnectivityOwner::default();
    let connectivity_event = sample_connectivity_event();
    connectivity_owner
        .apply_event_with(CONNECTIVITY_MAP_ID, connectivity_event, |_, _| Ok(()))
        .map_err(|err| format!("rust native connectivity benchmark seed failed: {err}"))?;
    let connectivity_owner_duplicate_ns_per_op = measure_ns_per_op(iterations, || {
        connectivity_owner
            .apply_event_with(CONNECTIVITY_MAP_ID, connectivity_event, |_, _| {
                Ok::<(), io::Error>(())
            })
            .map(|report| report.skipped)
            .map_err(|err| format!("rust native connectivity benchmark duplicate failed: {err}"))
    })?;

    Ok(NativeBenchmarkEvidence {
        iterations,
        dns_packet_to_domain_event_ns_per_op,
        domain_routing_duplicate_ns_per_op,
        domain_routing_toggle_ns_per_op,
        reload_transaction_ns_per_op,
        routing_owner_duplicate_ns_per_op,
        connectivity_owner_duplicate_ns_per_op,
    })
}

pub(super) fn measure_ns_per_op<T>(
    iterations: u32,
    mut f: impl FnMut() -> Result<T, String>,
) -> Result<u64, String> {
    let started = Instant::now();
    for _ in 0..iterations {
        black_box(f()?);
    }
    let elapsed = started.elapsed().as_nanos();
    Ok((elapsed / u128::from(iterations)).min(u128::from(u64::MAX)) as u64)
}
