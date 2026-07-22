use super::*;

pub(super) async fn run_resident_candidate_family_health_checks(
    group: &plan::ResidentProxyGroupPlan,
    candidate: &plan::ResidentProxyProbePlan,
    stop: SharedResidentStopSignal,
    owners: ResidentTransportOwnerRegistries,
    dns: Arc<dns::ResidentDnsPlan>,
) -> HealthCheckRoundStatus {
    scope_quic_endpoint_observation(
        QuicEndpointCallerClass::BackgroundHealth,
        Some(candidate.binding.runtime_generation()),
        run_resident_candidate_family_health_checks_scoped(group, candidate, stop, owners, dns),
    )
    .await
}

async fn run_resident_candidate_family_health_checks_scoped(
    group: &plan::ResidentProxyGroupPlan,
    candidate: &plan::ResidentProxyProbePlan,
    stop: SharedResidentStopSignal,
    owners: ResidentTransportOwnerRegistries,
    dns: Arc<dns::ResidentDnsPlan>,
) -> HealthCheckRoundStatus {
    let tcp_results = match super::tcp_family_probe::probe_resident_candidate_tcp_families(
        candidate,
        Some(&stop),
        owners.clone(),
        QuicEndpointCallerClass::BackgroundHealth,
    )
    .await
    {
        Ok(results) => results,
        Err(status) => return status,
    };
    for result in tcp_results {
        let _ = group.record_health_state(
            &candidate.node_tag,
            result.network_type,
            result.health_state,
            result.latency_ms,
            unix_now_secs(),
        );
    }

    let udp_results = match super::udp_family_probe::probe_resident_candidate_udp_families(
        candidate,
        Some(&stop),
        dns,
    )
    .await
    {
        Ok(results) => results,
        Err(status) => return status,
    };
    for result in udp_results {
        let _ = group.record_health_state(
            &candidate.node_tag,
            result.network_type,
            result.health_state,
            result.latency_ms,
            unix_now_secs(),
        );
    }
    HealthCheckRoundStatus::Completed
}
