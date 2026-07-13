use super::*;
use dae_outbound::HealthState;

pub(super) async fn run_resident_candidate_family_health_checks(
    group: &plan::ResidentProxyGroupPlan,
    candidate: &plan::ResidentProxyProbePlan,
    stop: SharedResidentStopSignal,
) -> HealthCheckRoundStatus {
    let tcp_results = match super::tcp_family_probe::probe_resident_candidate_tcp_families(
        candidate,
        Some(&stop),
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

    let udp_targets = tokio::select! {
        _ = wait_until_stopped_async(Arc::clone(&stop)) => {
            plan::ResidentHealthTargetFamilies::cancelled()
        }
        targets = candidate.udp_check.resolver.resolve() => targets,
    };
    if udp_targets.is_cancelled() {
        return HealthCheckRoundStatus::Cancelled;
    }
    record_udp_families(group, candidate, udp_targets, stop).await
}

async fn record_udp_families(
    group: &plan::ResidentProxyGroupPlan,
    candidate: &plan::ResidentProxyProbePlan,
    targets: plan::ResidentHealthTargetFamilies,
    stop: SharedResidentStopSignal,
) -> HealthCheckRoundStatus {
    let (ipv4, ipv6) = tokio::join!(
        Box::pin(probe_udp_family(candidate, targets.ipv4, Arc::clone(&stop),)),
        Box::pin(probe_udp_family(candidate, targets.ipv6, Arc::clone(&stop),)),
    );
    for (network_type, outcome) in [(NetworkType::DNS_UDP4, ipv4), (NetworkType::DNS_UDP6, ipv6)] {
        let Ok(outcome) = outcome else {
            return HealthCheckRoundStatus::Cancelled;
        };
        let _ = group.record_health_state(
            &candidate.node_tag,
            network_type,
            outcome.0,
            outcome.1,
            unix_now_secs(),
        );
    }
    HealthCheckRoundStatus::Completed
}

async fn probe_udp_family(
    candidate: &plan::ResidentProxyProbePlan,
    family: plan::ResidentHealthTargetFamily,
    stop: SharedResidentStopSignal,
) -> Result<(HealthState, Option<i64>), HealthCheckRoundStatus> {
    match family {
        plan::ResidentHealthTargetFamily::Present(addrs) => {
            let mut best_latency = None::<i64>;
            for addr in addrs {
                if stop.load(Ordering::Relaxed) {
                    return Err(HealthCheckRoundStatus::Cancelled);
                }
                let started = Instant::now();
                let result = tokio::select! {
                    _ = wait_until_stopped_async(Arc::clone(&stop)) => {
                        return Err(HealthCheckRoundStatus::Cancelled);
                    }
                    result = probe_resident_proxy_dns_udp_async(
                        &candidate.proxy,
                        addr,
                        &candidate.udp_check.lookup_host,
                    ) => result,
                };
                if result.is_ok() {
                    let latency = elapsed_millis(started.elapsed());
                    best_latency = Some(best_latency.map_or(latency, |best| best.min(latency)));
                }
            }
            Ok(match best_latency {
                Some(latency) => (HealthState::Alive, Some(latency)),
                None => (HealthState::Dead, None),
            })
        }
        plan::ResidentHealthTargetFamily::Absent => Ok((HealthState::Unavailable, None)),
        plan::ResidentHealthTargetFamily::Unknown(_) => Ok((HealthState::Unknown, None)),
        plan::ResidentHealthTargetFamily::Cancelled => Err(HealthCheckRoundStatus::Cancelled),
    }
}
