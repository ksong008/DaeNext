use super::*;
use dae_outbound::HealthState;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentUdpFamilyProbeResult {
    pub(super) network_type: NetworkType,
    pub(super) health_state: HealthState,
    pub(super) latency_ms: Option<i64>,
    pub(super) message: Option<String>,
}

pub(super) async fn probe_resident_candidate_udp_families(
    candidate: &plan::ResidentProxyProbePlan,
    stop: Option<&SharedResidentStopSignal>,
    owners: ResidentTransportOwnerRegistries,
) -> Result<Vec<ResidentUdpFamilyProbeResult>, HealthCheckRoundStatus> {
    let targets = match stop {
        Some(stop) => {
            tokio::select! {
                _ = wait_until_stopped_async(Arc::clone(stop)) => {
                    return Err(HealthCheckRoundStatus::Cancelled);
                }
                targets = candidate.udp_check.resolver.resolve() => targets,
            }
        }
        None => candidate.udp_check.resolver.resolve().await,
    };
    let (ipv4, ipv6) = tokio::join!(
        Box::pin(probe_udp_family(
            candidate,
            NetworkType::DNS_UDP4,
            targets.ipv4,
            stop,
            owners.clone(),
        )),
        Box::pin(probe_udp_family(
            candidate,
            NetworkType::DNS_UDP6,
            targets.ipv6,
            stop,
            owners.clone(),
        )),
    );
    Ok(vec![ipv4?, ipv6?])
}

async fn probe_udp_family(
    candidate: &plan::ResidentProxyProbePlan,
    network_type: NetworkType,
    family: plan::ResidentHealthTargetFamily,
    stop: Option<&SharedResidentStopSignal>,
    owners: ResidentTransportOwnerRegistries,
) -> Result<ResidentUdpFamilyProbeResult, HealthCheckRoundStatus> {
    match family {
        plan::ResidentHealthTargetFamily::Present(addrs) => {
            let mut best_latency = None::<i64>;
            let mut failures = Vec::new();
            for addr in addrs {
                if stop.is_some_and(|stop| stop.load(Ordering::Relaxed)) {
                    return Err(HealthCheckRoundStatus::Cancelled);
                }
                let started = Instant::now();
                let result = match stop {
                    Some(stop) => {
                        tokio::select! {
                            _ = wait_until_stopped_async(Arc::clone(stop)) => {
                                return Err(HealthCheckRoundStatus::Cancelled);
                            }
                            result = probe_resident_proxy_dns_udp_async(
                                Arc::clone(&candidate.proxy),
                                addr,
                                &candidate.udp_check.lookup_host,
                                owners.hysteria2(),
                                owners.tuic(),
                                owners.juicity(),
                            ) => result,
                        }
                    }
                    None => {
                        probe_resident_proxy_dns_udp_async(
                            Arc::clone(&candidate.proxy),
                            addr,
                            &candidate.udp_check.lookup_host,
                            owners.hysteria2(),
                            owners.tuic(),
                            owners.juicity(),
                        )
                        .await
                    }
                };
                match result {
                    Ok(()) => {
                        let latency = elapsed_millis(started.elapsed());
                        best_latency = Some(best_latency.map_or(latency, |best| best.min(latency)));
                    }
                    Err(err) => failures.push(format!("{addr}: {err}")),
                }
            }
            Ok(match best_latency {
                Some(latency_ms) => ResidentUdpFamilyProbeResult {
                    network_type,
                    health_state: HealthState::Alive,
                    latency_ms: Some(latency_ms),
                    message: None,
                },
                None => ResidentUdpFamilyProbeResult {
                    network_type,
                    health_state: HealthState::Dead,
                    latency_ms: None,
                    message: Some(if failures.is_empty() {
                        "UDP health target family had no probe result".to_owned()
                    } else {
                        failures.join("; ")
                    }),
                },
            })
        }
        plan::ResidentHealthTargetFamily::Absent => Ok(ResidentUdpFamilyProbeResult {
            network_type,
            health_state: HealthState::Unavailable,
            latency_ms: None,
            message: Some("UDP health target has no address in this family".to_owned()),
        }),
        plan::ResidentHealthTargetFamily::Unknown(err) => Ok(ResidentUdpFamilyProbeResult {
            network_type,
            health_state: HealthState::Unknown,
            latency_ms: None,
            message: Some(err),
        }),
    }
}
