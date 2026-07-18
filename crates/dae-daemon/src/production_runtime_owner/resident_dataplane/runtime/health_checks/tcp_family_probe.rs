use super::*;
use dae_outbound::HealthState;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentTcpFamilyProbeResult {
    pub(super) network_type: NetworkType,
    pub(super) health_state: HealthState,
    pub(super) latency_ms: Option<i64>,
    pub(super) message: Option<String>,
}

impl ResidentTcpFamilyProbeResult {
    pub(super) fn alive(&self) -> bool {
        self.health_state == HealthState::Alive && self.latency_ms.is_some()
    }

    pub(super) fn to_json(&self) -> Value {
        json!({
            "networkType": self.network_type.string_without_dns(),
            "networkDimension": self.network_type.dimension_name(),
            "healthState": self.health_state.as_str(),
            "latencyMs": self.latency_ms,
            "alive": self.alive(),
            "message": self.message,
        })
    }
}

pub(super) async fn probe_resident_candidate_tcp_families(
    candidate: &plan::ResidentProxyProbePlan,
    stop: Option<&SharedResidentStopSignal>,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    caller: QuicEndpointCallerClass,
) -> Result<Vec<ResidentTcpFamilyProbeResult>, HealthCheckRoundStatus> {
    let targets = match stop {
        Some(stop) => {
            tokio::select! {
                _ = wait_until_stopped_async(Arc::clone(stop)) => {
                    return Err(HealthCheckRoundStatus::Cancelled);
                }
                targets = candidate.tcp_check.resolver.resolve() => targets,
            }
        }
        None => candidate.tcp_check.resolver.resolve().await,
    };
    let (ipv4, ipv6) = tokio::join!(
        Box::pin(probe_tcp_family(
            candidate,
            NetworkType::TCP4,
            targets.ipv4,
            stop,
            hysteria2_owner_registry.clone(),
            tuic_owner_registry.clone(),
            caller,
        )),
        Box::pin(probe_tcp_family(
            candidate,
            NetworkType::TCP6,
            targets.ipv6,
            stop,
            hysteria2_owner_registry.clone(),
            tuic_owner_registry.clone(),
            caller,
        )),
    );
    Ok(vec![ipv4?, ipv6?])
}

async fn probe_tcp_family(
    candidate: &plan::ResidentProxyProbePlan,
    network_type: NetworkType,
    family: plan::ResidentHealthTargetFamily,
    stop: Option<&SharedResidentStopSignal>,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    caller: QuicEndpointCallerClass,
) -> Result<ResidentTcpFamilyProbeResult, HealthCheckRoundStatus> {
    match family {
        plan::ResidentHealthTargetFamily::Present(addrs) => {
            let mut best_latency = None::<i64>;
            let mut failures = Vec::new();
            for addr in addrs {
                if stop.is_some_and(|stop| stop.load(Ordering::Relaxed)) {
                    return Err(HealthCheckRoundStatus::Cancelled);
                }
                let target = plan::ResidentTcpCheckTarget {
                    target: addr.to_string(),
                    network_type: Some(network_type),
                };
                let result = match stop {
                    Some(stop) => {
                        tokio::select! {
                            _ = wait_until_stopped_async(Arc::clone(stop)) => {
                                return Err(HealthCheckRoundStatus::Cancelled);
                            }
                            result = probe_resident_candidate_tcp_target_endpoint_async(
                                candidate,
                                &target,
                                hysteria2_owner_registry.clone(),
                                tuic_owner_registry.clone(),
                                caller,
                            ) => result,
                        }
                    }
                    None => {
                        probe_resident_candidate_tcp_target_endpoint_async(
                            candidate,
                            &target,
                            hysteria2_owner_registry.clone(),
                            tuic_owner_registry.clone(),
                            caller,
                        )
                        .await
                    }
                };
                match result {
                    Ok(latency) => {
                        best_latency = Some(best_latency.map_or(latency, |best| best.min(latency)));
                    }
                    Err(err) => failures.push(format!("{}: {err}", target.target)),
                }
            }
            Ok(match best_latency {
                Some(latency_ms) => ResidentTcpFamilyProbeResult {
                    network_type,
                    health_state: HealthState::Alive,
                    latency_ms: Some(latency_ms),
                    message: None,
                },
                None => ResidentTcpFamilyProbeResult {
                    network_type,
                    health_state: HealthState::Dead,
                    latency_ms: None,
                    message: Some(if failures.is_empty() {
                        "TCP health target family had no probe result".to_owned()
                    } else {
                        failures.join("; ")
                    }),
                },
            })
        }
        plan::ResidentHealthTargetFamily::Absent => Ok(ResidentTcpFamilyProbeResult {
            network_type,
            health_state: HealthState::Unavailable,
            latency_ms: None,
            message: Some("TCP health target has no address in this family".to_owned()),
        }),
        plan::ResidentHealthTargetFamily::Unknown(err) => Ok(ResidentTcpFamilyProbeResult {
            network_type,
            health_state: HealthState::Unknown,
            latency_ms: None,
            message: Some(err),
        }),
    }
}

pub(super) fn preferred_tcp_family_probe_result(
    results: &[ResidentTcpFamilyProbeResult],
) -> Option<&ResidentTcpFamilyProbeResult> {
    results.iter().reduce(|current, next| {
        if prefer_tcp_family_result(next, current) {
            next
        } else {
            current
        }
    })
}

fn prefer_tcp_family_result(
    next: &ResidentTcpFamilyProbeResult,
    current: &ResidentTcpFamilyProbeResult,
) -> bool {
    match (next.latency_ms, current.latency_ms) {
        (Some(next_latency), Some(current_latency)) => next_latency < current_latency,
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => {
            health_state_failure_rank(next.health_state)
                < health_state_failure_rank(current.health_state)
        }
    }
}

fn health_state_failure_rank(state: HealthState) -> u8 {
    match state {
        HealthState::Dead => 0,
        HealthState::Unknown => 1,
        HealthState::Unavailable => 2,
        HealthState::Alive => 3,
    }
}
