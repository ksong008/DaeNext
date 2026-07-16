use crate::alive::AliveDialerSet;
use crate::annotation::Annotation;
use crate::dialer::{Dialer, DialerHealthSnapshot};
use crate::error::OutboundError;
use crate::policy::SelectionPolicy;
use crate::types::{IpVersion, NETWORK_TYPE_COLLECTION_COUNT, NetworkType};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedDialer {
    pub index: usize,
    pub latency_ms: i64,
    pub network_type: NetworkType,
}

#[derive(Clone, Debug)]
pub struct DialerGroup {
    pub name: String,
    pub dialers: Vec<Dialer>,
    policy: SelectionPolicy,
    alive_sets: Vec<Option<AliveDialerSet>>,
}

impl DialerGroup {
    pub fn new(
        name: impl Into<String>,
        dialers: Vec<Dialer>,
        annotations: Vec<Annotation>,
        policy: SelectionPolicy,
        check_dns_tcp: bool,
        tolerance_ms: i64,
    ) -> Self {
        let mut alive_sets = vec![None; NETWORK_TYPE_COLLECTION_COUNT];
        if policy.needs_alive_state() {
            for network_type in [
                NetworkType::DNS_UDP4,
                NetworkType::DNS_UDP6,
                NetworkType::TCP4,
                NetworkType::TCP6,
                NetworkType::DATA_UDP4,
                NetworkType::DATA_UDP6,
            ] {
                alive_sets[network_type.collection_index()] = Some(AliveDialerSet::new(
                    network_type,
                    policy.clone(),
                    &dialers,
                    &annotations,
                    tolerance_ms,
                    false,
                ));
            }
            if check_dns_tcp {
                for network_type in [NetworkType::DNS_TCP4, NetworkType::DNS_TCP6] {
                    alive_sets[network_type.collection_index()] = Some(AliveDialerSet::new(
                        network_type,
                        policy.clone(),
                        &dialers,
                        &annotations,
                        tolerance_ms,
                        false,
                    ));
                }
            }
        }
        Self {
            name: name.into(),
            dialers,
            policy,
            alive_sets,
        }
    }

    pub fn select(
        &mut self,
        network_type: NetworkType,
        strict_ip_version: bool,
    ) -> Result<SelectedDialer, OutboundError> {
        match self.select_with_policy(network_type, self.policy.clone()) {
            Ok(selected) => Ok(selected),
            Err(OutboundError::NoAliveDialer) if !strict_ip_version => {
                let fallback = network_type.with_ipversion(match network_type.ipversion {
                    IpVersion::V4 => IpVersion::V6,
                    IpVersion::V6 => IpVersion::V4,
                });
                self.select_with_policy(fallback, self.policy.clone())
            }
            Err(err) => Err(err),
        }
    }

    pub fn set_last_latency(&mut self, index: usize, network_type: NetworkType, latency_ms: i64) {
        self.dialers[index]
            .must_get_latencies10(network_type)
            .append(latency_ms);
    }

    pub fn set_moving_average(&mut self, index: usize, network_type: NetworkType, latency_ms: i64) {
        self.dialers[index].set_moving_average(network_type, latency_ms);
    }

    pub fn record_check_result(
        &mut self,
        index: usize,
        network_type: NetworkType,
        latency_ms: Option<i64>,
        checked_at_unix: i64,
    ) {
        self.dialers[index].record_check_result(network_type, latency_ms, checked_at_unix);
        self.notify_alive(index, network_type, latency_ms.is_some());
    }

    pub fn record_check_failure_without_latency(
        &mut self,
        index: usize,
        network_type: NetworkType,
        checked_at_unix: i64,
    ) {
        self.dialers[index].record_check_failure_without_latency(network_type, checked_at_unix);
        self.notify_alive(index, network_type, false);
    }

    pub fn record_available_traffic(
        &mut self,
        index: usize,
        network_type: NetworkType,
        checked_at_unix: i64,
    ) {
        self.dialers[index].record_available_traffic(network_type, checked_at_unix);
        self.notify_alive(index, network_type, true);
    }

    pub fn record_check_unavailable(
        &mut self,
        index: usize,
        network_type: NetworkType,
        checked_at_unix: i64,
    ) {
        self.dialers[index].record_check_unavailable(network_type, checked_at_unix);
        self.notify_alive(index, network_type, false);
    }

    pub fn record_check_unknown(
        &mut self,
        index: usize,
        network_type: NetworkType,
        checked_at_unix: i64,
    ) {
        self.dialers[index].record_check_unknown(network_type, checked_at_unix);
    }

    pub fn restore_health_snapshot(
        &mut self,
        index: usize,
        network_type: NetworkType,
        snapshot: DialerHealthSnapshot,
    ) {
        let alive = match snapshot.health_state {
            crate::dialer::HealthState::Alive => true,
            crate::dialer::HealthState::Dead | crate::dialer::HealthState::Unavailable => false,
            crate::dialer::HealthState::Unknown => snapshot.alive,
        };
        self.dialers[index].restore_health_snapshot(network_type, snapshot);
        self.notify_alive(index, network_type, alive);
    }

    pub fn notify_alive(&mut self, index: usize, network_type: NetworkType, alive: bool) {
        let alive_index = network_type.collection_index();
        if let Some(alive_set) = self.alive_sets[alive_index].as_mut() {
            alive_set.notify_latency_change(&self.dialers, index, alive);
        }
    }

    pub fn alive_set(&self, network_type: NetworkType) -> Option<&AliveDialerSet> {
        self.alive_sets[network_type.collection_index()].as_ref()
    }

    pub fn alive_set_mut(&mut self, network_type: NetworkType) -> Option<&mut AliveDialerSet> {
        self.alive_sets[network_type.collection_index()].as_mut()
    }

    pub fn has_alive_state(&self) -> bool {
        self.alive_sets.iter().any(|entry| entry.is_some())
    }

    fn select_with_policy(
        &mut self,
        network_type: NetworkType,
        policy: SelectionPolicy,
    ) -> Result<SelectedDialer, OutboundError> {
        if self.dialers.is_empty() {
            return Err(OutboundError::NoDialerInGroup);
        }
        match policy {
            SelectionPolicy::Fixed { index } => {
                if index >= self.dialers.len() {
                    return Err(OutboundError::FixedIndexOutOfRange);
                }
                Ok(SelectedDialer {
                    index,
                    latency_ms: 0,
                    network_type,
                })
            }
            SelectionPolicy::Random => {
                let (candidate_network_types, candidate_count) =
                    selection_network_types(network_type, &policy);
                for candidate_network_type in
                    candidate_network_types.into_iter().take(candidate_count)
                {
                    let Some(alive_set) = self
                        .alive_sets
                        .get_mut(candidate_network_type.collection_index())
                        .and_then(Option::as_mut)
                    else {
                        continue;
                    };
                    if let Some(index) = alive_set.get_rand() {
                        return Ok(SelectedDialer {
                            index,
                            latency_ms: 0,
                            network_type: candidate_network_type,
                        });
                    }
                }
                Err(OutboundError::NoAliveDialer)
            }
            SelectionPolicy::MinLastLatency
            | SelectionPolicy::MinAverage10
            | SelectionPolicy::MinMovingAverage => {
                let (candidate_network_types, candidate_count) =
                    selection_network_types(network_type, &policy);
                for candidate_network_type in
                    candidate_network_types.into_iter().take(candidate_count)
                {
                    let Some(alive_set) = self
                        .alive_sets
                        .get(candidate_network_type.collection_index())
                        .and_then(Option::as_ref)
                    else {
                        continue;
                    };
                    if let Some((index, latency_ms)) = alive_set.get_min_latency() {
                        return Ok(SelectedDialer {
                            index,
                            latency_ms,
                            network_type: candidate_network_type,
                        });
                    }
                }
                Err(OutboundError::NoAliveDialer)
            }
        }
    }
}

fn selection_network_types(
    network_type: NetworkType,
    policy: &SelectionPolicy,
) -> ([NetworkType; 3], usize) {
    let mut network_types = [network_type; 3];
    let mut count = 1;
    if matches!(policy, SelectionPolicy::Fixed { .. }) || !network_type.is_data_udp() {
        return (network_types, count);
    }
    network_types[count] = NetworkType::dns_udp_for_ipversion(network_type.ipversion);
    count += 1;
    network_types[count] = NetworkType::tcp_for_ipversion(network_type.ipversion);
    count += 1;
    (network_types, count)
}
