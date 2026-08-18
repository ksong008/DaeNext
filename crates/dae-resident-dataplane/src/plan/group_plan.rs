use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

const RESIDENT_GROUP_RESUSCITATION_MIN_INTERVAL: Duration = Duration::from_secs(1);
const RESIDENT_GROUP_RESUSCITATION_MAX_INTERVAL: Duration = Duration::from_secs(30);
const RESIDENT_GROUP_RESUSCITATION_INTERVAL_DIVISOR: u32 = 8;
const RESIDENT_HEALTH_DATABASE_SEED_TTL_INTERVALS: u32 = 2;
#[derive(Clone, Debug)]
pub(crate) struct ResidentProxyCandidatePlan {
    pub(crate) match_index: usize,
    pub(crate) annotation_add_latency_ms: i64,
    pub(crate) link: String,
    pub(crate) link_hash: String,
    pub(crate) execution_identity: String,
    pub(crate) redacted_link_source: String,
    pub(crate) binding: ResidentProxyBinding,
    pub(super) data_udp_observation: Arc<ResidentDataUdpObservation>,
}

#[derive(Debug, Default)]
pub(super) struct ResidentDataUdpObservation {
    last_recorded_unix: [AtomicI64; 2],
}

impl ResidentDataUdpObservation {
    fn should_publish(&self, network_type: NetworkType, checked_at_unix: i64) -> bool {
        let index = match network_type {
            NetworkType::DATA_UDP4 => 0,
            NetworkType::DATA_UDP6 => 1,
            _ => return false,
        };
        let recorded = &self.last_recorded_unix[index];
        let mut previous = recorded.load(Ordering::Relaxed);
        while checked_at_unix > previous {
            match recorded.compare_exchange_weak(
                previous,
                checked_at_unix,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => previous = observed,
            }
        }
        false
    }
}

#[cfg(test)]
mod data_udp_observation_tests {
    use super::*;

    #[test]
    fn successful_data_udp_observations_publish_once_per_family_and_second() {
        let observation = ResidentDataUdpObservation::default();

        assert!(!observation.should_publish(NetworkType::TCP4, 1));
        assert!(observation.should_publish(NetworkType::DATA_UDP4, 10));
        assert!(!observation.should_publish(NetworkType::DATA_UDP4, 10));
        assert!(!observation.should_publish(NetworkType::DATA_UDP4, 9));
        assert!(observation.should_publish(NetworkType::DATA_UDP6, 10));
        assert!(!observation.should_publish(NetworkType::DATA_UDP6, 10));
        assert!(observation.should_publish(NetworkType::DATA_UDP4, 11));
    }
}

pub(crate) type ResidentProxyGroupHandle = Arc<ResidentProxyGroupPlan>;
pub(crate) type ResidentProxyGroupHandleMap = BTreeMap<u8, ResidentProxyGroupHandle>;
pub(crate) type SharedResidentProxyGroupMap = Arc<ResidentProxyGroupHandleMap>;

#[derive(Clone, Debug)]
pub(crate) struct ResidentDnsProxyGroupSelector {
    proxy_groups: SharedResidentProxyGroupMap,
}

impl ResidentDnsProxyGroupSelector {
    pub(crate) fn shared(proxy_groups: SharedResidentProxyGroupMap) -> Arc<Self> {
        Arc::new(Self { proxy_groups })
    }
}

impl dae_resident_dns::ResidentDnsProxySelector for ResidentDnsProxyGroupSelector {
    fn select(
        &self,
        outbound: u8,
        network_type: NetworkType,
    ) -> Result<
        dae_resident_dns::ResidentDnsProxySelection,
        dae_resident_dns::ResidentDnsProxySelectionError,
    > {
        let proxy_group = self.proxy_groups.get(&outbound).ok_or_else(|| {
            dae_resident_dns::ResidentDnsProxySelectionError {
                message: format!(
                    "DNS upstream selected outbound {} but no Rust proxy plan is available",
                    OutboundIndex(outbound)
                ),
                no_alive: false,
            }
        })?;
        proxy_group
            .select_proxy_for_dns_upstream_candidate_detail(network_type)
            .map(|selection| dae_resident_dns::ResidentDnsProxySelection {
                binding: selection.proxy,
                network_type: selection.network_type,
                latency_ms: selection.latency_ms,
            })
            .map_err(|error| dae_resident_dns::ResidentDnsProxySelectionError {
                message: error.message,
                no_alive: error.no_alive,
            })
    }
}

#[derive(Clone)]
pub(crate) struct ResidentDataUdpAvailabilityHandle {
    selector: std::sync::Weak<std::sync::RwLock<DialerGroup>>,
    health_bootstrap: ResidentGroupHealthBootstrap,
    observation: Arc<ResidentDataUdpObservation>,
    candidate_index: usize,
    enabled: bool,
}

impl ResidentDataUdpAvailabilityHandle {
    pub(crate) fn record(&self, network_type: NetworkType, checked_at_unix: i64) {
        if !self.enabled
            || !self
                .observation
                .should_publish(network_type, checked_at_unix)
        {
            return;
        }
        if let Some(selector) = self.selector.upgrade()
            && let Ok(mut selector) = selector.write()
        {
            selector.record_available_traffic(self.candidate_index, network_type, checked_at_unix);
        }
        self.health_bootstrap
            .observe(self.candidate_index, HealthState::Alive);
    }
}

pub(crate) fn share_resident_proxy_groups(
    groups: BTreeMap<u8, ResidentProxyGroupPlan>,
) -> SharedResidentProxyGroupMap {
    Arc::new(
        groups
            .into_iter()
            .map(|(outbound, group)| (outbound, Arc::new(group)))
            .collect(),
    )
}

fn push_unique_network_type(network_types: &mut Vec<NetworkType>, network_type: NetworkType) {
    if !network_types.contains(&network_type) {
        network_types.push(network_type);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentProxyLatencySnapshot {
    pub(crate) node_tag: String,
    pub(crate) graph_id: String,
    pub(crate) link_hash: String,
    pub(crate) execution_identity: String,
    pub(crate) redacted_link_source: String,
    pub(crate) network_type: NetworkType,
    pub(crate) latency_ms: Option<i64>,
    pub(crate) alive: bool,
    pub(crate) checked_at_unix: i64,
    pub(crate) message: String,
    pub(crate) health_state: HealthState,
    pub(crate) last_success_at_unix: i64,
    pub(crate) last_failure_at_unix: i64,
    pub(crate) last_unknown_at_unix: i64,
    pub(crate) target_identity: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResidentDialerLatencySnapshotState {
    network_type: NetworkType,
    latency_ms: i64,
    alive: bool,
    checked_at_unix: i64,
    ok: bool,
    health_state: HealthState,
    last_success_at_unix: i64,
    last_failure_at_unix: i64,
    last_unknown_at_unix: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct ResidentProxySelection {
    pub(crate) proxy: ResidentProxyBinding,
    pub(crate) network_type: NetworkType,
    pub(crate) latency_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentProxySelectionError {
    pub(crate) message: String,
    pub(crate) no_alive: bool,
}

struct ResidentSelectedProxyCandidate<'a> {
    candidate: &'a ResidentProxyCandidatePlan,
    network_type: NetworkType,
    latency_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ResidentGroupPolicyPlan {
    Fixed { index: usize },
    Random,
    MinLastLatency,
    MinAverage10,
    MinMovingAverage,
}

impl ResidentGroupPolicyPlan {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Fixed { .. } => "fixed",
            Self::Random => "random",
            Self::MinLastLatency => "min",
            Self::MinAverage10 => "min_avg10",
            Self::MinMovingAverage => "min_moving_avg",
        }
    }

    pub(crate) fn fixed_index(&self) -> Option<usize> {
        match self {
            Self::Fixed { index } => Some(*index),
            _ => None,
        }
    }

    pub(crate) fn needs_latency_state(&self) -> bool {
        matches!(
            self,
            Self::MinLastLatency | Self::MinAverage10 | Self::MinMovingAverage
        )
    }

    pub(crate) fn needs_alive_state(&self) -> bool {
        !matches!(self, Self::Fixed { .. })
    }
}

impl ResidentDialerLatencySnapshotState {
    fn from_dialer(dialer: &Dialer, network_type: NetworkType) -> Self {
        let (latency_ms, alive, checked_at_unix, ok) = dialer.last_latency_snapshot(network_type);
        let health = dialer.health_snapshot(network_type);
        Self {
            network_type,
            latency_ms,
            alive,
            checked_at_unix,
            ok,
            health_state: health
                .as_ref()
                .map(|snapshot| snapshot.health_state)
                .unwrap_or(HealthState::Unknown),
            last_success_at_unix: health
                .as_ref()
                .map(|snapshot| snapshot.last_success_at_unix)
                .unwrap_or(0),
            last_failure_at_unix: health
                .as_ref()
                .map(|snapshot| snapshot.last_failure_at_unix)
                .unwrap_or(0),
            last_unknown_at_unix: health
                .as_ref()
                .map(|snapshot| snapshot.last_unknown_at_unix)
                .unwrap_or(0),
        }
    }
}

#[cfg(test)]
fn prefer_resident_latency_snapshot_state(
    next: ResidentDialerLatencySnapshotState,
    current: ResidentDialerLatencySnapshotState,
) -> bool {
    match (next.ok && next.alive, current.ok && current.alive) {
        (true, false) => return true,
        (false, true) => return false,
        (true, true) => return next.latency_ms < current.latency_ms,
        (false, false) => {}
    }
    match (next.ok, current.ok) {
        (true, false) => true,
        (false, true) => false,
        _ => next.checked_at_unix > current.checked_at_unix,
    }
}

#[cfg(test)]
fn preferred_resident_tcp_latency_snapshot_state(
    dialer: &Dialer,
    network_types: &[NetworkType],
) -> ResidentDialerLatencySnapshotState {
    network_types
        .iter()
        .copied()
        .map(|network_type| ResidentDialerLatencySnapshotState::from_dialer(dialer, network_type))
        .reduce(|current, next| {
            if prefer_resident_latency_snapshot_state(next, current) {
                next
            } else {
                current
            }
        })
        .unwrap_or(ResidentDialerLatencySnapshotState {
            network_type: NetworkType::TCP4,
            latency_ms: 0,
            alive: false,
            checked_at_unix: 0,
            ok: false,
            health_state: HealthState::Unknown,
            last_success_at_unix: 0,
            last_failure_at_unix: 0,
            last_unknown_at_unix: 0,
        })
}

#[derive(Clone, Debug)]
pub(crate) struct ResidentProxyGroupPlan {
    pub(crate) group_name: String,
    pub(crate) group_policy: ResidentGroupPolicyPlan,
    pub(crate) matched_candidate_count: usize,
    pub(crate) candidates: Vec<ResidentProxyCandidatePlan>,
    pub(super) candidate_index_by_node_tag: Arc<std::collections::HashMap<String, usize>>,
    pub(crate) selector: Arc<std::sync::RwLock<DialerGroup>>,
    pub(crate) check_interval: Duration,
    pub(crate) probe_profile: Arc<ResidentProbeProfile>,
    pub(crate) probe_candidates: Arc<[ResidentProxyProbePlan]>,
    pub(crate) resuscitation_last_unix_ms: Arc<Vec<AtomicI64>>,
    pub(crate) health_bootstrap: ResidentGroupHealthBootstrap,
}

impl ResidentProxyGroupPlan {
    pub(crate) fn apply_runtime_generation(
        &mut self,
        runtime_generation: u64,
    ) -> Result<(), String> {
        for candidate in &mut self.candidates {
            candidate.binding.bind_resident_generation(
                dae_runtime_control::OwnerGeneration::new(runtime_generation),
            )?;
        }
        let probes = Arc::get_mut(&mut self.probe_candidates).ok_or_else(|| {
            format!(
                "resident dataplane group {} probe plans were shared before generation binding",
                self.group_name
            )
        })?;
        for probe in probes {
            probe.apply_runtime_generation(runtime_generation)?;
        }
        Ok(())
    }

    pub(crate) fn group_policy_name(&self) -> &'static str {
        self.group_policy.as_str()
    }

    pub(crate) fn candidate_count(&self) -> usize {
        self.matched_candidate_count
    }

    pub(crate) fn admitted_candidate_count(&self) -> usize {
        self.candidates.len()
    }

    pub(crate) fn requires_tuic_transport_owner(&self) -> bool {
        self.candidates.iter().any(|candidate| {
            matches!(
                &candidate.binding.plan().handler,
                ResidentProxyProtocolPlan::TuicQuicTcp { .. }
            )
        })
    }

    pub(crate) fn requires_juicity_transport_owner(&self) -> bool {
        self.candidates.iter().any(|candidate| {
            matches!(
                &candidate.binding.plan().handler,
                ResidentProxyProtocolPlan::JuicityQuicTcp { .. }
            )
        })
    }

    pub(crate) fn requires_anytls_transport_owner(&self) -> bool {
        self.candidates
            .iter()
            .any(|candidate| candidate.binding.plan().requires_anytls_transport_owner())
    }

    pub(crate) fn requires_h2_carrier_owner(&self) -> bool {
        self.candidates
            .iter()
            .any(|candidate| candidate.binding.plan().requires_h2_carrier_owner())
    }

    pub(crate) fn requires_meek_transport_owner(&self) -> bool {
        self.candidates
            .iter()
            .any(|candidate| candidate.binding.plan().requires_meek_transport_owner())
    }

    pub(crate) fn requires_vless_mux_owner(&self) -> bool {
        self.candidates
            .iter()
            .any(|candidate| candidate.binding.plan().requires_vless_mux_owner())
    }

    pub(crate) fn requires_xhttp_xmux_owner(&self) -> bool {
        self.candidates
            .iter()
            .any(|candidate| candidate.binding.plan().requires_xhttp_xmux_owner())
    }

    pub(crate) fn annotation_latency_offset_count(&self) -> usize {
        self.candidates
            .iter()
            .filter(|candidate| candidate.annotation_add_latency_ms != 0)
            .count()
    }

    fn tcp_check_network_types(&self) -> Vec<NetworkType> {
        let mut network_types = Vec::new();
        for target in &self.probe_profile.tcp_check.targets {
            if let Some(network_type) = target.network_type_hint() {
                push_unique_network_type(&mut network_types, network_type);
            }
        }
        if network_types.is_empty() {
            network_types.extend([NetworkType::TCP4, NetworkType::TCP6]);
        }
        network_types
    }

    pub(crate) fn latency_state_wired(&self) -> bool {
        if !self.group_policy.needs_latency_state() {
            return true;
        }
        let network_types = self.tcp_check_network_types();
        self.selector
            .read()
            .ok()
            .map(|selector| {
                network_types.iter().all(|network_type| {
                    selector
                        .alive_set(*network_type)
                        .map(|alive_set| alive_set.latency_state_allocated)
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    pub(crate) fn alive_state_wired(&self) -> bool {
        if !self.group_policy.needs_alive_state() {
            return true;
        }
        self.selector
            .read()
            .map(|selector| selector.has_alive_state())
            .unwrap_or(false)
    }

    pub(crate) fn default_proxy_snapshot(&self) -> Option<ResidentProxyBinding> {
        self.snapshot_candidate()
            .map(|candidate| candidate.binding.clone())
    }

    pub(crate) fn needs_background_checks(&self) -> bool {
        self.group_policy.needs_alive_state()
    }

    pub(crate) fn begin_health_bootstrap(&self) {
        self.health_bootstrap.begin();
    }

    pub(crate) fn complete_health_bootstrap(&self, cancelled: bool) {
        self.health_bootstrap.complete(cancelled);
    }

    pub(crate) fn health_bootstrap_snapshot_json(&self) -> Value {
        self.health_bootstrap.snapshot_json()
    }

    pub(crate) fn check_interval(&self) -> Duration {
        self.check_interval
    }

    pub(crate) fn try_begin_resuscitation(&self, network_type: NetworkType) -> bool {
        if !self.group_policy.needs_alive_state() {
            return false;
        }
        let now_ms = resident_group_resuscitation_now_ms();
        let interval = (self.check_interval / RESIDENT_GROUP_RESUSCITATION_INTERVAL_DIVISOR).clamp(
            RESIDENT_GROUP_RESUSCITATION_MIN_INTERVAL,
            RESIDENT_GROUP_RESUSCITATION_MAX_INTERVAL,
        );
        let interval_ms = interval.as_millis().min(i64::MAX as u128) as i64;
        let Some(last_resuscitation) = self
            .resuscitation_last_unix_ms
            .get(network_type.collection_index())
        else {
            return false;
        };
        let mut last_ms = last_resuscitation.load(Ordering::Relaxed);
        loop {
            if now_ms.saturating_sub(last_ms) < interval_ms {
                return false;
            }
            match last_resuscitation.compare_exchange(
                last_ms,
                now_ms,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(value) => last_ms = value,
            }
        }
    }

    pub(crate) fn probe_candidates(&self) -> Arc<[ResidentProxyProbePlan]> {
        Arc::clone(&self.probe_candidates)
    }

    #[cfg(test)]
    pub(crate) fn latency_snapshots(&self) -> Vec<ResidentProxyLatencySnapshot> {
        let Ok(selector) = self.selector.read() else {
            return Vec::new();
        };
        let network_types = self.tcp_check_network_types();
        self.candidates
            .iter()
            .enumerate()
            .map(|(index, candidate)| {
                let snapshot = selector
                    .dialers
                    .get(index)
                    .map(|dialer| {
                        preferred_resident_tcp_latency_snapshot_state(dialer, &network_types)
                    })
                    .unwrap_or(ResidentDialerLatencySnapshotState {
                        network_type: NetworkType::TCP4,
                        latency_ms: 0,
                        alive: false,
                        checked_at_unix: 0,
                        ok: false,
                        health_state: HealthState::Unknown,
                        last_success_at_unix: 0,
                        last_failure_at_unix: 0,
                        last_unknown_at_unix: 0,
                    });
                ResidentProxyLatencySnapshot {
                    node_tag: candidate.binding.plan().node_tag.clone(),
                    graph_id: candidate.binding.plan().graph_id.clone(),
                    link_hash: candidate.link_hash.clone(),
                    execution_identity: candidate.execution_identity.clone(),
                    redacted_link_source: candidate.redacted_link_source.clone(),
                    network_type: snapshot.network_type,
                    latency_ms: snapshot.ok.then_some(snapshot.latency_ms),
                    alive: snapshot.ok && snapshot.alive,
                    checked_at_unix: snapshot.checked_at_unix,
                    message: resident_latency_message(
                        snapshot.ok,
                        snapshot.alive,
                        snapshot.latency_ms,
                    ),
                    health_state: snapshot.health_state,
                    last_success_at_unix: snapshot.last_success_at_unix,
                    last_failure_at_unix: snapshot.last_failure_at_unix,
                    last_unknown_at_unix: snapshot.last_unknown_at_unix,
                    target_identity: self.health_target_identity(snapshot.network_type),
                }
            })
            .collect()
    }

    pub(crate) fn health_state_snapshots(&self) -> Vec<ResidentProxyLatencySnapshot> {
        let Ok(selector) = self.selector.read() else {
            return Vec::new();
        };
        let network_types = [
            NetworkType::TCP4,
            NetworkType::TCP6,
            NetworkType::DNS_TCP4,
            NetworkType::DNS_TCP6,
            NetworkType::DNS_UDP4,
            NetworkType::DNS_UDP6,
            NetworkType::DATA_UDP4,
            NetworkType::DATA_UDP6,
        ];
        self.candidates
            .iter()
            .enumerate()
            .flat_map(|(index, candidate)| {
                let Some(dialer) = selector.dialers.get(index) else {
                    return Vec::new();
                };
                network_types
                    .into_iter()
                    .filter(|network_type| dialer.collection(*network_type).is_some())
                    .map(|network_type| {
                        let snapshot =
                            ResidentDialerLatencySnapshotState::from_dialer(dialer, network_type);
                        ResidentProxyLatencySnapshot {
                            node_tag: candidate.binding.plan().node_tag.clone(),
                            graph_id: candidate.binding.plan().graph_id.clone(),
                            link_hash: candidate.link_hash.clone(),
                            execution_identity: candidate.execution_identity.clone(),
                            redacted_link_source: candidate.redacted_link_source.clone(),
                            network_type,
                            latency_ms: snapshot.ok.then_some(snapshot.latency_ms),
                            alive: snapshot.alive,
                            checked_at_unix: snapshot.checked_at_unix,
                            message: snapshot.health_state.as_str().to_owned(),
                            health_state: snapshot.health_state,
                            last_success_at_unix: snapshot.last_success_at_unix,
                            last_failure_at_unix: snapshot.last_failure_at_unix,
                            last_unknown_at_unix: snapshot.last_unknown_at_unix,
                            target_identity: self.health_target_identity(network_type),
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    pub(crate) fn health_target_identity(&self, network_type: NetworkType) -> Option<String> {
        if network_type == NetworkType::TCP4 || network_type == NetworkType::TCP6 {
            return Some(
                self.probe_profile
                    .tcp_check
                    .identity(self.probe_profile.tcp_probe_timeout),
            );
        }
        if network_type == NetworkType::DNS_TCP4
            || network_type == NetworkType::DNS_TCP6
            || network_type == NetworkType::DNS_UDP4
            || network_type == NetworkType::DNS_UDP6
        {
            return Some(self.probe_profile.udp_check.identity());
        }
        None
    }

    #[cfg(test)]
    pub(crate) fn select_proxy_for_tcp(&self) -> Result<Arc<ResidentProxyPlan>, String> {
        self.select_proxy_for_tcp_network(NetworkType::TCP4)
    }

    pub(crate) fn select_proxy_for_tcp_network(
        &self,
        network_type: NetworkType,
    ) -> Result<Arc<ResidentProxyPlan>, String> {
        self.select_candidate(network_type, false)
            .map(|candidate| Arc::clone(candidate.binding.shared_plan()))
    }

    #[cfg(test)]
    pub(crate) fn select_proxy_for_tcp_runtime(
        &self,
        network_type: NetworkType,
        strict_ip_version: bool,
    ) -> Result<Arc<ResidentProxyPlan>, String> {
        self.select_proxy_for_tcp_runtime_detail(network_type, strict_ip_version)
            .map(ResidentProxyBinding::into_shared_plan)
            .map_err(|err| err.message)
    }

    pub(crate) fn select_proxy_for_tcp_runtime_detail(
        &self,
        network_type: NetworkType,
        strict_ip_version: bool,
    ) -> Result<ResidentProxyBinding, ResidentProxySelectionError> {
        self.select_candidate_with_selection_detail(network_type, strict_ip_version)
            .map(|candidate| candidate.candidate.binding.clone())
    }

    #[cfg(test)]
    pub(crate) fn select_proxy_for_udp(&self) -> Result<Arc<ResidentProxyPlan>, String> {
        self.select_proxy_for_udp_network(NetworkType::DNS_UDP4)
    }

    #[cfg(test)]
    pub(crate) fn select_proxy_for_udp_network(
        &self,
        network_type: NetworkType,
    ) -> Result<Arc<ResidentProxyPlan>, String> {
        self.select_candidate(network_type, false)
            .map(|candidate| Arc::clone(candidate.binding.shared_plan()))
    }

    #[cfg(test)]
    pub(crate) fn select_proxy_for_udp_runtime(
        &self,
        network_type: NetworkType,
        strict_ip_version: bool,
    ) -> Result<Arc<ResidentProxyPlan>, String> {
        self.select_proxy_for_udp_runtime_candidate(network_type, strict_ip_version)
            .map(|selection| selection.proxy.into_shared_plan())
    }

    #[cfg(test)]
    pub(crate) fn select_proxy_for_udp_runtime_candidate(
        &self,
        network_type: NetworkType,
        strict_ip_version: bool,
    ) -> Result<ResidentProxySelection, String> {
        self.select_proxy_for_udp_runtime_candidate_detail(network_type, strict_ip_version)
            .map_err(|err| err.message)
    }

    pub(crate) fn select_proxy_for_udp_runtime_candidate_detail(
        &self,
        network_type: NetworkType,
        strict_ip_version: bool,
    ) -> Result<ResidentProxySelection, ResidentProxySelectionError> {
        let selected =
            self.select_candidate_with_selection_detail(network_type, strict_ip_version)?;
        Ok(ResidentProxySelection {
            proxy: selected.candidate.binding.clone(),
            network_type: selected.network_type,
            latency_ms: selected.latency_ms,
        })
    }

    pub(crate) fn data_udp_availability_handle(
        &self,
        node_tag: &str,
    ) -> Result<ResidentDataUdpAvailabilityHandle, String> {
        let Some(candidate_index) = self
            .candidates
            .iter()
            .position(|candidate| candidate.binding.plan().node_tag == node_tag)
        else {
            return Err(format!(
                "resident dataplane group {} has no admitted candidate named {node_tag}",
                self.group_name
            ));
        };
        Ok(ResidentDataUdpAvailabilityHandle {
            selector: Arc::downgrade(&self.selector),
            health_bootstrap: self.health_bootstrap.clone(),
            observation: Arc::clone(&self.candidates[candidate_index].data_udp_observation),
            candidate_index,
            enabled: self.group_policy.needs_alive_state(),
        })
    }

    #[cfg(test)]
    pub(crate) fn select_proxy_for_dns_upstream(
        &self,
        network_type: NetworkType,
    ) -> Result<Arc<ResidentProxyPlan>, String> {
        self.select_proxy_for_dns_upstream_candidate(network_type)
            .map(|selection| selection.proxy.into_shared_plan())
    }

    #[cfg(test)]
    pub(crate) fn select_proxy_for_dns_upstream_candidate(
        &self,
        network_type: NetworkType,
    ) -> Result<ResidentProxySelection, String> {
        self.select_proxy_for_dns_upstream_candidate_detail(network_type)
            .map_err(|err| err.message)
    }

    pub(crate) fn select_proxy_for_dns_upstream_candidate_detail(
        &self,
        network_type: NetworkType,
    ) -> Result<ResidentProxySelection, ResidentProxySelectionError> {
        let selected = self.select_candidate_with_selection_detail(network_type, false)?;
        Ok(ResidentProxySelection {
            proxy: selected.candidate.binding.clone(),
            network_type: selected.network_type,
            latency_ms: selected.latency_ms,
        })
    }

    pub(crate) fn snapshot_candidate(&self) -> Option<&ResidentProxyCandidatePlan> {
        match self.group_policy {
            ResidentGroupPolicyPlan::Fixed { index } => self
                .candidates
                .iter()
                .find(|candidate| candidate.match_index == index),
            ResidentGroupPolicyPlan::Random
            | ResidentGroupPolicyPlan::MinLastLatency
            | ResidentGroupPolicyPlan::MinAverage10
            | ResidentGroupPolicyPlan::MinMovingAverage => self.candidates.first(),
        }
    }

    pub(crate) fn select_candidate(
        &self,
        network_type: NetworkType,
        strict_ip_version: bool,
    ) -> Result<&ResidentProxyCandidatePlan, String> {
        self.select_candidate_with_selection(network_type, strict_ip_version)
            .map(|selected| selected.candidate)
    }

    fn select_candidate_with_selection(
        &self,
        network_type: NetworkType,
        strict_ip_version: bool,
    ) -> Result<ResidentSelectedProxyCandidate<'_>, String> {
        self.select_candidate_with_selection_detail(network_type, strict_ip_version)
            .map_err(|err| err.message)
    }

    fn select_candidate_with_selection_detail(
        &self,
        network_type: NetworkType,
        strict_ip_version: bool,
    ) -> Result<ResidentSelectedProxyCandidate<'_>, ResidentProxySelectionError> {
        let network = network_type.label_without_dns();
        if self.candidates.is_empty() {
            return Err(resident_proxy_selection_error(
                format!(
                    "resident dataplane group {} has no admitted candidate for {network}",
                    self.group_name
                ),
                false,
            ));
        }
        match self.group_policy {
            ResidentGroupPolicyPlan::Fixed { index } => {
                let candidate = self
                    .candidates
                    .iter()
                    .find(|candidate| candidate.match_index == index)
                    .ok_or_else(|| {
                        resident_proxy_selection_error(
                            format!(
                                "resident dataplane group {} fixed policy index {} is not admitted for {network}",
                                self.group_name, index
                            ),
                            false,
                        )
                    })?;
                Ok(ResidentSelectedProxyCandidate {
                    candidate,
                    network_type,
                    latency_ms: 0,
                })
            }
            ResidentGroupPolicyPlan::MinLastLatency
            | ResidentGroupPolicyPlan::MinAverage10
            | ResidentGroupPolicyPlan::MinMovingAverage
            | ResidentGroupPolicyPlan::Random => {
                let selected = self
                    .selector
                    .read()
                    .map_err(|_| {
                        resident_proxy_selection_error(
                            format!(
                                "resident dataplane group {} selector lock is poisoned",
                                self.group_name
                            ),
                            false,
                        )
                    })?
                    .select(network_type, strict_ip_version)
                    .map_err(|err| {
                        resident_proxy_selection_error(
                            format!(
                                "resident dataplane group {} selector failed for {network}: {err}",
                                self.group_name
                            ),
                            matches!(err, OutboundError::NoAliveDialer),
                        )
                    })?;
                let candidate = self.candidates.get(selected.index).ok_or_else(|| {
                    resident_proxy_selection_error(
                        format!(
                            "resident dataplane group {} selector returned missing candidate {} for {network}",
                            self.group_name, selected.index
                        ),
                        false,
                    )
                })?;
                Ok(ResidentSelectedProxyCandidate {
                    candidate,
                    network_type: selected.network_type,
                    latency_ms: selected.latency_ms,
                })
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn record_check_result(
        &self,
        node_tag: &str,
        network_type: NetworkType,
        latency_ms: Option<i64>,
        checked_at_unix: i64,
    ) -> Result<(), String> {
        let Some(index) = self.candidate_index_by_node_tag.get(node_tag).copied() else {
            return Err(format!(
                "resident dataplane group {} has no admitted candidate named {node_tag}",
                self.group_name
            ));
        };
        self.selector
            .write()
            .map_err(|_| {
                format!(
                    "resident dataplane group {} selector lock is poisoned",
                    self.group_name
                )
            })?
            .record_check_result(index, network_type, latency_ms, checked_at_unix);
        Ok(())
    }

    pub(crate) fn record_health_state(
        &self,
        node_tag: &str,
        network_type: NetworkType,
        health_state: HealthState,
        latency_ms: Option<i64>,
        checked_at_unix: i64,
    ) -> Result<(), String> {
        let Some(index) = self.candidate_index_by_node_tag.get(node_tag).copied() else {
            return Err(format!(
                "resident dataplane group {} has no admitted candidate named {node_tag}",
                self.group_name
            ));
        };
        let mut selector = self.selector.write().map_err(|_| {
            format!(
                "resident dataplane group {} selector lock is poisoned",
                self.group_name
            )
        })?;
        record_selector_health_state(
            &mut selector,
            index,
            network_type,
            health_state,
            latency_ms,
            checked_at_unix,
        )
        .map_err(|err| format!("resident dataplane group {} {err}", self.group_name))?;
        drop(selector);
        self.health_bootstrap.observe(index, health_state);
        Ok(())
    }

    pub(crate) fn record_manual_latency_result_for_link(
        &self,
        link: &str,
        network_type: NetworkType,
        latency_ms: Option<i64>,
        checked_at_unix: i64,
    ) -> Result<usize, String> {
        self.record_manual_health_state_for_link(
            link,
            network_type,
            if latency_ms.is_some() {
                HealthState::Alive
            } else {
                HealthState::Dead
            },
            latency_ms,
            checked_at_unix,
        )
    }

    pub(crate) fn record_manual_health_state_for_link(
        &self,
        link: &str,
        network_type: NetworkType,
        health_state: HealthState,
        latency_ms: Option<i64>,
        checked_at_unix: i64,
    ) -> Result<usize, String> {
        let indexes = self
            .candidates
            .iter()
            .enumerate()
            .filter_map(|(index, candidate)| (candidate.link == link).then_some(index))
            .collect::<Vec<_>>();
        if indexes.is_empty() {
            return Ok(0);
        }
        let mut selector = self.selector.write().map_err(|_| {
            format!(
                "resident dataplane group {} selector lock is poisoned",
                self.group_name
            )
        })?;
        for index in &indexes {
            record_selector_health_state(
                &mut selector,
                *index,
                network_type,
                health_state,
                latency_ms,
                checked_at_unix,
            )
            .map_err(|err| format!("resident dataplane group {} {err}", self.group_name))?;
            self.health_bootstrap.observe(*index, health_state);
        }
        Ok(indexes.len())
    }

    pub(crate) fn apply_health_seed_snapshot(&self, snapshot: &Value) -> Result<usize, String> {
        if !self.group_policy.needs_alive_state() {
            return Ok(0);
        }
        let execution_identity = snapshot
            .get("executionIdentity")
            .and_then(Value::as_str)
            .filter(|identity| !identity.is_empty());
        let legacy_link_hash =
            latency_seed_snapshot_link_hash(snapshot).filter(|identity| !identity.is_empty());
        if execution_identity.is_none() && legacy_link_hash.is_none() {
            return Ok(0);
        }
        let Some(network_type) = health_seed_snapshot_network_type(snapshot) else {
            return Ok(0);
        };
        let checked_at_unix = snapshot
            .get("checkedAtUnix")
            .and_then(Value::as_i64)
            .filter(|value| *value > 0)
            .unwrap_or(0);
        if snapshot.get("seedSource").and_then(Value::as_str) == Some("database")
            && !self.database_health_seed_is_fresh(checked_at_unix)
        {
            return Ok(0);
        }
        if let Some(target_identity) = snapshot.get("targetIdentity").and_then(Value::as_str)
            && self.health_target_identity(network_type).as_deref() != Some(target_identity)
        {
            return Ok(0);
        }
        let health_state = snapshot
            .get("healthState")
            .and_then(Value::as_str)
            .and_then(HealthState::parse)
            .unwrap_or_else(|| {
                if snapshot
                    .get("alive")
                    .and_then(Value::as_bool)
                    .unwrap_or_else(|| snapshot.get("latencyMs").and_then(Value::as_i64).is_some())
                {
                    HealthState::Alive
                } else {
                    HealthState::Dead
                }
            });
        let latency_ms = snapshot.get("latencyMs").and_then(Value::as_i64);
        if health_state == HealthState::Alive && latency_ms.is_none() {
            return Ok(0);
        }
        let indexes = self
            .candidates
            .iter()
            .enumerate()
            .filter_map(|(index, candidate)| {
                let matches = execution_identity
                    .map(|identity| candidate.execution_identity == identity)
                    .unwrap_or_else(|| {
                        legacy_link_hash
                            .map(|identity| candidate.link_hash == identity)
                            .unwrap_or(false)
                    });
                matches.then_some(index)
            })
            .collect::<Vec<_>>();
        if indexes.is_empty() {
            return Ok(0);
        }
        let restored = DialerHealthSnapshot {
            latency_ms,
            alive: match health_state {
                HealthState::Alive => true,
                HealthState::Dead | HealthState::Unavailable => false,
                HealthState::Unknown => snapshot
                    .get("alive")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            },
            checked_at_unix,
            health_state,
            last_success_at_unix: snapshot
                .get("lastSuccessAtUnix")
                .and_then(Value::as_i64)
                .unwrap_or_else(|| {
                    if health_state == HealthState::Alive {
                        checked_at_unix
                    } else {
                        0
                    }
                }),
            last_failure_at_unix: snapshot
                .get("lastFailureAtUnix")
                .and_then(Value::as_i64)
                .unwrap_or_else(|| {
                    if health_state == HealthState::Dead {
                        checked_at_unix
                    } else {
                        0
                    }
                }),
            last_unknown_at_unix: snapshot
                .get("lastUnknownAtUnix")
                .and_then(Value::as_i64)
                .unwrap_or(0),
        };
        let mut selector = self.selector.write().map_err(|_| {
            format!(
                "resident dataplane group {} selector lock is poisoned",
                self.group_name
            )
        })?;
        for index in &indexes {
            selector.restore_health_snapshot(*index, network_type, restored);
            self.health_bootstrap.observe(*index, health_state);
        }
        Ok(indexes.len())
    }

    fn database_health_seed_is_fresh(&self, checked_at_unix: i64) -> bool {
        if checked_at_unix <= 0 || self.check_interval.is_zero() {
            return false;
        }
        let ttl_seconds = self
            .check_interval
            .saturating_mul(RESIDENT_HEALTH_DATABASE_SEED_TTL_INTERVALS)
            .as_secs()
            .min(i64::MAX as u64) as i64;
        resident_group_now_secs().saturating_sub(checked_at_unix) <= ttl_seconds
    }

    #[cfg(test)]
    pub(crate) fn fixed_single_for_test(mut proxy: ResidentProxyPlan) -> Self {
        proxy.materialize_execution();
        let udp_check_addr = SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            dae_dns::ACTIVE_DNS_DEFAULT_TARGET_PORT,
        );
        let tcp_check_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 80);
        let tcp_check_host = tcp_check_addr.ip().to_string();
        let tcp_check_target = ResidentTcpCheckTarget {
            target: tcp_check_addr.to_string(),
            network_type: Some(NetworkType::TCP4),
        };
        let udp_check_target = ResidentUdpCheckTarget::literal(udp_check_addr);
        let group_name = proxy.group_name.clone();
        let candidates = vec![ResidentProxyCandidatePlan {
            match_index: 0,
            annotation_add_latency_ms: 0,
            link: proxy.node_tag.clone(),
            link_hash: link_hash(&proxy.node_tag),
            execution_identity: execution_link_hash(&proxy.node_tag),
            redacted_link_source: redacted_link_source(&proxy.node_tag),
            binding: ResidentProxyBinding::configuration(Arc::new(proxy))
                .expect("materialized fixed test proxy binding"),
            data_udp_observation: Arc::new(ResidentDataUdpObservation::default()),
        }];
        let probe_profile = Arc::new(ResidentProbeProfile::new(
            ResidentTcpCheckPlan {
                scheme: "http".to_owned(),
                target: tcp_check_target.target.clone(),
                targets: vec![tcp_check_target],
                host: tcp_check_host.clone(),
                path: "/".to_owned(),
                method: "HEAD".to_owned(),
                resolver: ResidentHealthTargetResolver::new(
                    tcp_check_host,
                    80,
                    vec![tcp_check_addr],
                    udp_check_addr,
                    0,
                    Duration::from_secs(30),
                ),
            },
            ResidentUdpCheckPlan {
                target: udp_check_target.clone(),
                targets: vec![udp_check_target],
                host: "localhost".to_owned(),
                lookup_host: "connectivitycheck.gstatic.com.".to_owned(),
                resolver: ResidentHealthTargetResolver::new(
                    udp_check_addr.ip().to_string(),
                    udp_check_addr.port(),
                    vec![udp_check_addr],
                    udp_check_addr,
                    0,
                    Duration::from_secs(30),
                ),
            },
            RESIDENT_TCP_LATENCY_PROBE_TIMEOUT,
        ));
        let probe_candidates = share_group_probe_plans(&candidates, Arc::clone(&probe_profile));
        let mut candidate_index_by_node_tag =
            std::collections::HashMap::with_capacity(candidates.len());
        for (index, candidate) in candidates.iter().enumerate() {
            candidate_index_by_node_tag
                .entry(candidate.binding.plan().node_tag.clone())
                .or_insert(index);
        }
        Self {
            group_name,
            group_policy: ResidentGroupPolicyPlan::Fixed { index: 0 },
            matched_candidate_count: 1,
            candidates,
            candidate_index_by_node_tag: Arc::new(candidate_index_by_node_tag),
            selector: Arc::new(std::sync::RwLock::new(DialerGroup::new(
                "test",
                vec![Dialer::new("test", "")],
                vec![Annotation::default()],
                SelectionPolicy::Fixed { index: 0 },
                true,
                0,
            ))),
            check_interval: Duration::from_secs(30),
            probe_profile,
            probe_candidates,
            resuscitation_last_unix_ms: Arc::new(
                (0..NETWORK_TYPE_COLLECTION_COUNT)
                    .map(|_| AtomicI64::new(0))
                    .collect(),
            ),
            health_bootstrap: ResidentGroupHealthBootstrap::new(1),
        }
    }
}

fn record_selector_health_state(
    selector: &mut DialerGroup,
    index: usize,
    network_type: NetworkType,
    health_state: HealthState,
    latency_ms: Option<i64>,
    checked_at_unix: i64,
) -> Result<(), &'static str> {
    match health_state {
        HealthState::Alive => {
            let Some(latency_ms) = latency_ms else {
                return Err("alive health result has no latency");
            };
            selector.record_check_result(index, network_type, Some(latency_ms), checked_at_unix);
        }
        HealthState::Dead => {
            selector.record_check_failure_without_latency(index, network_type, checked_at_unix)
        }
        HealthState::Unavailable => {
            selector.record_check_unavailable(index, network_type, checked_at_unix)
        }
        HealthState::Unknown => selector.record_check_unknown(index, network_type, checked_at_unix),
    }
    Ok(())
}

fn resident_proxy_selection_error(message: String, no_alive: bool) -> ResidentProxySelectionError {
    ResidentProxySelectionError { message, no_alive }
}

fn resident_group_resuscitation_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

fn resident_group_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

#[cfg(test)]
pub(crate) fn resident_latency_message(ok: bool, alive: bool, latency_ms: i64) -> String {
    if !ok {
        "no latency result".to_owned()
    } else if alive {
        format!("{latency_ms}ms")
    } else {
        "unavailable".to_owned()
    }
}

pub(crate) fn apply_health_seed_snapshots(
    groups: &BTreeMap<u8, ResidentProxyGroupPlan>,
    snapshots: &[Value],
) {
    if groups.is_empty() || snapshots.is_empty() {
        return;
    }
    for snapshot in snapshots {
        for group in groups.values() {
            let _ = group.apply_health_seed_snapshot(snapshot);
        }
    }
}

fn latency_seed_snapshot_link_hash(snapshot: &Value) -> Option<&str> {
    snapshot
        .get("linkHash")
        .and_then(Value::as_str)
        .or_else(|| {
            snapshot
                .pointer("/linkIdentity/linkHash")
                .and_then(Value::as_str)
        })
}

fn health_seed_snapshot_network_type(snapshot: &Value) -> Option<NetworkType> {
    if let Some(dimension) = snapshot.get("networkDimension").and_then(Value::as_str) {
        return NetworkType::from_dimension_name(dimension);
    }
    let Some(raw) = snapshot.get("networkType").and_then(Value::as_str) else {
        return (snapshot.get("scope").and_then(Value::as_str) == Some("proxy-tcp-check"))
            .then_some(NetworkType::TCP4);
    };
    [NetworkType::TCP4, NetworkType::TCP6]
        .into_iter()
        .find(|network_type| network_type.string_without_dns() == raw)
}
