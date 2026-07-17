use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

const RESIDENT_GROUP_RESUSCITATION_MIN_INTERVAL: Duration = Duration::from_secs(1);
const RESIDENT_GROUP_RESUSCITATION_MAX_INTERVAL: Duration = Duration::from_secs(30);
const RESIDENT_GROUP_RESUSCITATION_INTERVAL_DIVISOR: u32 = 8;
const RESIDENT_HEALTH_DATABASE_SEED_TTL_INTERVALS: u32 = 2;
#[derive(Clone, Debug)]
pub(crate) struct ResidentProxyCandidatePlan {
    pub(in crate::production_runtime_owner::resident_dataplane) match_index: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) annotation_add_latency_ms: i64,
    pub(in crate::production_runtime_owner::resident_dataplane) link: String,
    pub(in crate::production_runtime_owner::resident_dataplane) link_hash: String,
    pub(in crate::production_runtime_owner::resident_dataplane) execution_identity: String,
    pub(in crate::production_runtime_owner::resident_dataplane) redacted_link_source: String,
    pub(in crate::production_runtime_owner::resident_dataplane) proxy: Arc<ResidentProxyPlan>,
}

pub(in crate::production_runtime_owner::resident_dataplane) type ResidentProxyGroupHandle =
    Arc<ResidentProxyGroupPlan>;
pub(in crate::production_runtime_owner::resident_dataplane) type ResidentProxyGroupHandleMap =
    BTreeMap<u8, ResidentProxyGroupHandle>;
pub(in crate::production_runtime_owner::resident_dataplane) type SharedResidentProxyGroupMap =
    Arc<ResidentProxyGroupHandleMap>;

pub(in crate::production_runtime_owner::resident_dataplane) fn share_resident_proxy_groups(
    groups: BTreeMap<u8, ResidentProxyGroupPlan>,
) -> SharedResidentProxyGroupMap {
    Arc::new(
        groups
            .into_iter()
            .map(|(outbound, group)| (outbound, Arc::new(group)))
            .collect(),
    )
}

#[derive(Clone, Debug)]
pub(crate) struct ResidentProxyProbePlan {
    pub(in crate::production_runtime_owner::resident_dataplane) node_tag: String,
    pub(in crate::production_runtime_owner::resident_dataplane) link: String,
    pub(in crate::production_runtime_owner::resident_dataplane) link_hash: String,
    pub(in crate::production_runtime_owner::resident_dataplane) execution_identity: String,
    pub(in crate::production_runtime_owner::resident_dataplane) redacted_link_source: String,
    pub(in crate::production_runtime_owner::resident_dataplane) tcp_check: ResidentTcpCheckPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) udp_check: ResidentUdpCheckPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) tcp_probe_timeout: Duration,
    pub(in crate::production_runtime_owner::resident_dataplane) proxy: Arc<ResidentProxyPlan>,
}

impl ResidentProxyProbePlan {
    pub(in crate::production_runtime_owner::resident_dataplane) fn apply_runtime_generation(
        &mut self,
        runtime_generation: u64,
    ) {
        Arc::make_mut(&mut self.proxy).apply_runtime_generation(runtime_generation);
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn apply_latency_probe_control_mark(
        &mut self,
        mark: u32,
    ) {
        Arc::make_mut(&mut self.proxy).apply_latency_probe_control_mark(mark);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentTcpCheckPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) scheme: String,
    pub(in crate::production_runtime_owner::resident_dataplane) target: String,
    pub(in crate::production_runtime_owner::resident_dataplane) targets:
        Vec<ResidentTcpCheckTarget>,
    pub(in crate::production_runtime_owner::resident_dataplane) host: String,
    pub(in crate::production_runtime_owner::resident_dataplane) path: String,
    pub(in crate::production_runtime_owner::resident_dataplane) method: String,
    pub(in crate::production_runtime_owner::resident_dataplane) resolver:
        ResidentHealthTargetResolver,
}

impl ResidentTcpCheckPlan {
    fn identity(&self, probe_timeout: Duration) -> String {
        link_hash(
            &serde_json::json!({
                "resolver": self.resolver.identity(),
                "scheme": self.scheme,
                "host": self.host,
                "path": self.path,
                "method": self.method,
                "probeTimeoutNanos": probe_timeout.as_nanos().to_string(),
            })
            .to_string(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentTcpCheckTarget {
    pub(in crate::production_runtime_owner::resident_dataplane) target: String,
    pub(in crate::production_runtime_owner::resident_dataplane) network_type: Option<NetworkType>,
}

impl ResidentTcpCheckTarget {
    pub(in crate::production_runtime_owner::resident_dataplane) fn network_type_hint(
        &self,
    ) -> Option<NetworkType> {
        self.network_type
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentUdpCheckPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) target: ResidentUdpCheckTarget,
    pub(in crate::production_runtime_owner::resident_dataplane) targets:
        Vec<ResidentUdpCheckTarget>,
    pub(in crate::production_runtime_owner::resident_dataplane) host: String,
    pub(in crate::production_runtime_owner::resident_dataplane) lookup_host: String,
    pub(in crate::production_runtime_owner::resident_dataplane) resolver:
        ResidentHealthTargetResolver,
}

impl ResidentUdpCheckPlan {
    fn identity(&self) -> String {
        link_hash(
            &serde_json::json!({
                "resolver": self.resolver.identity(),
                "lookupHost": self.lookup_host,
            })
            .to_string(),
        )
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ResidentUdpCheckTarget {
    authority: String,
    literal_addr: Option<SocketAddr>,
}

impl ResidentUdpCheckTarget {
    pub(in crate::production_runtime_owner::resident_dataplane) fn new(
        authority: String,
        literal_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            authority,
            literal_addr,
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn literal(
        addr: SocketAddr,
    ) -> Self {
        Self::new(addr.to_string(), Some(addr))
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn authority(&self) -> &str {
        &self.authority
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn network_type_hint(
        &self,
    ) -> Option<NetworkType> {
        self.literal_addr.map(resident_udp_check_network_type)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn literal_addr(
        &self,
    ) -> Option<SocketAddr> {
        self.literal_addr
    }
}

pub(in crate::production_runtime_owner::resident_dataplane) fn resident_tcp_check_network_type(
    addr: IpAddr,
) -> NetworkType {
    if addr.is_ipv6() {
        NetworkType::TCP6
    } else {
        NetworkType::TCP4
    }
}

pub(in crate::production_runtime_owner::resident_dataplane) fn resident_udp_check_network_type(
    addr: SocketAddr,
) -> NetworkType {
    if addr.is_ipv6() {
        NetworkType::DNS_UDP6
    } else {
        NetworkType::DNS_UDP4
    }
}

pub(in crate::production_runtime_owner::resident_dataplane) fn resident_data_udp_network_type(
    addr: SocketAddr,
) -> NetworkType {
    if addr.is_ipv6() {
        NetworkType::DATA_UDP6
    } else {
        NetworkType::DATA_UDP4
    }
}

fn push_unique_network_type(network_types: &mut Vec<NetworkType>, network_type: NetworkType) {
    if !network_types.contains(&network_type) {
        network_types.push(network_type);
    }
}

impl PartialEq for ResidentUdpCheckTarget {
    fn eq(&self, other: &Self) -> bool {
        self.authority == other.authority && self.literal_addr == other.literal_addr
    }
}

impl Eq for ResidentUdpCheckTarget {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentProxyLatencySnapshot {
    pub(in crate::production_runtime_owner::resident_dataplane) node_tag: String,
    pub(in crate::production_runtime_owner::resident_dataplane) graph_id: String,
    pub(in crate::production_runtime_owner::resident_dataplane) link_hash: String,
    pub(in crate::production_runtime_owner::resident_dataplane) execution_identity: String,
    pub(in crate::production_runtime_owner::resident_dataplane) redacted_link_source: String,
    pub(in crate::production_runtime_owner::resident_dataplane) network_type: NetworkType,
    pub(in crate::production_runtime_owner::resident_dataplane) latency_ms: Option<i64>,
    pub(in crate::production_runtime_owner::resident_dataplane) alive: bool,
    pub(in crate::production_runtime_owner::resident_dataplane) checked_at_unix: i64,
    pub(in crate::production_runtime_owner::resident_dataplane) message: String,
    pub(in crate::production_runtime_owner::resident_dataplane) health_state: HealthState,
    pub(in crate::production_runtime_owner::resident_dataplane) last_success_at_unix: i64,
    pub(in crate::production_runtime_owner::resident_dataplane) last_failure_at_unix: i64,
    pub(in crate::production_runtime_owner::resident_dataplane) last_unknown_at_unix: i64,
    pub(in crate::production_runtime_owner::resident_dataplane) target_identity: Option<String>,
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
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentProxySelection {
    pub(in crate::production_runtime_owner::resident_dataplane) proxy: Arc<ResidentProxyPlan>,
    pub(in crate::production_runtime_owner::resident_dataplane) network_type: NetworkType,
    pub(in crate::production_runtime_owner::resident_dataplane) latency_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentProxySelectionError {
    pub(in crate::production_runtime_owner::resident_dataplane) message: String,
    pub(in crate::production_runtime_owner::resident_dataplane) no_alive: bool,
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
    pub(in crate::production_runtime_owner::resident_dataplane) fn as_str(&self) -> &'static str {
        match self {
            Self::Fixed { .. } => "fixed",
            Self::Random => "random",
            Self::MinLastLatency => "min",
            Self::MinAverage10 => "min_avg10",
            Self::MinMovingAverage => "min_moving_avg",
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn fixed_index(
        &self,
    ) -> Option<usize> {
        match self {
            Self::Fixed { index } => Some(*index),
            _ => None,
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn needs_latency_state(
        &self,
    ) -> bool {
        matches!(
            self,
            Self::MinLastLatency | Self::MinAverage10 | Self::MinMovingAverage
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn needs_alive_state(
        &self,
    ) -> bool {
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
    pub(in crate::production_runtime_owner::resident_dataplane) group_name: String,
    pub(in crate::production_runtime_owner::resident_dataplane) group_policy:
        ResidentGroupPolicyPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) matched_candidate_count: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) candidates:
        Vec<ResidentProxyCandidatePlan>,
    pub(in crate::production_runtime_owner::resident_dataplane) selector: Arc<Mutex<DialerGroup>>,
    pub(in crate::production_runtime_owner::resident_dataplane) check_interval: Duration,
    pub(in crate::production_runtime_owner::resident_dataplane) tcp_check: ResidentTcpCheckPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) udp_check: ResidentUdpCheckPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) tcp_probe_timeout: Duration,
    pub(in crate::production_runtime_owner::resident_dataplane) resuscitation_last_unix_ms:
        Arc<Vec<AtomicI64>>,
    pub(in crate::production_runtime_owner::resident_dataplane) health_bootstrap:
        ResidentGroupHealthBootstrap,
}

impl ResidentProxyGroupPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) fn apply_runtime_generation(
        &mut self,
        runtime_generation: u64,
    ) {
        for candidate in &mut self.candidates {
            Arc::make_mut(&mut candidate.proxy).apply_runtime_generation(runtime_generation);
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn group_policy_name(
        &self,
    ) -> &'static str {
        self.group_policy.as_str()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn candidate_count(&self) -> usize {
        self.matched_candidate_count
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn admitted_candidate_count(
        &self,
    ) -> usize {
        self.candidates.len()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn annotation_latency_offset_count(
        &self,
    ) -> usize {
        self.candidates
            .iter()
            .filter(|candidate| candidate.annotation_add_latency_ms != 0)
            .count()
    }

    fn tcp_check_network_types(&self) -> Vec<NetworkType> {
        let mut network_types = Vec::new();
        for target in &self.tcp_check.targets {
            if let Some(network_type) = target.network_type_hint() {
                push_unique_network_type(&mut network_types, network_type);
            }
        }
        if network_types.is_empty() {
            network_types.extend([NetworkType::TCP4, NetworkType::TCP6]);
        }
        network_types
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn latency_state_wired(
        &self,
    ) -> bool {
        if !self.group_policy.needs_latency_state() {
            return true;
        }
        let network_types = self.tcp_check_network_types();
        self.selector
            .lock()
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

    pub(in crate::production_runtime_owner::resident_dataplane) fn alive_state_wired(
        &self,
    ) -> bool {
        if !self.group_policy.needs_alive_state() {
            return true;
        }
        self.selector
            .lock()
            .map(|selector| selector.has_alive_state())
            .unwrap_or(false)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn default_proxy_snapshot(
        &self,
    ) -> Option<ResidentProxyPlan> {
        self.snapshot_candidate()
            .map(|candidate| candidate.proxy.as_ref().clone())
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn needs_background_checks(
        &self,
    ) -> bool {
        self.group_policy.needs_alive_state()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn begin_health_bootstrap(&self) {
        self.health_bootstrap.begin();
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn complete_health_bootstrap(
        &self,
        cancelled: bool,
    ) {
        self.health_bootstrap.complete(cancelled);
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn health_bootstrap_snapshot_json(
        &self,
    ) -> Value {
        self.health_bootstrap.snapshot_json()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn check_interval(
        &self,
    ) -> Duration {
        self.check_interval
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn try_begin_resuscitation(
        &self,
        network_type: NetworkType,
    ) -> bool {
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

    pub(in crate::production_runtime_owner::resident_dataplane) fn probe_candidates(
        &self,
    ) -> Vec<ResidentProxyProbePlan> {
        self.candidates
            .iter()
            .map(|candidate| ResidentProxyProbePlan {
                node_tag: candidate.proxy.node_tag.clone(),
                link: candidate.link.clone(),
                link_hash: candidate.link_hash.clone(),
                execution_identity: candidate.execution_identity.clone(),
                redacted_link_source: candidate.redacted_link_source.clone(),
                tcp_check: self.tcp_check.clone(),
                udp_check: self.udp_check.clone(),
                tcp_probe_timeout: self.tcp_probe_timeout,
                proxy: Arc::new(candidate.proxy.latency_probe_proxy()),
            })
            .collect()
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn latency_snapshots(
        &self,
    ) -> Vec<ResidentProxyLatencySnapshot> {
        let Ok(selector) = self.selector.lock() else {
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
                    node_tag: candidate.proxy.node_tag.clone(),
                    graph_id: candidate.proxy.graph_id.clone(),
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

    pub(in crate::production_runtime_owner::resident_dataplane) fn health_state_snapshots(
        &self,
    ) -> Vec<ResidentProxyLatencySnapshot> {
        let Ok(selector) = self.selector.lock() else {
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
                            node_tag: candidate.proxy.node_tag.clone(),
                            graph_id: candidate.proxy.graph_id.clone(),
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

    pub(in crate::production_runtime_owner::resident_dataplane) fn health_target_identity(
        &self,
        network_type: NetworkType,
    ) -> Option<String> {
        if network_type == NetworkType::TCP4 || network_type == NetworkType::TCP6 {
            return Some(self.tcp_check.identity(self.tcp_probe_timeout));
        }
        if network_type == NetworkType::DNS_TCP4
            || network_type == NetworkType::DNS_TCP6
            || network_type == NetworkType::DNS_UDP4
            || network_type == NetworkType::DNS_UDP6
        {
            return Some(self.udp_check.identity());
        }
        None
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn select_proxy_for_tcp(
        &self,
    ) -> Result<Arc<ResidentProxyPlan>, String> {
        self.select_proxy_for_tcp_network(NetworkType::TCP4)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn select_proxy_for_tcp_network(
        &self,
        network_type: NetworkType,
    ) -> Result<Arc<ResidentProxyPlan>, String> {
        self.select_candidate(network_type, false)
            .map(|candidate| Arc::clone(&candidate.proxy))
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn select_proxy_for_tcp_runtime(
        &self,
        network_type: NetworkType,
        strict_ip_version: bool,
    ) -> Result<Arc<ResidentProxyPlan>, String> {
        self.select_proxy_for_tcp_runtime_detail(network_type, strict_ip_version)
            .map_err(|err| err.message)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn select_proxy_for_tcp_runtime_detail(
        &self,
        network_type: NetworkType,
        strict_ip_version: bool,
    ) -> Result<Arc<ResidentProxyPlan>, ResidentProxySelectionError> {
        self.select_candidate_with_selection_detail(network_type, strict_ip_version)
            .map(|candidate| Arc::clone(&candidate.candidate.proxy))
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn select_proxy_for_udp(
        &self,
    ) -> Result<Arc<ResidentProxyPlan>, String> {
        self.select_proxy_for_udp_network(NetworkType::DNS_UDP4)
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn select_proxy_for_udp_network(
        &self,
        network_type: NetworkType,
    ) -> Result<Arc<ResidentProxyPlan>, String> {
        self.select_candidate(network_type, false)
            .map(|candidate| Arc::clone(&candidate.proxy))
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn select_proxy_for_udp_runtime(
        &self,
        network_type: NetworkType,
        strict_ip_version: bool,
    ) -> Result<Arc<ResidentProxyPlan>, String> {
        self.select_proxy_for_udp_runtime_candidate(network_type, strict_ip_version)
            .map(|selection| selection.proxy)
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn select_proxy_for_udp_runtime_candidate(
        &self,
        network_type: NetworkType,
        strict_ip_version: bool,
    ) -> Result<ResidentProxySelection, String> {
        self.select_proxy_for_udp_runtime_candidate_detail(network_type, strict_ip_version)
            .map_err(|err| err.message)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn select_proxy_for_udp_runtime_candidate_detail(
        &self,
        network_type: NetworkType,
        strict_ip_version: bool,
    ) -> Result<ResidentProxySelection, ResidentProxySelectionError> {
        let selected =
            self.select_candidate_with_selection_detail(network_type, strict_ip_version)?;
        Ok(ResidentProxySelection {
            proxy: Arc::clone(&selected.candidate.proxy),
            network_type: selected.network_type,
            latency_ms: selected.latency_ms,
        })
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn record_data_udp_available_traffic(
        &self,
        node_tag: &str,
        network_type: NetworkType,
        checked_at_unix: i64,
    ) -> Result<(), String> {
        if !self.group_policy.needs_alive_state() {
            return Ok(());
        }
        let Some(index) = self
            .candidates
            .iter()
            .position(|candidate| candidate.proxy.node_tag == node_tag)
        else {
            return Err(format!(
                "resident dataplane group {} has no admitted candidate named {node_tag}",
                self.group_name
            ));
        };
        self.selector
            .lock()
            .map_err(|_| {
                format!(
                    "resident dataplane group {} selector lock is poisoned",
                    self.group_name
                )
            })?
            .record_available_traffic(index, network_type, checked_at_unix);
        self.health_bootstrap.observe(index, HealthState::Alive);
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn select_proxy_for_dns_upstream(
        &self,
        network_type: NetworkType,
    ) -> Result<Arc<ResidentProxyPlan>, String> {
        self.select_proxy_for_dns_upstream_candidate(network_type)
            .map(|selection| selection.proxy)
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn select_proxy_for_dns_upstream_candidate(
        &self,
        network_type: NetworkType,
    ) -> Result<ResidentProxySelection, String> {
        self.select_proxy_for_dns_upstream_candidate_detail(network_type)
            .map_err(|err| err.message)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn select_proxy_for_dns_upstream_candidate_detail(
        &self,
        network_type: NetworkType,
    ) -> Result<ResidentProxySelection, ResidentProxySelectionError> {
        let selected = self.select_candidate_with_selection_detail(network_type, false)?;
        Ok(ResidentProxySelection {
            proxy: Arc::clone(&selected.candidate.proxy),
            network_type: selected.network_type,
            latency_ms: selected.latency_ms,
        })
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn snapshot_candidate(
        &self,
    ) -> Option<&ResidentProxyCandidatePlan> {
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

    pub(in crate::production_runtime_owner::resident_dataplane) fn select_candidate(
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
        let network = network_type.string_without_dns();
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
                    .lock()
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
    pub(in crate::production_runtime_owner::resident_dataplane) fn record_check_result(
        &self,
        node_tag: &str,
        network_type: NetworkType,
        latency_ms: Option<i64>,
        checked_at_unix: i64,
    ) -> Result<(), String> {
        let Some(index) = self
            .candidates
            .iter()
            .position(|candidate| candidate.proxy.node_tag == node_tag)
        else {
            return Err(format!(
                "resident dataplane group {} has no admitted candidate named {node_tag}",
                self.group_name
            ));
        };
        self.selector
            .lock()
            .map_err(|_| {
                format!(
                    "resident dataplane group {} selector lock is poisoned",
                    self.group_name
                )
            })?
            .record_check_result(index, network_type, latency_ms, checked_at_unix);
        Ok(())
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn record_health_state(
        &self,
        node_tag: &str,
        network_type: NetworkType,
        health_state: HealthState,
        latency_ms: Option<i64>,
        checked_at_unix: i64,
    ) -> Result<(), String> {
        let Some(index) = self
            .candidates
            .iter()
            .position(|candidate| candidate.proxy.node_tag == node_tag)
        else {
            return Err(format!(
                "resident dataplane group {} has no admitted candidate named {node_tag}",
                self.group_name
            ));
        };
        let mut selector = self.selector.lock().map_err(|_| {
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

    pub(in crate::production_runtime_owner::resident_dataplane) fn record_manual_latency_result_for_link(
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

    pub(in crate::production_runtime_owner::resident_dataplane) fn record_manual_health_state_for_link(
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
        let mut selector = self.selector.lock().map_err(|_| {
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

    pub(in crate::production_runtime_owner::resident_dataplane) fn apply_health_seed_snapshot(
        &self,
        snapshot: &Value,
    ) -> Result<usize, String> {
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
        let mut selector = self.selector.lock().map_err(|_| {
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
    pub(in crate::production_runtime_owner::resident_dataplane) fn fixed_single_for_test(
        proxy: ResidentProxyPlan,
    ) -> Self {
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
        Self {
            group_name: proxy.group_name.clone(),
            group_policy: ResidentGroupPolicyPlan::Fixed { index: 0 },
            matched_candidate_count: 1,
            candidates: vec![ResidentProxyCandidatePlan {
                match_index: 0,
                annotation_add_latency_ms: 0,
                link: proxy.node_tag.clone(),
                link_hash: link_hash(&proxy.node_tag),
                execution_identity: execution_link_hash(&proxy.node_tag),
                redacted_link_source: redacted_link_source(&proxy.node_tag),
                proxy: Arc::new(proxy),
            }],
            selector: Arc::new(Mutex::new(DialerGroup::new(
                "test",
                vec![Dialer::new("test", "")],
                vec![Annotation::default()],
                SelectionPolicy::Fixed { index: 0 },
                true,
                0,
            ))),
            check_interval: Duration::from_secs(30),
            tcp_check: ResidentTcpCheckPlan {
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
            udp_check: ResidentUdpCheckPlan {
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
            tcp_probe_timeout: RESIDENT_TCP_LATENCY_PROBE_TIMEOUT,
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

pub(in crate::production_runtime_owner::resident_dataplane) fn apply_health_seed_snapshots(
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
