use super::*;
use tokio::sync::OnceCell;
#[derive(Clone, Debug)]
pub(crate) struct ResidentProxyCandidatePlan {
    pub(in crate::production_runtime_owner::resident_dataplane) match_index: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) annotation_add_latency_ms: i64,
    pub(in crate::production_runtime_owner::resident_dataplane) link: String,
    pub(in crate::production_runtime_owner::resident_dataplane) link_hash: String,
    pub(in crate::production_runtime_owner::resident_dataplane) redacted_link_source: String,
    pub(in crate::production_runtime_owner::resident_dataplane) proxy: Arc<ResidentProxyPlan>,
}

#[derive(Clone, Debug)]
pub(crate) struct ResidentProxyProbePlan {
    pub(in crate::production_runtime_owner::resident_dataplane) node_tag: String,
    pub(in crate::production_runtime_owner::resident_dataplane) link: String,
    pub(in crate::production_runtime_owner::resident_dataplane) link_hash: String,
    pub(in crate::production_runtime_owner::resident_dataplane) redacted_link_source: String,
    pub(in crate::production_runtime_owner::resident_dataplane) tcp_check: ResidentTcpCheckPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) udp_check: ResidentUdpCheckPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) proxy: Arc<ResidentProxyPlan>,
}

impl ResidentProxyProbePlan {
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
}

impl ResidentTcpCheckPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) fn primary_target(
        &self,
    ) -> &ResidentTcpCheckTarget {
        self.targets
            .first()
            .expect("resident TCP check plan always has at least one target")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentTcpCheckTarget {
    pub(in crate::production_runtime_owner::resident_dataplane) target: String,
    pub(in crate::production_runtime_owner::resident_dataplane) network_type: Option<NetworkType>,
}

impl ResidentTcpCheckTarget {
    pub(in crate::production_runtime_owner::resident_dataplane) fn network_type_for_record(
        &self,
    ) -> NetworkType {
        self.network_type.unwrap_or(NetworkType::TCP4)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentUdpCheckPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) target: ResidentUdpCheckTarget,
    pub(in crate::production_runtime_owner::resident_dataplane) targets:
        Vec<ResidentUdpCheckTarget>,
    pub(in crate::production_runtime_owner::resident_dataplane) host: String,
    pub(in crate::production_runtime_owner::resident_dataplane) lookup_host: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ResidentUdpCheckTarget {
    authority: String,
    host: String,
    port: u16,
    literal_addr: Option<SocketAddr>,
    fallback_resolver: SocketAddr,
    resolver_mark: u32,
    resolved_addr: Arc<OnceCell<SocketAddr>>,
}

impl ResidentUdpCheckTarget {
    pub(in crate::production_runtime_owner::resident_dataplane) fn new(
        authority: String,
        host: String,
        port: u16,
        fallback_resolver: SocketAddr,
        resolver_mark: u32,
        literal_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            authority,
            host,
            port,
            literal_addr,
            fallback_resolver,
            resolver_mark,
            resolved_addr: Arc::new(OnceCell::new()),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn literal(
        addr: SocketAddr,
    ) -> Self {
        Self::new(
            addr.to_string(),
            addr.ip().to_string(),
            addr.port(),
            addr,
            0,
            Some(addr),
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn authority(&self) -> &str {
        &self.authority
    }

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

    pub(in crate::production_runtime_owner::resident_dataplane) async fn resolve(
        &self,
    ) -> Result<SocketAddr, String> {
        if let Some(addr) = self.literal_addr {
            return Ok(addr);
        }
        self.resolved_addr
            .get_or_try_init(|| async {
                resolve_host_with_configured_fallback_dns(
                    &self.host,
                    self.port,
                    self.fallback_resolver,
                    self.resolver_mark,
                    "resolve UDP health check",
                )
                .await
            })
            .await
            .copied()
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

fn push_unique_network_type(network_types: &mut Vec<NetworkType>, network_type: NetworkType) {
    if !network_types.contains(&network_type) {
        network_types.push(network_type);
    }
}

fn latency_snapshot_tcp_network_types() -> [NetworkType; 2] {
    [NetworkType::TCP4, NetworkType::TCP6]
}

fn latency_seed_snapshot_network_type(snapshot: &Value) -> Option<NetworkType> {
    let raw = snapshot.get("networkType").and_then(Value::as_str)?;
    latency_snapshot_tcp_network_types()
        .into_iter()
        .find(|network_type| network_type.string_without_dns() == raw)
}

fn latency_seed_network_types_for_snapshot_network(network_type: NetworkType) -> Vec<NetworkType> {
    vec![
        NetworkType::TCP4.with_ipversion(network_type.ipversion),
        NetworkType::DNS_UDP4.with_ipversion(network_type.ipversion),
    ]
}

fn legacy_latency_seed_network_types() -> Vec<NetworkType> {
    latency_seed_network_types_for_snapshot_network(NetworkType::TCP4)
}

impl PartialEq for ResidentUdpCheckTarget {
    fn eq(&self, other: &Self) -> bool {
        self.authority == other.authority
            && self.host == other.host
            && self.port == other.port
            && self.literal_addr == other.literal_addr
            && self.fallback_resolver == other.fallback_resolver
            && self.resolver_mark == other.resolver_mark
    }
}

impl Eq for ResidentUdpCheckTarget {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentProxyLatencySnapshot {
    pub(in crate::production_runtime_owner::resident_dataplane) node_tag: String,
    pub(in crate::production_runtime_owner::resident_dataplane) graph_id: String,
    pub(in crate::production_runtime_owner::resident_dataplane) link_hash: String,
    pub(in crate::production_runtime_owner::resident_dataplane) redacted_link_source: String,
    pub(in crate::production_runtime_owner::resident_dataplane) network_type: NetworkType,
    pub(in crate::production_runtime_owner::resident_dataplane) latency_ms: Option<i64>,
    pub(in crate::production_runtime_owner::resident_dataplane) alive: bool,
    pub(in crate::production_runtime_owner::resident_dataplane) checked_at_unix: i64,
    pub(in crate::production_runtime_owner::resident_dataplane) message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResidentDialerLatencySnapshotState {
    network_type: NetworkType,
    latency_ms: i64,
    alive: bool,
    checked_at_unix: i64,
    ok: bool,
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
        Self {
            network_type,
            latency_ms,
            alive,
            checked_at_unix,
            ok,
        }
    }
}

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
}

impl ResidentProxyGroupPlan {
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
            push_unique_network_type(&mut network_types, target.network_type_for_record());
        }
        network_types
    }

    fn udp_check_network_types(&self) -> Vec<NetworkType> {
        let mut network_types = Vec::new();
        for target in &self.udp_check.targets {
            push_unique_network_type(
                &mut network_types,
                target.network_type_hint().unwrap_or(NetworkType::DNS_UDP4),
            );
        }
        network_types
    }

    fn tcp_selection_network_types(&self) -> Vec<NetworkType> {
        let mut network_types = self.tcp_check_network_types();
        if network_types.is_empty() {
            network_types.push(NetworkType::TCP4);
        }
        network_types
    }

    fn udp_selection_network_types(&self) -> Vec<NetworkType> {
        let mut network_types = self.udp_check_network_types();
        if network_types.is_empty() {
            network_types.push(NetworkType::DNS_UDP4);
        }
        network_types
    }

    fn latency_seed_network_types(&self, snapshot: &Value) -> Vec<NetworkType> {
        let mut configured = self.tcp_check_network_types();
        for network_type in self.udp_check_network_types() {
            push_unique_network_type(&mut configured, network_type);
        }
        let requested = latency_seed_snapshot_network_type(snapshot)
            .map(latency_seed_network_types_for_snapshot_network)
            .unwrap_or_else(legacy_latency_seed_network_types);
        requested
            .into_iter()
            .filter(|network_type| configured.contains(network_type))
            .collect()
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

    pub(in crate::production_runtime_owner::resident_dataplane) fn check_interval(
        &self,
    ) -> Duration {
        self.check_interval
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
                redacted_link_source: candidate.redacted_link_source.clone(),
                tcp_check: self.tcp_check.clone(),
                udp_check: self.udp_check.clone(),
                proxy: Arc::new(candidate.proxy.latency_probe_proxy()),
            })
            .collect()
    }

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
                    });
                ResidentProxyLatencySnapshot {
                    node_tag: candidate.proxy.node_tag.clone(),
                    graph_id: candidate.proxy.graph_id.clone(),
                    link_hash: candidate.link_hash.clone(),
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
                }
            })
            .collect()
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
        self.select_candidate(network_type)
            .map(|candidate| Arc::clone(&candidate.proxy))
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn select_proxy_for_tcp_runtime(
        &self,
    ) -> Result<Arc<ResidentProxyPlan>, String> {
        self.select_candidate_for_runtime_networks(&self.tcp_selection_network_types())
            .map(|candidate| Arc::clone(&candidate.proxy))
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
        self.select_candidate(network_type)
            .map(|candidate| Arc::clone(&candidate.proxy))
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn select_proxy_for_udp_runtime(
        &self,
    ) -> Result<Arc<ResidentProxyPlan>, String> {
        self.select_candidate_for_runtime_networks(&self.udp_selection_network_types())
            .map(|candidate| Arc::clone(&candidate.proxy))
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
    ) -> Result<&ResidentProxyCandidatePlan, String> {
        let network = network_type.string_without_dns();
        if self.candidates.is_empty() {
            return Err(format!(
                "resident dataplane group {} has no admitted candidate for {network}",
                self.group_name
            ));
        }
        match self.group_policy {
            ResidentGroupPolicyPlan::Fixed { index } => self
                .candidates
                .iter()
                .find(|candidate| candidate.match_index == index)
                .ok_or_else(|| {
                    format!(
                        "resident dataplane group {} fixed policy index {} is not admitted for {network}",
                        self.group_name, index
                    )
                }),
            ResidentGroupPolicyPlan::MinLastLatency
            | ResidentGroupPolicyPlan::MinAverage10
            | ResidentGroupPolicyPlan::MinMovingAverage
            | ResidentGroupPolicyPlan::Random => {
                let selected = self
                    .selector
                    .lock()
                    .map_err(|_| {
                        format!(
                            "resident dataplane group {} selector lock is poisoned",
                            self.group_name
                        )
                    })?
                    .select(network_type, false)
                    .map_err(|err| {
                        format!(
                            "resident dataplane group {} selector failed for {network}: {err}",
                            self.group_name
                        )
                    })?;
                self.candidates.get(selected.index).ok_or_else(|| {
                    format!(
                        "resident dataplane group {} selector returned missing candidate {} for {network}",
                        self.group_name, selected.index
                    )
                })
            }
        }
    }

    fn select_candidate_for_runtime_networks(
        &self,
        network_types: &[NetworkType],
    ) -> Result<&ResidentProxyCandidatePlan, String> {
        if self.candidates.is_empty() {
            return Err(format!(
                "resident dataplane group {} has no admitted candidate",
                self.group_name
            ));
        }
        if let ResidentGroupPolicyPlan::Fixed { index } = self.group_policy {
            return self
                .candidates
                .iter()
                .find(|candidate| candidate.match_index == index)
                .ok_or_else(|| {
                    format!(
                        "resident dataplane group {} fixed policy index {} is not admitted",
                        self.group_name, index
                    )
                });
        }
        let selector = self.selector.lock().map_err(|_| {
            format!(
                "resident dataplane group {} selector lock is poisoned",
                self.group_name
            )
        })?;
        let selected_index = match self.group_policy {
            ResidentGroupPolicyPlan::Fixed { .. } => unreachable!("fixed policy handled above"),
            ResidentGroupPolicyPlan::Random => {
                let mut alive_indexes = Vec::new();
                for network_type in network_types {
                    if let Some(alive_set) = selector.alive_set(*network_type) {
                        for index in alive_set.alive_indexes() {
                            if !alive_indexes.contains(&index) {
                                alive_indexes.push(index);
                            }
                        }
                    }
                }
                if alive_indexes.is_empty() {
                    if self.candidates.len() == 1 {
                        0
                    } else {
                        return Err(format!(
                            "resident dataplane group {} selector failed: no alive dialer",
                            self.group_name
                        ));
                    }
                } else {
                    alive_indexes[fastrand::usize(..alive_indexes.len())]
                }
            }
            ResidentGroupPolicyPlan::MinLastLatency
            | ResidentGroupPolicyPlan::MinAverage10
            | ResidentGroupPolicyPlan::MinMovingAverage => {
                let mut best = None::<(usize, i64)>;
                for network_type in network_types {
                    let Some((index, latency_ms)) = selector
                        .alive_set(*network_type)
                        .and_then(|alive_set| alive_set.get_min_latency())
                    else {
                        continue;
                    };
                    if best
                        .map(|(best_index, best_latency_ms)| {
                            latency_ms < best_latency_ms
                                || (latency_ms == best_latency_ms && index < best_index)
                        })
                        .unwrap_or(true)
                    {
                        best = Some((index, latency_ms));
                    }
                }
                if let Some((index, _)) = best {
                    index
                } else if self.candidates.len() == 1 {
                    0
                } else {
                    return Err(format!(
                        "resident dataplane group {} selector failed: no alive dialer",
                        self.group_name
                    ));
                }
            }
        };
        self.candidates.get(selected_index).ok_or_else(|| {
            format!(
                "resident dataplane group {} selector returned missing candidate {}",
                self.group_name, selected_index
            )
        })
    }

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

    pub(in crate::production_runtime_owner::resident_dataplane) fn record_manual_latency_result_for_link(
        &self,
        link: &str,
        network_type: NetworkType,
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
            if let Some(latency_ms) = latency_ms {
                selector.record_check_result(
                    *index,
                    network_type,
                    Some(latency_ms),
                    checked_at_unix,
                );
            } else {
                selector.record_check_failure_without_latency(
                    *index,
                    network_type,
                    checked_at_unix,
                );
            }
        }
        Ok(indexes.len())
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn apply_successful_latency_seed_snapshot(
        &self,
        snapshot: &Value,
    ) -> Result<usize, String> {
        if !self.group_policy.needs_alive_state() {
            return Ok(0);
        }
        let Some(link_hash) = latency_seed_snapshot_link_hash(snapshot) else {
            return Ok(0);
        };
        let Some(latency_ms) = latency_seed_snapshot_success_latency_ms(snapshot) else {
            return Ok(0);
        };
        let indexes = self
            .candidates
            .iter()
            .enumerate()
            .filter_map(|(index, candidate)| (candidate.link_hash == link_hash).then_some(index))
            .collect::<Vec<_>>();
        if indexes.is_empty() {
            return Ok(0);
        }
        let network_types = self.latency_seed_network_types(snapshot);
        if network_types.is_empty() {
            return Ok(0);
        }
        let checked_at_unix = snapshot
            .get("checkedAtUnix")
            .and_then(Value::as_i64)
            .filter(|value| *value > 0)
            .unwrap_or(0);
        let mut selector = self.selector.lock().map_err(|_| {
            format!(
                "resident dataplane group {} selector lock is poisoned",
                self.group_name
            )
        })?;
        for index in &indexes {
            for network_type in &network_types {
                selector.record_check_result(
                    *index,
                    *network_type,
                    Some(latency_ms),
                    checked_at_unix,
                );
            }
        }
        Ok(indexes.len())
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn fixed_single_for_test(
        proxy: ResidentProxyPlan,
    ) -> Self {
        let udp_check_addr = SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            dae_dns::ACTIVE_DNS_DEFAULT_TARGET_PORT,
        );
        let tcp_check_target = ResidentTcpCheckTarget {
            target: "cp.cloudflare.com:80".to_owned(),
            network_type: None,
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
                host: "cp.cloudflare.com".to_owned(),
                path: "/".to_owned(),
                method: "HEAD".to_owned(),
            },
            udp_check: ResidentUdpCheckPlan {
                target: udp_check_target.clone(),
                targets: vec![udp_check_target],
                host: "localhost".to_owned(),
                lookup_host: "connectivitycheck.gstatic.com.".to_owned(),
            },
        }
    }
}

pub(crate) fn resident_latency_message(ok: bool, alive: bool, latency_ms: i64) -> String {
    if !ok {
        "no latency result".to_owned()
    } else if alive {
        format!("{latency_ms}ms")
    } else {
        "unavailable".to_owned()
    }
}

pub(in crate::production_runtime_owner::resident_dataplane) fn apply_successful_latency_seed_snapshots(
    groups: &BTreeMap<u8, ResidentProxyGroupPlan>,
    snapshots: &[Value],
) {
    if groups.is_empty() || snapshots.is_empty() {
        return;
    }
    for snapshot in snapshots {
        for group in groups.values() {
            let _ = group.apply_successful_latency_seed_snapshot(snapshot);
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

fn latency_seed_snapshot_success_latency_ms(snapshot: &Value) -> Option<i64> {
    let latency_ms = snapshot.get("latencyMs").and_then(Value::as_i64)?;
    let alive = snapshot
        .get("alive")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    alive.then_some(latency_ms)
}
