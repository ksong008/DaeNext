use super::*;
use tokio::sync::OnceCell;
#[derive(Clone, Debug)]
pub(crate) struct ResidentProxyCandidatePlan {
    pub(in crate::production_runtime_owner::resident_dataplane) match_index: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) annotation_add_latency_ms: i64,
    pub(in crate::production_runtime_owner::resident_dataplane) link: String,
    pub(in crate::production_runtime_owner::resident_dataplane) link_hash: String,
    pub(in crate::production_runtime_owner::resident_dataplane) redacted_link_source: String,
    pub(in crate::production_runtime_owner::resident_dataplane) proxy: ResidentProxyPlan,
}

#[derive(Clone, Debug)]
pub(crate) struct ResidentProxyProbePlan {
    pub(in crate::production_runtime_owner::resident_dataplane) node_tag: String,
    pub(in crate::production_runtime_owner::resident_dataplane) link: String,
    pub(in crate::production_runtime_owner::resident_dataplane) link_hash: String,
    pub(in crate::production_runtime_owner::resident_dataplane) redacted_link_source: String,
    pub(in crate::production_runtime_owner::resident_dataplane) tcp_check: ResidentTcpCheckPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) udp_check: ResidentUdpCheckPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) proxy: ResidentProxyPlan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentTcpCheckPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) scheme: String,
    pub(in crate::production_runtime_owner::resident_dataplane) target: String,
    pub(in crate::production_runtime_owner::resident_dataplane) host: String,
    pub(in crate::production_runtime_owner::resident_dataplane) path: String,
    pub(in crate::production_runtime_owner::resident_dataplane) method: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentUdpCheckPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) target: ResidentUdpCheckTarget,
    pub(in crate::production_runtime_owner::resident_dataplane) host: String,
    pub(in crate::production_runtime_owner::resident_dataplane) lookup_host: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ResidentUdpCheckTarget {
    authority: String,
    literal_addr: Option<SocketAddr>,
    resolved_addr: Arc<OnceCell<SocketAddr>>,
}

impl ResidentUdpCheckTarget {
    pub(in crate::production_runtime_owner::resident_dataplane) fn new(
        authority: String,
        literal_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            authority,
            literal_addr,
            resolved_addr: Arc::new(OnceCell::new()),
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
                tokio::net::lookup_host(self.authority.as_str())
                    .await
                    .map_err(|err| format!("resolve UDP health check {}: {err}", self.authority))?
                    .next()
                    .ok_or_else(|| {
                        format!("resolve UDP health check {}: no IP address", self.authority)
                    })
            })
            .await
            .copied()
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
    pub(in crate::production_runtime_owner::resident_dataplane) redacted_link_source: String,
    pub(in crate::production_runtime_owner::resident_dataplane) latency_ms: Option<i64>,
    pub(in crate::production_runtime_owner::resident_dataplane) alive: bool,
    pub(in crate::production_runtime_owner::resident_dataplane) checked_at_unix: i64,
    pub(in crate::production_runtime_owner::resident_dataplane) message: String,
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

    pub(in crate::production_runtime_owner::resident_dataplane) fn latency_state_wired(
        &self,
    ) -> bool {
        if !self.group_policy.needs_latency_state() {
            return true;
        }
        self.selector
            .lock()
            .ok()
            .and_then(|selector| selector.alive_set(NetworkType::TCP4).cloned())
            .map(|alive_set| alive_set.latency_state_allocated)
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
            .map(|candidate| candidate.proxy.clone())
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
                proxy: candidate.proxy.clone(),
            })
            .collect()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn latency_snapshots(
        &self,
    ) -> Vec<ResidentProxyLatencySnapshot> {
        let Ok(selector) = self.selector.lock() else {
            return Vec::new();
        };
        self.candidates
            .iter()
            .enumerate()
            .map(|(index, candidate)| {
                let (latency_ms, alive, checked_at_unix, ok) = selector
                    .dialers
                    .get(index)
                    .map(|dialer| dialer.last_latency_snapshot(NetworkType::TCP4))
                    .unwrap_or((0, false, 0, false));
                ResidentProxyLatencySnapshot {
                    node_tag: candidate.proxy.node_tag.clone(),
                    graph_id: candidate.proxy.graph_id.clone(),
                    link_hash: candidate.link_hash.clone(),
                    redacted_link_source: candidate.redacted_link_source.clone(),
                    latency_ms: ok.then_some(latency_ms),
                    alive: ok && alive,
                    checked_at_unix,
                    message: resident_latency_message(ok, alive, latency_ms),
                }
            })
            .collect()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn select_proxy_for_tcp(
        &self,
    ) -> Result<ResidentProxyPlan, String> {
        self.select_proxy_for_network("tcp4")
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn select_proxy_for_udp(
        &self,
    ) -> Result<ResidentProxyPlan, String> {
        self.select_proxy_for_network("udp4")
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn select_proxy_for_network(
        &self,
        network: &str,
    ) -> Result<ResidentProxyPlan, String> {
        self.select_candidate(network)
            .map(|candidate| candidate.proxy.clone())
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
        network: &str,
    ) -> Result<&ResidentProxyCandidatePlan, String> {
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
                let network_type = resident_selector_network_type(network)?;
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

    pub(in crate::production_runtime_owner::resident_dataplane) fn record_check_result_for_link(
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
            selector.record_check_result(*index, network_type, latency_ms, checked_at_unix);
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
                proxy,
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
                target: "cp.cloudflare.com:80".to_owned(),
                host: "cp.cloudflare.com".to_owned(),
                path: "/".to_owned(),
                method: "HEAD".to_owned(),
            },
            udp_check: ResidentUdpCheckPlan {
                target: ResidentUdpCheckTarget::literal(udp_check_addr),
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
