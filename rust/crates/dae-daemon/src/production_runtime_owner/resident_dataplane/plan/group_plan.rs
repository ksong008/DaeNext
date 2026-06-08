#[derive(Clone, Debug)]
pub(super) struct ResidentProxyCandidatePlan {
    pub(super) match_index: usize,
    pub(super) annotation_add_latency_ms: i64,
    pub(super) link: String,
    pub(super) link_hash: String,
    pub(super) redacted_link_source: String,
    pub(super) proxy: ResidentProxyPlan,
}

#[derive(Clone, Debug)]
pub(super) struct ResidentProxyProbePlan {
    pub(super) node_tag: String,
    pub(super) link: String,
    pub(super) link_hash: String,
    pub(super) redacted_link_source: String,
    pub(super) tcp_check: ResidentTcpCheckPlan,
    pub(super) udp_check: ResidentUdpCheckPlan,
    pub(super) proxy: ResidentProxyPlan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentTcpCheckPlan {
    pub(super) scheme: String,
    pub(super) target: String,
    pub(super) host: String,
    pub(super) path: String,
    pub(super) method: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentUdpCheckPlan {
    pub(super) target: SocketAddrV4,
    pub(super) host: String,
    pub(super) lookup_host: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentProxyLatencySnapshot {
    pub(super) node_tag: String,
    pub(super) graph_id: String,
    pub(super) link_hash: String,
    pub(super) redacted_link_source: String,
    pub(super) latency_ms: Option<i64>,
    pub(super) alive: bool,
    pub(super) checked_at_unix: i64,
    pub(super) message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ResidentGroupPolicyPlan {
    Fixed { index: usize },
    Random,
    MinLastLatency,
    MinAverage10,
    MinMovingAverage,
}

impl ResidentGroupPolicyPlan {
    pub(super) fn as_str(&self) -> &'static str {
        match self {
            Self::Fixed { .. } => "fixed",
            Self::Random => "random",
            Self::MinLastLatency => "min",
            Self::MinAverage10 => "min_avg10",
            Self::MinMovingAverage => "min_moving_avg",
        }
    }

    pub(super) fn fixed_index(&self) -> Option<usize> {
        match self {
            Self::Fixed { index } => Some(*index),
            _ => None,
        }
    }

    pub(super) fn needs_latency_state(&self) -> bool {
        matches!(
            self,
            Self::MinLastLatency | Self::MinAverage10 | Self::MinMovingAverage
        )
    }

    pub(super) fn needs_alive_state(&self) -> bool {
        !matches!(self, Self::Fixed { .. })
    }
}

#[derive(Clone, Debug)]
pub(super) struct ResidentProxyGroupPlan {
    pub(super) group_name: String,
    pub(super) group_policy: ResidentGroupPolicyPlan,
    matched_candidate_count: usize,
    candidates: Vec<ResidentProxyCandidatePlan>,
    selector: Arc<Mutex<DialerGroup>>,
    check_interval: Duration,
    tcp_check: ResidentTcpCheckPlan,
    udp_check: ResidentUdpCheckPlan,
}

impl ResidentProxyGroupPlan {
    pub(super) fn group_policy_name(&self) -> &'static str {
        self.group_policy.as_str()
    }

    pub(super) fn candidate_count(&self) -> usize {
        self.matched_candidate_count
    }

    pub(super) fn admitted_candidate_count(&self) -> usize {
        self.candidates.len()
    }

    pub(super) fn annotation_latency_offset_count(&self) -> usize {
        self.candidates
            .iter()
            .filter(|candidate| candidate.annotation_add_latency_ms != 0)
            .count()
    }

    pub(super) fn latency_state_wired(&self) -> bool {
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

    pub(super) fn alive_state_wired(&self) -> bool {
        if !self.group_policy.needs_alive_state() {
            return true;
        }
        self.selector
            .lock()
            .map(|selector| selector.has_alive_state())
            .unwrap_or(false)
    }

    pub(super) fn default_proxy_snapshot(&self) -> Option<ResidentProxyPlan> {
        self.snapshot_candidate()
            .map(|candidate| candidate.proxy.clone())
    }

    pub(super) fn needs_background_checks(&self) -> bool {
        self.group_policy.needs_alive_state()
    }

    pub(super) fn check_interval(&self) -> Duration {
        self.check_interval
    }

    pub(super) fn probe_candidates(&self) -> Vec<ResidentProxyProbePlan> {
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

    pub(super) fn latency_snapshots(&self) -> Vec<ResidentProxyLatencySnapshot> {
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

    pub(super) fn select_proxy_for_tcp(&self) -> Result<ResidentProxyPlan, String> {
        self.select_proxy_for_network("tcp4")
    }

    pub(super) fn select_proxy_for_udp(&self) -> Result<ResidentProxyPlan, String> {
        self.select_proxy_for_network("udp4")
    }

    fn select_proxy_for_network(&self, network: &str) -> Result<ResidentProxyPlan, String> {
        self.select_candidate(network)
            .map(|candidate| candidate.proxy.clone())
    }

    fn snapshot_candidate(&self) -> Option<&ResidentProxyCandidatePlan> {
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

    fn select_candidate(&self, network: &str) -> Result<&ResidentProxyCandidatePlan, String> {
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

    pub(super) fn record_check_result(
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

    pub(super) fn record_check_result_for_link(
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
    pub(super) fn fixed_single_for_test(proxy: ResidentProxyPlan) -> Self {
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
                target: SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53),
                host: "dns.google".to_owned(),
                lookup_host: "connectivitycheck.gstatic.com.".to_owned(),
            },
        }
    }
}

fn resident_latency_message(ok: bool, alive: bool, latency_ms: i64) -> String {
    if !ok {
        "no latency result".to_owned()
    } else if alive {
        format!("{latency_ms}ms")
    } else {
        "unavailable".to_owned()
    }
}
