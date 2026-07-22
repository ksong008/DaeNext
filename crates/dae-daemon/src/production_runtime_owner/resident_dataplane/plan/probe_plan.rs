use std::ops::Deref;

use super::*;

#[derive(Clone, Debug)]
pub(crate) struct ResidentProbeProfile {
    pub(in crate::production_runtime_owner::resident_dataplane) tcp_check: ResidentTcpCheckPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) udp_check: ResidentUdpCheckPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) tcp_probe_timeout: Duration,
}

impl ResidentProbeProfile {
    pub(in crate::production_runtime_owner::resident_dataplane) fn new(
        tcp_check: ResidentTcpCheckPlan,
        udp_check: ResidentUdpCheckPlan,
        tcp_probe_timeout: Duration,
    ) -> Self {
        Self {
            tcp_check,
            udp_check,
            tcp_probe_timeout,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ResidentProxyProbePlan {
    pub(in crate::production_runtime_owner::resident_dataplane) node_tag: Arc<String>,
    pub(in crate::production_runtime_owner::resident_dataplane) link_hash: Arc<String>,
    pub(in crate::production_runtime_owner::resident_dataplane) execution_identity: Arc<String>,
    pub(in crate::production_runtime_owner::resident_dataplane) redacted_link_source: Arc<String>,
    profile: Arc<ResidentProbeProfile>,
    pub(in crate::production_runtime_owner::resident_dataplane) binding: ResidentProxyBinding,
}

impl ResidentProxyProbePlan {
    pub(in crate::production_runtime_owner::resident_dataplane) fn new(
        node_tag: String,
        link_hash: String,
        execution_identity: String,
        redacted_link_source: String,
        profile: Arc<ResidentProbeProfile>,
        binding: ResidentProxyBinding,
    ) -> Self {
        Self {
            node_tag: Arc::new(node_tag),
            link_hash: Arc::new(link_hash),
            execution_identity: Arc::new(execution_identity),
            redacted_link_source: Arc::new(redacted_link_source),
            profile,
            binding,
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn apply_runtime_generation(
        &mut self,
        runtime_generation: u64,
    ) -> Result<(), String> {
        self.binding
            .bind_resident_generation(dae_runtime_control::OwnerGeneration::new(
                runtime_generation,
            ))
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn apply_latency_probe_control_mark(
        &mut self,
        mark: u32,
    ) {
        self.binding.apply_control_socket_mark(mark);
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn shares_profile_with(
        &self,
        other: &Self,
    ) -> bool {
        Arc::ptr_eq(&self.profile, &other.profile)
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn profile_mut_for_test(
        &mut self,
    ) -> &mut ResidentProbeProfile {
        Arc::make_mut(&mut self.profile)
    }
}

impl Deref for ResidentProxyProbePlan {
    type Target = ResidentProbeProfile;

    fn deref(&self) -> &Self::Target {
        &self.profile
    }
}

pub(super) fn share_group_probe_plans(
    candidates: &[ResidentProxyCandidatePlan],
    profile: Arc<ResidentProbeProfile>,
) -> Arc<[ResidentProxyProbePlan]> {
    candidates
        .iter()
        .map(|candidate| {
            ResidentProxyProbePlan::new(
                candidate.binding.plan().node_tag.clone(),
                candidate.link_hash.clone(),
                candidate.execution_identity.clone(),
                candidate.redacted_link_source.clone(),
                Arc::clone(&profile),
                candidate.binding.clone().without_persistent_xhttp_reuse(),
            )
        })
        .collect()
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
    pub(super) fn identity(&self, probe_timeout: Duration) -> String {
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
    pub(super) fn identity(&self) -> String {
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

impl PartialEq for ResidentUdpCheckTarget {
    fn eq(&self, other: &Self) -> bool {
        self.authority == other.authority && self.literal_addr == other.literal_addr
    }
}

impl Eq for ResidentUdpCheckTarget {}

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
