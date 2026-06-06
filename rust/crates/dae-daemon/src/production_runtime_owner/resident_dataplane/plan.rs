use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dae_config::{Config, DynamicFunctionValue, Function, Group, Param};
use dae_core_types::OutboundIndex;
use dae_datapath::TcpDialMode;
use dae_outbound::{
    Annotation, AnyTLSLink, Dialer, DialerGroup, DialerSet, Filter, FilterParam, NetworkType,
    SelectionPolicy,
    http_proxy::{HttpProxyLink, HttpScheme},
    hysteria2::{Hysteria2Link, server_contract as hysteria2_server_contract},
    juicity::JuicityLink,
    shadowsocks::{ShadowsocksLink, cipher_spec},
    shared_transport::{UtlsFingerprint, resolve_utls_client_hello_id},
    trojan::{TrojanLink, TrojanTransportType},
    tuic::TuicLink,
    vless::{VLESSLink, password_to_key},
    vmess::VMessLink,
};
use url::Url;

use super::{
    XTLS_RPRX_VISION,
    dns::{ResidentDnsPlan, build_resident_dns_plan},
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct SelectedGroupNode {
    match_index: usize,
    tag: String,
    link: String,
    annotation_add_latency_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentNodeLinkShape {
    pub(super) tag: String,
    pub(super) scheme: String,
    pub(super) link: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentUtlsFingerprintPlan {
    pub(super) source: &'static str,
    pub(super) requested: String,
    pub(super) name: String,
    pub(super) canonical: String,
    pub(super) family: String,
    pub(super) client: String,
    pub(super) randomized: bool,
    pub(super) alpn_policy: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum GroupNodeSelection {
    Selected(Vec<SelectedGroupNode>),
    NoCandidate {
        explicit_name_filter: bool,
        unresolved_names: Vec<String>,
    },
}

#[derive(Clone, Debug)]
pub(super) enum ResidentProxyProtocolPlan {
    VlessVisionTcpTls {
        key: [u8; 16],
    },
    Socks5Tcp {
        username: String,
        password: String,
    },
    HttpProxyTcp {
        username: String,
        password: String,
    },
    ShadowsocksAeadTcp {
        cipher: String,
        password: String,
        salt_len: usize,
    },
    TrojanTcpTls {
        password: String,
    },
    AnyTlsTcpTls {
        auth: String,
    },
    VmessAeadTcp {
        id: String,
    },
    Hysteria2QuicTcp {
        auth: String,
        pin_sha256: String,
        max_rx: u64,
    },
    TuicQuicTcp {
        uuid: String,
        password: String,
        alpn: Vec<String>,
    },
    JuicityQuicTcp {
        uuid: String,
        password: String,
        allow_insecure: bool,
        pinned_certchain_sha256: String,
    },
}

#[derive(Clone, Debug)]
pub(super) struct ResidentProxyPlan {
    pub(super) protocol: String,
    pub(super) group_name: String,
    pub(super) group_policy: String,
    pub(super) node_tag: String,
    pub(super) server_host: String,
    pub(super) server_port: u16,
    pub(super) server_name: String,
    pub(super) alpn: Vec<String>,
    pub(super) flow: String,
    pub(super) net: String,
    pub(super) tls: String,
    pub(super) allow_insecure: bool,
    pub(super) utls_fingerprint: Option<ResidentUtlsFingerprintPlan>,
    pub(super) handler: ResidentProxyProtocolPlan,
    pub(super) mark: u32,
    pub(super) mptcp: bool,
}

impl ResidentProxyPlan {
    pub(super) fn vless_key(&self) -> Result<[u8; 16], String> {
        match self.handler {
            ResidentProxyProtocolPlan::VlessVisionTcpTls { key } => Ok(key),
            _ => Err(format!(
                "resident proxy {} node {} is not a VLESS handler",
                self.protocol, self.node_tag
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct ResidentProxyCandidatePlan {
    pub(super) match_index: usize,
    pub(super) annotation_add_latency_ms: i64,
    pub(super) link: String,
    pub(super) proxy: ResidentProxyPlan,
}

#[derive(Clone, Debug)]
pub(super) struct ResidentProxyProbePlan {
    pub(super) node_tag: String,
    pub(super) link: String,
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
    pub(super) link: String,
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
                    link: candidate.link.clone(),
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

#[derive(Clone, Debug)]
pub(super) struct ResidentDataplanePlan {
    pub(super) enabled: bool,
    pub(super) unsupported_reason: Option<String>,
    pub(super) proxies: BTreeMap<u8, ResidentProxyGroupPlan>,
    pub(super) default_outbound: Option<u8>,
    pub(super) tcp_dial_mode: TcpDialMode,
    pub(super) sniffing_timeout: Duration,
    pub(super) dns: ResidentDnsPlan,
}

impl ResidentDataplanePlan {
    pub(super) fn default_proxy_group(&self) -> Option<&ResidentProxyGroupPlan> {
        self.default_outbound
            .and_then(|outbound| self.proxies.get(&outbound))
    }

    pub(super) fn default_proxy_snapshot(&self) -> Option<ResidentProxyPlan> {
        self.default_proxy_group()
            .and_then(ResidentProxyGroupPlan::default_proxy_snapshot)
    }
}

pub(super) fn build_resident_dataplane_plan(
    config: &Config,
) -> Result<ResidentDataplanePlan, String> {
    let node_links = tagged_node_links(config);
    let (proxies, default_outbound) = resident_proxy_plans(config, &node_links)?;
    if default_outbound
        .and_then(|outbound| proxies.get(&outbound))
        .and_then(ResidentProxyGroupPlan::default_proxy_snapshot)
        .is_none()
    {
        return Ok(ResidentDataplanePlan {
            enabled: false,
            unsupported_reason: Some(
                "no user-defined routing outbound with a resolvable node link was found".to_owned(),
            ),
            proxies,
            default_outbound: None,
            tcp_dial_mode: parse_tcp_dial_mode(config)?,
            sniffing_timeout: Duration::ZERO,
            dns: ResidentDnsPlan::asis(config.global.so_mark_from_dae),
        });
    };
    let tcp_dial_mode = parse_tcp_dial_mode(config)?;
    let sniffing_timeout = tcp_sniffing_timeout(config, tcp_dial_mode);
    let dns = build_resident_dns_plan(config)?;
    Ok(ResidentDataplanePlan {
        enabled: true,
        unsupported_reason: None,
        proxies,
        default_outbound,
        tcp_dial_mode,
        sniffing_timeout,
        dns,
    })
}

fn resident_proxy_plans(
    config: &Config,
    node_links: &BTreeMap<String, String>,
) -> Result<(BTreeMap<u8, ResidentProxyGroupPlan>, Option<u8>), String> {
    let mut proxies = BTreeMap::new();
    let mut default_outbound = None;
    for outbound in referenced_user_outbounds(config) {
        if node_links.contains_key(&outbound) {
            return Err(format!(
                "resident dataplane cannot assign direct node outbound {outbound} to a stable Go-compatible outbound index; put the node behind a group before enabling Rust resident dataplane",
            ));
        }
        let Some((group_index, group)) = config
            .group
            .iter()
            .enumerate()
            .find(|(_, group)| group.name == outbound)
        else {
            continue;
        };
        let outbound_index = (OutboundIndex::USER_DEFINED_MIN.value() as usize + group_index) as u8;
        if proxies.contains_key(&outbound_index) {
            continue;
        }
        let group_policy = parse_group_policy(&group.policy)
            .map_err(|err| format!("resident dataplane group {} policy: {err}", group.name))?;
        let matched_nodes = match select_group_nodes(group, node_links)? {
            GroupNodeSelection::Selected(nodes) => nodes,
            GroupNodeSelection::NoCandidate {
                explicit_name_filter,
                unresolved_names,
            } => {
                let names = if unresolved_names.is_empty() {
                    "<empty>".to_owned()
                } else {
                    unresolved_names.join(", ")
                };
                let reason = if explicit_name_filter {
                    format!(
                        "resident dataplane cannot resolve group {} name filter node(s): {names}; subscription-backed groups must be materialized before Rust resident dataplane can own runtime",
                        group.name
                    )
                } else {
                    format!(
                        "resident dataplane cannot resolve any node for referenced group {}",
                        group.name
                    )
                };
                return Err(reason);
            }
        };
        let matched_candidate_count = matched_nodes.len();
        let build_nodes = if let Some(index) = group_policy.fixed_index() {
            let Some(node) = matched_nodes.get(index) else {
                return Err(format!(
                    "resident dataplane group {} fixed policy index {} is out of range for {} matched node(s)",
                    group.name, index, matched_candidate_count
                ));
            };
            vec![node.clone()]
        } else {
            matched_nodes
        };
        let mut candidates = Vec::with_capacity(build_nodes.len());
        for node in build_nodes {
            let link = node.link.clone();
            let mut proxy =
                build_proxy_plan(config, group.name.clone(), node.tag.clone(), node.link)?;
            proxy.group_policy = group_policy.as_str().to_owned();
            candidates.push(ResidentProxyCandidatePlan {
                match_index: node.match_index,
                annotation_add_latency_ms: node.annotation_add_latency_ms,
                link,
                proxy,
            });
        }
        if candidates.is_empty() {
            return Err(format!(
                "resident dataplane cannot resolve any admitted candidate for referenced group {}",
                group.name
            ));
        }
        let selector = build_resident_group_selector(
            &group.name,
            &group_policy,
            &candidates,
            group_check_tolerance_ms(config, group),
        );
        let group_plan = ResidentProxyGroupPlan {
            group_name: group.name.clone(),
            group_policy,
            matched_candidate_count,
            selector: Arc::new(Mutex::new(selector)),
            candidates,
            check_interval: group_check_interval(config, group),
            tcp_check: group_tcp_check_plan(config, group)?,
            udp_check: group_udp_check_plan(config, group)?,
        };
        default_outbound.get_or_insert(outbound_index);
        proxies.insert(outbound_index, group_plan);
    }
    Ok((proxies, default_outbound))
}

fn build_resident_group_selector(
    group_name: &str,
    group_policy: &ResidentGroupPolicyPlan,
    candidates: &[ResidentProxyCandidatePlan],
    check_tolerance_ms: i64,
) -> DialerGroup {
    let selector_policy = match group_policy {
        ResidentGroupPolicyPlan::Fixed { .. } => SelectionPolicy::Fixed { index: 0 },
        ResidentGroupPolicyPlan::Random => SelectionPolicy::Random,
        ResidentGroupPolicyPlan::MinLastLatency => SelectionPolicy::MinLastLatency,
        ResidentGroupPolicyPlan::MinAverage10 => SelectionPolicy::MinAverage10,
        ResidentGroupPolicyPlan::MinMovingAverage => SelectionPolicy::MinMovingAverage,
    };
    DialerGroup::new(
        group_name,
        candidates
            .iter()
            .map(|candidate| {
                Dialer::new(candidate.proxy.node_tag.clone(), "").with_link(candidate.link.clone())
            })
            .collect(),
        candidates
            .iter()
            .map(|candidate| Annotation {
                add_latency_ms: candidate.annotation_add_latency_ms,
            })
            .collect(),
        selector_policy,
        true,
        check_tolerance_ms,
    )
}

fn group_check_tolerance_ms(config: &Config, group: &Group) -> i64 {
    let nanos = if group.check_tolerance.as_nanos() != 0 {
        group.check_tolerance.as_nanos()
    } else {
        config.global.check_tolerance.as_nanos()
    };
    duration_nanos_to_millis(nanos)
}

fn group_check_interval(config: &Config, group: &Group) -> Duration {
    let nanos = if group.check_interval.as_nanos() != 0 {
        group.check_interval.as_nanos()
    } else {
        config.global.check_interval.as_nanos()
    };
    duration_nanos_to_duration(nanos)
}

fn duration_nanos_to_duration(nanos: i64) -> Duration {
    if nanos <= 0 {
        return Duration::ZERO;
    }
    Duration::from_nanos(nanos as u64)
}

fn group_tcp_check_plan(config: &Config, group: &Group) -> Result<ResidentTcpCheckPlan, String> {
    let urls = group
        .tcp_check_url
        .as_ref()
        .filter(|urls| !urls.is_empty())
        .unwrap_or(&config.global.tcp_check_url);
    let raw = urls
        .first()
        .filter(|raw| !raw.is_empty())
        .map(String::as_str)
        .unwrap_or("http://cp.cloudflare.com");
    let url = Url::parse(raw).map_err(|err| {
        format!(
            "resident dataplane group {} tcp_check_url {raw}: {err}",
            group.name
        )
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "resident dataplane group {} tcp_check_url supports http or https check targets, got scheme {}",
            group.name,
            url.scheme()
        ));
    }
    let host = url.host_str().ok_or_else(|| {
        format!(
            "resident dataplane group {} tcp_check_url {raw} has no host",
            group.name
        )
    })?;
    let port = url.port_or_known_default().unwrap_or(80);
    let mut path = url.path().to_owned();
    if path.is_empty() {
        path = "/".to_owned();
    }
    if let Some(query) = url.query()
        && !query.is_empty()
    {
        path.push('?');
        path.push_str(query);
    }
    let method = if !group.tcp_check_http_method.is_empty() {
        group.tcp_check_http_method.clone()
    } else if !config.global.tcp_check_http_method.is_empty() {
        config.global.tcp_check_http_method.clone()
    } else {
        "HEAD".to_owned()
    };
    let explicit_addresses = if urls.len() > 1 { &urls[1..] } else { &[] };
    Ok(ResidentTcpCheckPlan {
        scheme: url.scheme().to_owned(),
        target: tcp_check_target(host, port, explicit_addresses),
        host: host.to_owned(),
        path,
        method,
    })
}

fn group_udp_check_plan(config: &Config, group: &Group) -> Result<ResidentUdpCheckPlan, String> {
    let values = group
        .udp_check_dns
        .as_ref()
        .filter(|values| !values.is_empty())
        .unwrap_or(&config.global.udp_check_dns);
    let raw = values
        .first()
        .filter(|raw| !raw.is_empty())
        .map(String::as_str)
        .unwrap_or("dns.google:53");
    let (host, port) = split_check_host_port(raw).map_err(|err| {
        format!(
            "resident dataplane group {} udp_check_dns {raw}: {err}",
            group.name
        )
    })?;
    let explicit_addresses = if values.len() > 1 { &values[1..] } else { &[] };
    let target = explicit_or_resolved_ipv4(&host, port, explicit_addresses).map_err(|err| {
        format!(
            "resident dataplane group {} udp_check_dns {raw}: {err}",
            group.name
        )
    })?;
    Ok(ResidentUdpCheckPlan {
        target,
        host,
        lookup_host: "connectivitycheck.gstatic.com.".to_owned(),
    })
}

fn split_check_host_port(raw: &str) -> Result<(String, u16), String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty host:port".to_owned());
    }
    if let Some(rest) = raw.strip_prefix('[') {
        let Some((host, after_host)) = rest.split_once(']') else {
            return Err("missing closing bracket for IPv6 host".to_owned());
        };
        let port = after_host
            .strip_prefix(':')
            .ok_or_else(|| "missing port after IPv6 host".to_owned())?;
        return Ok((host.to_owned(), parse_check_port(port)?));
    }
    let Some((host, port)) = raw.rsplit_once(':') else {
        return Err("expected host:port".to_owned());
    };
    if host.is_empty() {
        return Err("empty host".to_owned());
    }
    Ok((host.to_owned(), parse_check_port(port)?))
}

fn parse_check_port(raw: &str) -> Result<u16, String> {
    raw.parse::<u16>()
        .map_err(|err| format!("invalid port {raw}: {err}"))
}

fn tcp_check_target(host: &str, port: u16, explicit_addresses: &[String]) -> String {
    for raw in explicit_addresses {
        let raw = raw.trim();
        if raw.parse::<Ipv4Addr>().is_ok() {
            return format!("{raw}:{port}");
        }
    }
    format!("{host}:{port}")
}

fn explicit_or_resolved_ipv4(
    host: &str,
    port: u16,
    explicit_addresses: &[String],
) -> Result<SocketAddrV4, String> {
    for raw in explicit_addresses {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if let Ok(ip) = raw.parse::<Ipv4Addr>() {
            return Ok(SocketAddrV4::new(ip, port));
        }
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(SocketAddrV4::new(ip, port));
    }
    let authority = format!("{host}:{port}");
    authority
        .to_socket_addrs()
        .map_err(|err| format!("resolve {authority}: {err}"))?
        .find_map(|addr| match addr {
            SocketAddr::V4(addr) => Some(addr),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("resolve {authority}: no IPv4 address"))
}

fn duration_nanos_to_millis(nanos: i64) -> i64 {
    if nanos <= 0 {
        return 0;
    }
    (nanos + 999_999) / 1_000_000
}

fn resident_selector_network_type(network: &str) -> Result<NetworkType, String> {
    match network {
        "tcp4" => Ok(NetworkType::TCP4),
        "udp4" => Ok(NetworkType::DNS_UDP4),
        other => Err(format!("unsupported resident selector network: {other}")),
    }
}

fn build_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let scheme = link_scheme(&link).unwrap_or_default();
    match scheme.as_str() {
        "vless" => build_vless_proxy_plan(config, group_name, node_tag, link),
        "socks" | "socks5" => build_socks5_proxy_plan(config, group_name, node_tag, link),
        "http" | "https" => build_http_proxy_plan(config, group_name, node_tag, link),
        "ss" | "shadowsocks" => build_shadowsocks_proxy_plan(config, group_name, node_tag, link),
        "trojan" | "trojan-go" => build_trojan_proxy_plan(config, group_name, node_tag, link),
        "anytls" => build_anytls_proxy_plan(config, group_name, node_tag, link),
        "vmess" => build_vmess_proxy_plan(config, group_name, node_tag, link),
        "hysteria2" | "hy2" => build_hysteria2_proxy_plan(config, group_name, node_tag, link),
        "tuic" => build_tuic_proxy_plan(config, group_name, node_tag, link),
        "juicity" => build_juicity_proxy_plan(config, group_name, node_tag, link),
        _ => Err(format!(
            "resident dataplane selected unsupported {scheme} node {node_tag}; no Rust protocol handler is admitted for this node yet, keep Go outbound for this config",
        )),
    }
}

fn build_vless_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let vless =
        VLESSLink::parse(&link).map_err(|err| format!("parse VLESS node {node_tag}: {err}"))?;
    vless
        .validate_flow_client(true)
        .map_err(|err| format!("validate VLESS flow for {node_tag}: {err}"))?;
    vless
        .validate_transport_contract()
        .map_err(|err| format!("validate VLESS transport for {node_tag}: {err}"))?;
    if vless.flow != XTLS_RPRX_VISION {
        return Err(format!(
            "resident dataplane vless native experiment admits only flow={XTLS_RPRX_VISION}, got '{}' for node {node_tag}; keep Go outbound for this config",
            vless.flow
        ));
    }
    if vless.net != "tcp" {
        return Err(format!(
            "resident dataplane vless handler currently supports tcp transport only, got {} for node {node_tag}",
            vless.net
        ));
    }
    if vless.tls != "tls" {
        return Err(format!(
            "resident dataplane vless handler currently supports security=tls only, got {} for node {node_tag}",
            vless.tls
        ));
    }
    if vless.allow_insecure || config.global.allow_insecure {
        return Err(
            "resident dataplane vless TLS handler does not admit allow_insecure; keep Go fallback for this config"
                .to_owned(),
        );
    }
    let utls_fingerprint = resident_utls_fingerprint_plan(config, Some(&vless.fingerprint))?;
    let server_port = vless.port.parse::<u16>().map_err(|err| {
        format!(
            "invalid VLESS port {} for node {node_tag}: {err}",
            vless.port
        )
    })?;
    let key = password_to_key(&vless.id)
        .map_err(|err| format!("parse VLESS key for {node_tag}: {err}"))?;
    let server_name = if vless.sni.is_empty() {
        vless.add.clone()
    } else {
        vless.sni.clone()
    };
    let alpn = split_alpn(&vless.alpn);
    Ok(ResidentProxyPlan {
        protocol: "vless".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: vless.add,
        server_port,
        server_name,
        alpn,
        flow: vless.flow,
        net: vless.net,
        tls: vless.tls,
        allow_insecure: false,
        utls_fingerprint,
        handler: ResidentProxyProtocolPlan::VlessVisionTcpTls { key },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_socks5_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed = Url::parse(&link).map_err(|err| format!("parse SOCKS node {node_tag}: {err}"))?;
    if !matches!(parsed.scheme(), "socks" | "socks5") {
        return Err(format!(
            "resident dataplane socks5 handler got unsupported scheme {} for node {node_tag}",
            parsed.scheme()
        ));
    }
    let server_host = parsed
        .host_str()
        .ok_or_else(|| format!("parse SOCKS node {node_tag}: missing host"))?
        .to_owned();
    let server_port = parsed.port().unwrap_or(1080);
    Ok(ResidentProxyPlan {
        protocol: "socks5".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host,
        server_port,
        server_name: String::new(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        tls: "none".to_owned(),
        allow_insecure: false,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::Socks5Tcp {
            username: parsed.username().to_owned(),
            password: parsed.password().unwrap_or_default().to_owned(),
        },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_http_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed = HttpProxyLink::parse(&link)
        .map_err(|err| format!("parse HTTP proxy node {node_tag}: {err}"))?;
    if parsed.protocol != HttpScheme::Http {
        return Err(format!(
            "resident dataplane first-batch HTTP proxy handler admits plain http proxy endpoints only for node {node_tag}"
        ));
    }
    if parsed.transport {
        return Err(format!(
            "resident dataplane first-batch HTTP proxy handler does not admit HTTP transport mode for node {node_tag}"
        ));
    }
    if parsed.allow_insecure {
        return Err(format!(
            "resident dataplane first-batch HTTP proxy handler does not admit allow_insecure for node {node_tag}"
        ));
    }
    Ok(ResidentProxyPlan {
        protocol: "http-proxy".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name: String::new(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        tls: "none".to_owned(),
        allow_insecure: false,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::HttpProxyTcp {
            username: parsed.username,
            password: parsed.password,
        },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_shadowsocks_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed = ShadowsocksLink::parse(&link)
        .map_err(|err| format!("parse Shadowsocks node {node_tag}: {err}"))?;
    if !parsed.plugin.name.is_empty() {
        return Err(format!(
            "resident dataplane first-batch Shadowsocks handler does not admit SIP003 plugin {} for node {node_tag}",
            parsed.plugin.name
        ));
    }
    let spec = cipher_spec(&parsed.cipher)
        .map_err(|err| format!("admit Shadowsocks cipher for node {node_tag}: {err}"))?;
    Ok(ResidentProxyPlan {
        protocol: "shadowsocks".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name: String::new(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        tls: "aead".to_owned(),
        allow_insecure: false,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
            cipher: spec.cipher.to_owned(),
            password: parsed.password,
            salt_len: spec.salt_len,
        },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_trojan_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        TrojanLink::parse(&link).map_err(|err| format!("parse Trojan node {node_tag}: {err}"))?;
    if parsed.protocol != "trojan" || parsed.transport_kind() != TrojanTransportType::None {
        return Err(format!(
            "resident dataplane generic TLS/TCP handler admits only plain trojan endpoints for node {node_tag}; transport={} protocol={}",
            parsed.transport_type, parsed.protocol
        ));
    }
    if parsed.allow_insecure || config.global.allow_insecure {
        return Err(
            "resident dataplane generic TLS/TCP handler does not admit allow_insecure; keep Go fallback for this config"
                .to_owned(),
        );
    }
    let utls_fingerprint = resident_utls_fingerprint_plan(config, None)?;
    Ok(ResidentProxyPlan {
        protocol: "trojan".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name: parsed.sni,
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        tls: "tls".to_owned(),
        allow_insecure: false,
        utls_fingerprint,
        handler: ResidentProxyProtocolPlan::TrojanTcpTls {
            password: parsed.password,
        },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_anytls_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        AnyTLSLink::parse(&link).map_err(|err| format!("parse AnyTLS node {node_tag}: {err}"))?;
    if parsed.insecure || config.global.allow_insecure {
        return Err(
            "resident dataplane generic TLS/TCP handler does not admit AnyTLS insecure mode; keep Go fallback for this config"
                .to_owned(),
        );
    }
    let url =
        Url::parse(&link).map_err(|err| format!("parse AnyTLS endpoint {node_tag}: {err}"))?;
    let server_host = url
        .host_str()
        .ok_or_else(|| format!("parse AnyTLS endpoint {node_tag}: missing host"))?
        .to_owned();
    let server_port = url.port().unwrap_or(443);
    let utls_fingerprint = resident_utls_fingerprint_plan(config, None)?;
    Ok(ResidentProxyPlan {
        protocol: "anytls".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host,
        server_port,
        server_name: parsed.tls_server_name,
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        tls: "tls".to_owned(),
        allow_insecure: false,
        utls_fingerprint,
        handler: ResidentProxyProtocolPlan::AnyTlsTcpTls { auth: parsed.auth },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_tuic_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        TuicLink::parse(&link).map_err(|err| format!("parse TUIC node {node_tag}: {err}"))?;
    parsed
        .validate_uuid()
        .map_err(|err| format!("validate TUIC UUID for {node_tag}: {err}"))?;
    if !(parsed.allow_insecure || config.global.allow_insecure || parsed.disable_sni) {
        return Err(format!(
            "resident dataplane generic QUIC handler admits TUIC only when allow_insecure is explicit for node {node_tag}; keep Go fallback for this config"
        ));
    }
    if parsed.password.is_empty() {
        return Err(format!(
            "resident dataplane generic QUIC handler requires TUIC password for node {node_tag}; keep Go fallback for this config"
        ));
    }
    let server_name = if parsed.sni.is_empty() {
        parsed.server.clone()
    } else {
        parsed.sni.clone()
    };
    let alpn = if parsed.alpn.is_empty() {
        vec!["h3".to_owned()]
    } else {
        parsed.alpn.clone()
    };
    Ok(ResidentProxyPlan {
        protocol: "tuic".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name,
        alpn: alpn.clone(),
        flow: String::new(),
        net: "udp".to_owned(),
        tls: "quic".to_owned(),
        allow_insecure: true,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::TuicQuicTcp {
            uuid: parsed.user,
            password: parsed.password,
            alpn,
        },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_hysteria2_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed = Hysteria2Link::parse(&link)
        .map_err(|err| format!("parse Hysteria2 node {node_tag}: {err}"))?;
    if parsed.insecure || config.global.allow_insecure {
        return Err(
            "resident dataplane generic QUIC handler does not admit Hysteria2 insecure mode; keep Go fallback for this config"
                .to_owned(),
        );
    }
    if parsed.pin_sha256.is_empty() {
        return Err(format!(
            "resident dataplane generic QUIC handler requires Hysteria2 pinSHA256 for node {node_tag}; keep Go fallback for this config"
        ));
    }
    let auth = if parsed.password.is_empty() {
        parsed.user.clone()
    } else {
        format!("{}:{}", parsed.user, parsed.password)
    };
    if auth.is_empty() {
        return Err(format!(
            "resident dataplane generic QUIC handler requires Hysteria2 auth for node {node_tag}; keep Go fallback for this config"
        ));
    }
    let server = hysteria2_server_contract(&parsed.server);
    if server.port_hopping {
        return Err(format!(
            "resident dataplane generic QUIC handler admits only single-port Hysteria2 endpoints for node {node_tag}; got {}",
            parsed.server
        ));
    }
    let server_port = server.port.parse::<u16>().map_err(|err| {
        format!(
            "invalid Hysteria2 port {} for node {node_tag}: {err}",
            server.port
        )
    })?;
    let server_name = if parsed.sni.is_empty() {
        server.host.clone()
    } else {
        parsed.sni.clone()
    };
    Ok(ResidentProxyPlan {
        protocol: "hysteria2".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: server.host,
        server_port,
        server_name,
        alpn: vec!["h3".to_owned()],
        flow: String::new(),
        net: "udp".to_owned(),
        tls: "quic".to_owned(),
        allow_insecure: false,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            auth,
            pin_sha256: parsed.pin_sha256,
            max_rx: parsed.max_rx,
        },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_juicity_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        JuicityLink::parse(&link).map_err(|err| format!("parse Juicity node {node_tag}: {err}"))?;
    parsed
        .validate_uuid()
        .map_err(|err| format!("validate Juicity UUID for {node_tag}: {err}"))?;
    if parsed.password.is_empty() {
        return Err(format!(
            "resident dataplane generic QUIC handler requires Juicity password for node {node_tag}; keep Go fallback for this config"
        ));
    }
    let allow_insecure = parsed.allow_insecure || config.global.allow_insecure;
    if !allow_insecure && parsed.pinned_certchain_sha256.is_empty() {
        return Err(format!(
            "resident dataplane generic QUIC handler requires Juicity allow_insecure or pinned_certchain_sha256 for node {node_tag}; keep Go fallback for this config"
        ));
    }
    let server_name = if parsed.sni.is_empty() {
        parsed.server.clone()
    } else {
        parsed.sni.clone()
    };
    Ok(ResidentProxyPlan {
        protocol: "juicity".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name,
        alpn: vec!["h3".to_owned()],
        flow: String::new(),
        net: "udp".to_owned(),
        tls: "quic".to_owned(),
        allow_insecure,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::JuicityQuicTcp {
            uuid: parsed.user,
            password: parsed.password,
            allow_insecure,
            pinned_certchain_sha256: parsed.pinned_certchain_sha256,
        },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_vmess_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        VMessLink::parse(&link).map_err(|err| format!("parse VMess node {node_tag}: {err}"))?;
    parsed
        .validate_aead()
        .map_err(|err| format!("validate VMess AEAD for {node_tag}: {err}"))?;
    parsed
        .validate_transport()
        .map_err(|err| format!("validate VMess transport for {node_tag}: {err}"))?;
    if parsed.net != "tcp" {
        return Err(format!(
            "resident dataplane generic AEAD TCP handler admits only VMess net=tcp endpoints for node {node_tag}; got {}",
            parsed.net
        ));
    }
    if !parsed.tls.is_empty() && parsed.tls != "none" {
        return Err(format!(
            "resident dataplane generic AEAD TCP handler admits only plain VMess TCP endpoints for node {node_tag}; got tls={}",
            parsed.tls
        ));
    }
    if parsed.allow_insecure || config.global.allow_insecure {
        return Err(
            "resident dataplane generic AEAD TCP handler does not admit allow_insecure; keep Go fallback for this config"
                .to_owned(),
        );
    }
    let server_port = parsed.port.parse::<u16>().map_err(|err| {
        format!(
            "invalid VMess port {} for node {node_tag}: {err}",
            parsed.port
        )
    })?;
    Ok(ResidentProxyPlan {
        protocol: "vmess".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.add,
        server_port,
        server_name: String::new(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        tls: "none".to_owned(),
        allow_insecure: false,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::VmessAeadTcp { id: parsed.id },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

pub(super) fn build_resident_proxy_plan_for_node(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    build_proxy_plan(config, group_name, node_tag, link)
}

pub(super) fn resident_node_link_shapes(config: &Config) -> Vec<ResidentNodeLinkShape> {
    tagged_node_links(config)
        .into_iter()
        .map(|(tag, link)| ResidentNodeLinkShape {
            tag,
            scheme: link_scheme(&link).unwrap_or_default(),
            link,
        })
        .collect()
}

fn resident_utls_fingerprint_plan(
    config: &Config,
    link_fingerprint: Option<&str>,
) -> Result<Option<ResidentUtlsFingerprintPlan>, String> {
    let link_fingerprint = link_fingerprint.unwrap_or_default().trim();
    if !link_fingerprint.is_empty() && !link_fingerprint.eq_ignore_ascii_case("unsafe") {
        return resolve_optional_resident_utls_fingerprint("link fp", link_fingerprint);
    }
    if link_fingerprint.eq_ignore_ascii_case("unsafe") {
        return Ok(None);
    }

    if config
        .global
        .tls_implementation
        .trim()
        .eq_ignore_ascii_case("utls")
    {
        let global_fingerprint = config.global.utls_imitate.trim();
        if global_fingerprint.is_empty() {
            return resolve_resident_utls_fingerprint("default fingerprint", "chrome").map(Some);
        }
        return resolve_optional_resident_utls_fingerprint(
            "global utls_imitate",
            global_fingerprint,
        );
    }

    Ok(None)
}

fn resolve_optional_resident_utls_fingerprint(
    source: &'static str,
    requested: &str,
) -> Result<Option<ResidentUtlsFingerprintPlan>, String> {
    if requested.eq_ignore_ascii_case("unsafe") {
        return Ok(None);
    }
    resolve_resident_utls_fingerprint(source, requested).map(Some)
}

fn resolve_resident_utls_fingerprint(
    source: &'static str,
    requested: &str,
) -> Result<ResidentUtlsFingerprintPlan, String> {
    let fingerprint = resolve_utls_client_hello_id(requested)
        .map_err(|err| format!("resident dataplane unsupported {source} {requested}: {err}"))?;
    Ok(resident_utls_fingerprint_plan_from(
        source,
        requested,
        fingerprint,
    ))
}

fn resident_utls_fingerprint_plan_from(
    source: &'static str,
    requested: &str,
    fingerprint: UtlsFingerprint,
) -> ResidentUtlsFingerprintPlan {
    ResidentUtlsFingerprintPlan {
        source,
        requested: requested.to_owned(),
        name: fingerprint.name.to_owned(),
        canonical: fingerprint.canonical.to_owned(),
        family: fingerprint.family.to_owned(),
        client: fingerprint.client.to_owned(),
        randomized: fingerprint.randomized,
        alpn_policy: fingerprint.alpn_policy.to_owned(),
    }
}

fn parse_tcp_dial_mode(config: &Config) -> Result<TcpDialMode, String> {
    config
        .global
        .dial_mode
        .parse::<TcpDialMode>()
        .map_err(|err| format!("resident dataplane dial_mode: {err}"))
}

fn tcp_sniffing_timeout(config: &Config, dial_mode: TcpDialMode) -> Duration {
    if dial_mode == TcpDialMode::Ip {
        return Duration::ZERO;
    }
    let nanos = config.global.sniffing_timeout.as_nanos();
    if nanos <= 0 {
        Duration::ZERO
    } else {
        Duration::from_nanos(nanos as u64)
    }
}

fn referenced_user_outbounds(config: &Config) -> Vec<String> {
    let mut outbounds = Vec::new();
    for rule in &config.routing.rules {
        push_user_outbound(&mut outbounds, &rule.outbound.name);
    }
    match &config.routing.fallback {
        DynamicFunctionValue::String(name) => push_user_outbound(&mut outbounds, name),
        DynamicFunctionValue::Function(function) => {
            push_user_outbound(&mut outbounds, &function.name)
        }
        DynamicFunctionValue::FunctionList(functions) => {
            for function in functions {
                push_user_outbound(&mut outbounds, &function.name);
            }
        }
        DynamicFunctionValue::Nil => {}
    }
    outbounds
}

fn push_user_outbound(outbounds: &mut Vec<String>, name: &str) {
    if matches!(
        name,
        "direct" | "block" | "must_rules" | "logical_or" | "logical_and"
    ) {
        return;
    }
    if !outbounds.iter().any(|seen| seen == name) {
        outbounds.push(name.to_owned());
    }
}

fn select_group_nodes(
    group: &Group,
    node_links: &BTreeMap<String, String>,
) -> Result<GroupNodeSelection, String> {
    let (explicit_name_filter, unresolved_names) =
        unresolved_positive_name_filters(group, node_links);
    let filter_groups = outbound_filter_groups(group);
    let annotations = outbound_filter_annotations(group)?;
    let dialer_set = DialerSet {
        dialers: node_links
            .iter()
            .map(|(tag, link)| Dialer::new(tag.clone(), "").with_link(link.clone()))
            .collect(),
    };
    let matched = dialer_set
        .filter_and_annotate(&filter_groups, &annotations)
        .map_err(|err| format!("resident dataplane group {} filter: {err}", group.name))?;
    if matched.is_empty() {
        return Ok(GroupNodeSelection::NoCandidate {
            explicit_name_filter,
            unresolved_names,
        });
    }
    let mut nodes = Vec::with_capacity(matched.len());
    for (match_index, matched) in matched.into_iter().enumerate() {
        let link = node_links
            .get(&matched.name)
            .ok_or_else(|| {
                format!(
                    "group {} selected missing node {}",
                    group.name, matched.name
                )
            })?
            .clone();
        nodes.push(SelectedGroupNode {
            match_index,
            tag: matched.name,
            link,
            annotation_add_latency_ms: matched.annotation.add_latency_ms,
        });
    }
    Ok(GroupNodeSelection::Selected(nodes))
}

fn unresolved_positive_name_filters(
    group: &Group,
    node_links: &BTreeMap<String, String>,
) -> (bool, Vec<String>) {
    let mut unresolved_names = Vec::<String>::new();
    let mut explicit_name_filter = false;
    for filter in &group.filter {
        for function in filter {
            if function.name != "name" || function.not {
                continue;
            }
            explicit_name_filter = true;
            for param in &function.params {
                if param.key.is_empty() && !node_links.contains_key(&param.val) {
                    unresolved_names.push(param.val.clone());
                }
            }
        }
    }
    (explicit_name_filter, unresolved_names)
}

fn outbound_filter_groups(group: &Group) -> Vec<Vec<Filter>> {
    group
        .filter
        .iter()
        .map(|filters| filters.iter().map(outbound_filter).collect())
        .collect()
}

fn outbound_filter(function: &Function) -> Filter {
    Filter {
        name: function.name.clone(),
        not: function.not,
        params: function
            .params
            .iter()
            .map(|param| FilterParam::new(param.key.clone(), param.val.clone()))
            .collect(),
    }
}

fn outbound_filter_annotations(group: &Group) -> Result<Vec<Annotation>, String> {
    if group.filter.is_empty() {
        return Ok(Vec::new());
    }
    if group.filter_annotation.is_empty() {
        return Ok(vec![Annotation::default(); group.filter.len()]);
    }
    if group.filter_annotation.len() != group.filter.len() {
        return Err(format!(
            "unmatched filter annotation length: {} filters and {} annotations",
            group.filter.len(),
            group.filter_annotation.len()
        ));
    }
    group
        .filter_annotation
        .iter()
        .map(|params| match params {
            Some(params) => annotation_from_params(params),
            None => Ok(Annotation::default()),
        })
        .collect()
}

fn annotation_from_params(params: &[Param]) -> Result<Annotation, String> {
    let pairs = params
        .iter()
        .map(|param| (param.key.as_str(), param.val.as_str()))
        .collect::<Vec<_>>();
    Annotation::from_params(&pairs).map_err(|err| err.to_string())
}

fn parse_group_policy(policy: &DynamicFunctionValue) -> Result<ResidentGroupPolicyPlan, String> {
    match policy {
        DynamicFunctionValue::Nil => Ok(ResidentGroupPolicyPlan::Fixed { index: 0 }),
        DynamicFunctionValue::String(value) => parse_group_policy_string(value),
        DynamicFunctionValue::Function(function) => parse_group_policy_function(function),
        DynamicFunctionValue::FunctionList(functions) if functions.len() == 1 => {
            parse_group_policy_function(&functions[0])
        }
        DynamicFunctionValue::FunctionList(functions) => Err(format!(
            "policy should be exact 1 function: got {}",
            functions.len()
        )),
    }
}

fn parse_group_policy_string(value: &str) -> Result<ResidentGroupPolicyPlan, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(ResidentGroupPolicyPlan::Fixed { index: 0 });
    }
    if let Some(raw) = value
        .strip_prefix("fixed(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        let index = raw
            .trim()
            .parse::<usize>()
            .map_err(|err| format!("invalid fixed policy index {raw}: {err}"))?;
        return Ok(ResidentGroupPolicyPlan::Fixed { index });
    }
    match value {
        "fixed" => Ok(ResidentGroupPolicyPlan::Fixed { index: 0 }),
        "random" => Ok(ResidentGroupPolicyPlan::Random),
        "min" => Ok(ResidentGroupPolicyPlan::MinLastLatency),
        "min_avg10" | "min_average10" => Ok(ResidentGroupPolicyPlan::MinAverage10),
        "min_moving_avg" => Ok(ResidentGroupPolicyPlan::MinMovingAverage),
        other => Err(format!("unexpected policy: {other}")),
    }
}

fn parse_group_policy_function(function: &Function) -> Result<ResidentGroupPolicyPlan, String> {
    match function.name.as_str() {
        "fixed" => {
            if function.not {
                return Err("policy param does not support not operator: !fixed()".to_owned());
            }
            let Some(param) = function.params.first() else {
                return Ok(ResidentGroupPolicyPlan::Fixed { index: 0 });
            };
            if param.key != "" {
                return Err(r#"invalid "fixed" param format"#.to_owned());
            }
            let index = param
                .val
                .parse::<usize>()
                .map_err(|err| format!(r#"invalid "fixed" param format: {err}"#))?;
            Ok(ResidentGroupPolicyPlan::Fixed { index })
        }
        "random" => Ok(ResidentGroupPolicyPlan::Random),
        "min" => Ok(ResidentGroupPolicyPlan::MinLastLatency),
        "min_avg10" | "min_average10" => Ok(ResidentGroupPolicyPlan::MinAverage10),
        "min_moving_avg" => Ok(ResidentGroupPolicyPlan::MinMovingAverage),
        other => Err(format!("unexpected policy: {other}")),
    }
}

fn tagged_node_links(config: &Config) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for raw in &config.node {
        let (tag, link) = split_keyable_link(raw);
        if link.contains("://") {
            let tag = tag.unwrap_or_else(|| link.clone());
            out.insert(tag, link);
        }
    }
    out
}

fn link_scheme(link: &str) -> Option<String> {
    link.split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
}

fn split_keyable_link(raw: &str) -> (Option<String>, String) {
    let trimmed = raw.trim();
    let Some(scheme_pos) = trimmed.find("://") else {
        return (None, unquote_config_value(trimmed));
    };
    let before_scheme = &trimmed[..scheme_pos];
    if let Some(colon) = before_scheme.rfind(':') {
        let tag = unquote_config_value(&trimmed[..colon]);
        let link = unquote_config_value(&trimmed[colon + 1..]);
        if !tag.is_empty() {
            return (Some(tag), link);
        }
    }
    (None, unquote_config_value(trimmed))
}

fn unquote_config_value(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
        {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value.to_owned()
}

fn split_alpn(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_config(input: &str) -> Config {
        let sections = dae_config::parser::parse_config(input).unwrap();
        dae_config::schema::build_config(&sections).unwrap()
    }

    #[test]
    fn resident_dataplane_plan_selects_vless_group_node() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        pname(dae) -> must_direct
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        assert!(plan.enabled);
        assert_eq!(plan.proxies.len(), 1);
        assert_eq!(proxy.group_name, "proxy");
        assert_eq!(proxy.node_tag, "vless_live");
        assert_eq!(proxy.server_host, "156.246.90.2");
        assert_eq!(proxy.server_port, 443);
        assert_eq!(proxy.server_name, "office.example");
        assert_eq!(proxy.flow, "xtls-rprx-vision");
        assert_eq!(proxy.alpn, ["h2", "http/1.1"]);
        assert_eq!(proxy.mark, 1234);
    }

    #[test]
    fn group_node_selection_keeps_fixed_policy_order() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: fixed(1)
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let links = tagged_node_links(&config);
        let selected = select_group_nodes(&config.group[0], &links).unwrap();
        match selected {
            GroupNodeSelection::Selected(nodes) => {
                assert_eq!(nodes.len(), 2);
                assert_eq!(nodes[0].tag, "node_a");
                assert_eq!(nodes[0].link, "socks://127.0.0.1:1080");
                assert_eq!(nodes[1].tag, "node_b");
                assert_eq!(nodes[1].link, "socks://127.0.0.1:1081");
            }
            GroupNodeSelection::NoCandidate { .. } => panic!("expected selected node"),
        }
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        assert_eq!(proxy.node_tag, "node_b");
        assert_eq!(plan.default_proxy_group().unwrap().candidate_count(), 2);
    }

    #[test]
    fn group_node_selection_supports_generic_name_filters() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        node_c: 'socks://127.0.0.1:1082'
        }
        group {
        proxy {
            filter: name(regex: "^node_[ab]$") && !name(node_b)
            policy: random
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let links = tagged_node_links(&config);
        let selected = select_group_nodes(&config.group[0], &links).unwrap();
        match selected {
            GroupNodeSelection::Selected(nodes) => {
                assert_eq!(nodes.len(), 1);
                assert_eq!(nodes[0].tag, "node_a");
            }
            GroupNodeSelection::NoCandidate { .. } => panic!("expected selected node"),
        }
    }

    #[test]
    fn resident_dataplane_plan_keeps_non_fixed_group_candidates() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: random
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        assert_eq!(group.group_policy, ResidentGroupPolicyPlan::Random);
        assert_eq!(group.candidate_count(), 2);
        assert_eq!(group.admitted_candidate_count(), 2);
        assert!(group.alive_state_wired());
        let selected = group.select_proxy_for_tcp().unwrap();
        assert!(matches!(selected.node_tag.as_str(), "node_a" | "node_b"));
    }

    #[test]
    fn resident_dataplane_plan_wires_min_policy_latency_state() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: min_moving_avg
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        assert_eq!(
            group.group_policy,
            ResidentGroupPolicyPlan::MinMovingAverage
        );
        assert_eq!(group.candidate_count(), 2);
        assert_eq!(group.admitted_candidate_count(), 2);
        assert!(group.alive_state_wired());
        assert!(group.latency_state_wired());
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_a");
    }

    #[test]
    fn resident_dataplane_group_tcp_check_uses_group_override() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        tcp_check_url: 'http://global.example/generate_204'
        tcp_check_http_method: GET
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: min
            tcp_check_url: 'http://group.example/check?q=1'
            tcp_check_http_method: HEAD
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        let probes = group.probe_candidates();
        assert_eq!(probes[0].tcp_check.scheme, "http");
        assert_eq!(probes[0].tcp_check.target, "group.example:80");
        assert_eq!(probes[0].tcp_check.host, "group.example");
        assert_eq!(probes[0].tcp_check.path, "/check?q=1");
        assert_eq!(probes[0].tcp_check.method, "HEAD");
    }

    #[test]
    fn resident_dataplane_group_tcp_check_accepts_https() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        }
        group {
        proxy {
            filter: name(node_a)
            policy: min
            tcp_check_url: 'https://check.example/generate_204,203.0.113.7'
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let probes = plan.default_proxy_group().unwrap().probe_candidates();
        assert_eq!(probes[0].tcp_check.scheme, "https");
        assert_eq!(probes[0].tcp_check.target, "203.0.113.7:443");
        assert_eq!(probes[0].tcp_check.host, "check.example");
        assert_eq!(probes[0].tcp_check.path, "/generate_204");
    }

    #[test]
    fn resident_dataplane_group_udp_check_uses_group_override_ipv4() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        udp_check_dns: 'dns.global:53,8.8.8.8'
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        }
        group {
        proxy {
            filter: name(node_a)
            policy: min
            udp_check_dns: 'dns.group:5353,8.8.4.4'
        }
        }
        routing {
        l4proto(udp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let probes = plan.default_proxy_group().unwrap().probe_candidates();
        assert_eq!(
            probes[0].udp_check.target,
            SocketAddrV4::new(Ipv4Addr::new(8, 8, 4, 4), 5353)
        );
        assert_eq!(probes[0].udp_check.host, "dns.group");
        assert_eq!(
            probes[0].udp_check.lookup_host,
            "connectivitycheck.gstatic.com."
        );
    }

    #[test]
    fn resident_dataplane_min_policy_selects_checked_lowest_last_latency() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: min
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        group
            .record_check_result("node_a", NetworkType::TCP4, Some(200), 1)
            .unwrap();
        group
            .record_check_result("node_b", NetworkType::TCP4, Some(50), 2)
            .unwrap();
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
    }

    #[test]
    fn resident_dataplane_min_avg10_policy_uses_latency_history() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: min_avg10
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        for latency in [300, 300, 300] {
            group
                .record_check_result("node_a", NetworkType::TCP4, Some(latency), 1)
                .unwrap();
        }
        for latency in [120, 120, 120] {
            group
                .record_check_result("node_b", NetworkType::TCP4, Some(latency), 2)
                .unwrap();
        }
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
    }

    #[test]
    fn resident_dataplane_min_moving_avg_policy_uses_moving_average() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: min_moving_avg
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        group
            .record_check_result("node_a", NetworkType::TCP4, Some(240), 1)
            .unwrap();
        group
            .record_check_result("node_b", NetworkType::TCP4, Some(80), 2)
            .unwrap();
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
    }

    #[test]
    fn resident_dataplane_min_policy_honors_group_check_tolerance() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        check_tolerance: 10ms
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: min
            check_tolerance: 50ms
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        group
            .record_check_result("node_a", NetworkType::TCP4, Some(100), 1)
            .unwrap();
        group
            .record_check_result("node_b", NetworkType::TCP4, Some(80), 2)
            .unwrap();
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_a");
        group
            .record_check_result("node_b", NetworkType::TCP4, Some(40), 3)
            .unwrap();
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
    }

    #[test]
    fn resident_dataplane_min_policy_applies_add_latency_to_sorting_only() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a) [add_latency: 100ms]
            filter: name(node_b)
            policy: min
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        assert_eq!(group.annotation_latency_offset_count(), 1);
        group
            .record_check_result("node_a", NetworkType::TCP4, Some(50), 1)
            .unwrap();
        group
            .record_check_result("node_b", NetworkType::TCP4, Some(90), 2)
            .unwrap();
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
    }

    #[test]
    fn resident_dataplane_plan_keeps_fixed_from_building_unselected_candidate() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        unsupported: 'vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443?security=tls&type=xhttp&sni=office.example&path=%2Fxhttp&mode=packet-up&alpn=h3'
        }
        group {
        proxy {
            filter: name(node_a, unsupported)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        assert_eq!(group.candidate_count(), 2);
        assert_eq!(group.admitted_candidate_count(), 1);
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_a");
    }

    #[test]
    fn resident_dataplane_plan_does_not_fallback_unresolved_name_filter_to_static_ss_node() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        _022: 'ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@217.116.171.227:25868#ss2022'
        xhttp: 'vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443?security=tls&type=xhttp&sni=office.example&path=%2Fxhttp&mode=packet-up&alpn=h3'
        }
        group {
        proxy {
            filter: name(node_17)
            policy: fixed
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains("cannot resolve group proxy name filter node(s): node_17"));
        assert!(!err.contains("parse VLESS node _022"));
    }

    #[test]
    fn resident_dataplane_plan_rejects_unwired_shadowsocks_variant() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        ss_live: 'ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@217.116.171.227:25868#ss2022'
        }
        group {
        proxy {
            filter: name(ss_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains("admit Shadowsocks cipher for node ss_live"));
        assert!(err.contains("cipher is not stage18 AEAD TCP candidate"));
        assert!(!err.contains("parse VLESS node ss_live"));
    }

    #[test]
    fn resident_dataplane_plan_admits_first_batch_tcp_handlers() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        routing {
        fallback: direct
        }
        "#,
        );
        let socks = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "socks_live".to_owned(),
            "socks5://matrix:matrix-socks-pass@203.0.113.10:28447#socks".to_owned(),
        )
        .unwrap();
        assert_eq!(socks.protocol, "socks5");
        assert_eq!(socks.server_host, "203.0.113.10");
        assert_eq!(socks.server_port, 28447);
        assert!(matches!(
            socks.handler,
            ResidentProxyProtocolPlan::Socks5Tcp { .. }
        ));

        let http = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "http_live".to_owned(),
            "http://matrix:matrix-http-pass@203.0.113.10:28448#http".to_owned(),
        )
        .unwrap();
        assert_eq!(http.protocol, "http-proxy");
        assert_eq!(http.tls, "none");
        assert!(matches!(
            http.handler,
            ResidentProxyProtocolPlan::HttpProxyTcp { .. }
        ));

        let shadowsocks = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "ss_live".to_owned(),
            "ss://aes-128-gcm:matrix-ss-pass@203.0.113.10:28446#ss".to_owned(),
        )
        .unwrap();
        assert_eq!(shadowsocks.protocol, "shadowsocks");
        assert_eq!(shadowsocks.tls, "aead");
        assert!(matches!(
            shadowsocks.handler,
            ResidentProxyProtocolPlan::ShadowsocksAeadTcp { salt_len: 16, .. }
        ));

        let trojan = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "trojan_live".to_owned(),
            "trojan://matrix-trojan-pass@203.0.113.10:28444?sni=office.example#trojan".to_owned(),
        )
        .unwrap();
        assert_eq!(trojan.protocol, "trojan");
        assert_eq!(trojan.server_host, "203.0.113.10");
        assert_eq!(trojan.server_port, 28444);
        assert_eq!(trojan.server_name, "office.example");
        assert_eq!(trojan.tls, "tls");
        assert!(matches!(
            trojan.handler,
            ResidentProxyProtocolPlan::TrojanTcpTls { .. }
        ));

        let anytls = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "anytls_live".to_owned(),
            "anytls://matrix-anytls-pass@203.0.113.10:28451?sni=office.example#anytls".to_owned(),
        )
        .unwrap();
        assert_eq!(anytls.protocol, "anytls");
        assert_eq!(anytls.server_host, "203.0.113.10");
        assert_eq!(anytls.server_port, 28451);
        assert_eq!(anytls.server_name, "office.example");
        assert_eq!(anytls.tls, "tls");
        assert!(matches!(
            anytls.handler,
            ResidentProxyProtocolPlan::AnyTlsTcpTls { .. }
        ));

        let vmess = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_live".to_owned(),
            "vmess://eyJ2IjoiMiIsInBzIjoidm1lc3MiLCJhZGQiOiIyMDMuMC4xMTMuMTAiLCJwb3J0IjoiMjg0NTIiLCJpZCI6IjAxMjM0NTY3LTg5YWItY2RlZi0wMTIzLTQ1Njc4OWFiY2RlZiIsImFpZCI6IjAiLCJuZXQiOiJ0Y3AiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiIiLCJwYXRoIjoiIiwidGxzIjoiIn0=".to_owned(),
        )
        .unwrap();
        assert_eq!(vmess.protocol, "vmess");
        assert_eq!(vmess.server_host, "203.0.113.10");
        assert_eq!(vmess.server_port, 28452);
        assert_eq!(vmess.tls, "none");
        assert!(matches!(
            vmess.handler,
            ResidentProxyProtocolPlan::VmessAeadTcp { .. }
        ));

        let hysteria2 = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "hy2_live".to_owned(),
            "hy2://matrix-hy2-auth@203.0.113.10:28453?sni=office.example&pinSHA256=AA-BB-CC#hy2"
                .to_owned(),
        )
        .unwrap();
        assert_eq!(hysteria2.protocol, "hysteria2");
        assert_eq!(hysteria2.server_host, "203.0.113.10");
        assert_eq!(hysteria2.server_port, 28453);
        assert_eq!(hysteria2.server_name, "office.example");
        assert_eq!(hysteria2.net, "udp");
        assert_eq!(hysteria2.tls, "quic");
        assert!(matches!(
            hysteria2.handler,
            ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. }
        ));

        let tuic = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "tuic_live".to_owned(),
            "tuic://01234567-89ab-cdef-0123-456789abcdef:matrix-tuic-pass@203.0.113.10:28454?allow_insecure=1&sni=office.example&alpn=h3#tuic"
                .to_owned(),
        )
        .unwrap();
        assert_eq!(tuic.protocol, "tuic");
        assert_eq!(tuic.server_host, "203.0.113.10");
        assert_eq!(tuic.server_port, 28454);
        assert_eq!(tuic.server_name, "office.example");
        assert_eq!(tuic.net, "udp");
        assert_eq!(tuic.tls, "quic");
        assert!(matches!(
            tuic.handler,
            ResidentProxyProtocolPlan::TuicQuicTcp { .. }
        ));

        let juicity = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "juicity_live".to_owned(),
            "juicity://01234567-89ab-cdef-0123-456789abcdef:matrix-juicity-pass@203.0.113.10:28455?allow_insecure=1&sni=office.example#juicity"
                .to_owned(),
        )
        .unwrap();
        assert_eq!(juicity.protocol, "juicity");
        assert_eq!(juicity.server_host, "203.0.113.10");
        assert_eq!(juicity.server_port, 28455);
        assert_eq!(juicity.server_name, "office.example");
        assert_eq!(juicity.net, "udp");
        assert_eq!(juicity.tls, "quic");
        assert!(matches!(
            juicity.handler,
            ResidentProxyProtocolPlan::JuicityQuicTcp { .. }
        ));
    }

    #[test]
    fn resident_dataplane_plan_keeps_first_batch_unsupported_shapes_blocked() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        routing {
        fallback: direct
        }
        "#,
        );
        let https = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "https_live".to_owned(),
            "https://matrix:matrix-http-pass@203.0.113.10:28448#https".to_owned(),
        )
        .unwrap_err();
        assert!(https.contains("plain http proxy endpoints only"));

        let plugin = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "ss_plugin".to_owned(),
            "ss://aes-128-gcm:matrix-ss-pass@203.0.113.10:28446?plugin=simple-obfs%3Bobfs%3Dhttp#ss-plugin".to_owned(),
        )
        .unwrap_err();
        assert!(plugin.contains("does not admit SIP003 plugin"));

        let trojan_go = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "trojan_go".to_owned(),
            "trojan-go://matrix-trojan-pass@203.0.113.10:28444?type=ws&sni=office.example#trojan-go".to_owned(),
        )
        .unwrap_err();
        assert!(trojan_go.contains("admits only plain trojan endpoints"));

        let anytls_insecure = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "anytls_insecure".to_owned(),
            "anytls://matrix-anytls-pass@203.0.113.10:28451?insecure=1&sni=office.example#anytls"
                .to_owned(),
        )
        .unwrap_err();
        assert!(anytls_insecure.contains("does not admit AnyTLS insecure mode"));

        let vmess_tls = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_tls".to_owned(),
            "vmess://eyJ2IjoiMiIsInBzIjoidm1lc3MtdGxzIiwiYWRkIjoiMjAzLjAuMTEzLjEwIiwicG9ydCI6IjI4NDUyIiwiaWQiOiIwMTIzNDU2Ny04OWFiLWNkZWYtMDEyMy00NTY3ODlhYmNkZWYiLCJhaWQiOiIwIiwibmV0IjoidGNwIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6InRscyJ9".to_owned(),
        )
        .unwrap_err();
        assert!(vmess_tls.contains("admits only plain VMess TCP endpoints"));

        let hy2_no_pin = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "hy2_no_pin".to_owned(),
            "hy2://matrix-hy2-auth@203.0.113.10:28453?sni=office.example#hy2".to_owned(),
        )
        .unwrap_err();
        assert!(hy2_no_pin.contains("requires Hysteria2 pinSHA256"));

        let hy2_hopping = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "hy2_hopping".to_owned(),
            "hy2://matrix-hy2-auth@example.com:443,8443-8445?sni=office.example&pinSHA256=AA-BB-CC#hy2"
                .to_owned(),
        )
        .unwrap_err();
        assert!(hy2_hopping.contains("single-port Hysteria2 endpoints"));

        let tuic_without_insecure = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "tuic_without_insecure".to_owned(),
            "tuic://01234567-89ab-cdef-0123-456789abcdef:matrix-tuic-pass@203.0.113.10:28454?sni=office.example&alpn=h3#tuic"
                .to_owned(),
        )
        .unwrap_err();
        assert!(tuic_without_insecure.contains("allow_insecure is explicit"));

        let juicity_without_verification = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "juicity_without_verification".to_owned(),
            "juicity://01234567-89ab-cdef-0123-456789abcdef:matrix-juicity-pass@203.0.113.10:28455?sni=office.example#juicity"
                .to_owned(),
        )
        .unwrap_err();
        assert!(
            juicity_without_verification
                .contains("requires Juicity allow_insecure or pinned_certchain_sha256")
        );
    }

    #[test]
    fn resident_dataplane_plan_builds_proxy_by_outbound_index() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        dial_mode: domain++
        }
        node {
        hk: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=hk.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        us: 'vless://01234567-89ab-cdef-0123-456789abcdef@203.0.113.2:443?security=tls&type=tcp&sni=us.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(hk)
            policy: fixed(0)
        }
        openai {
            filter: name(us)
            policy: fixed(0)
        }
        }
        routing {
        domain(suffix: googleapis.com) -> openai
        fallback: proxy
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        assert!(plan.enabled);
        assert_eq!(plan.tcp_dial_mode, TcpDialMode::DomainPlusPlus);
        let proxy = plan
            .proxies
            .get(&2)
            .unwrap()
            .default_proxy_snapshot()
            .unwrap();
        let openai = plan
            .proxies
            .get(&3)
            .unwrap()
            .default_proxy_snapshot()
            .unwrap();
        assert_eq!(proxy.group_name, "proxy");
        assert_eq!(proxy.node_tag, "hk");
        assert_eq!(openai.group_name, "openai");
        assert_eq!(openai.node_tag, "us");
    }

    #[test]
    fn resident_dataplane_plan_rejects_vless_without_vision_flow() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains("admits only flow=xtls-rprx-vision"));
        assert!(err.contains("keep Go outbound"));
    }

    #[test]
    fn resident_dataplane_plan_resolves_link_fingerprint_before_wire_gate() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        tls_implementation: utls
        utls_imitate: safari
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=firefox_105&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "link fp");
        assert_eq!(utls.requested, "firefox_105");
        assert_eq!(utls.name, "firefox_105");
        assert_eq!(utls.family, "firefox");
    }

    #[test]
    fn resident_dataplane_plan_carries_generic_link_fingerprint() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=safari_16_0&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        assert!(plan.enabled);
        assert_eq!(proxy.node_tag, "vless_live");
        assert_eq!(proxy.flow, XTLS_RPRX_VISION);
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "link fp");
        assert_eq!(utls.requested, "safari_16_0");
        assert_eq!(utls.family, "safari");
    }

    #[test]
    fn resident_dataplane_plan_keeps_standard_tls_when_link_omits_fp_and_global_tls() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        assert!(proxy.utls_fingerprint.is_none());
    }

    #[test]
    fn resident_dataplane_plan_keeps_standard_tls_when_link_fp_is_empty_and_global_tls() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        assert!(proxy.utls_fingerprint.is_none());
    }

    #[test]
    fn resident_dataplane_plan_keeps_document_unsafe_auxiliary_rustls_path() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=unsafe&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        assert!(proxy.utls_fingerprint.is_none());
    }

    #[test]
    fn resident_dataplane_plan_uses_global_utls_when_link_does_not_set_fp() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        tls_implementation: utls
        utls_imitate: safari
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "global utls_imitate");
        assert_eq!(utls.requested, "safari");
        assert_eq!(utls.canonical, "safari_auto");
        assert_eq!(utls.family, "safari");
    }

    #[test]
    fn resident_dataplane_plan_uses_global_utls_when_link_fp_is_empty() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        tls_implementation: utls
        utls_imitate: edge
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "global utls_imitate");
        assert_eq!(utls.requested, "edge");
        assert_eq!(utls.canonical, "edge_auto");
        assert_eq!(utls.family, "edge");
    }

    #[test]
    fn resident_dataplane_plan_uses_document_default_when_global_utls_has_empty_imitate() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        tls_implementation: utls
        utls_imitate: ""
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "default fingerprint");
        assert_eq!(utls.requested, "chrome");
        assert_eq!(utls.canonical, "chrome_auto");
        assert_eq!(utls.family, "chrome");
    }

    #[test]
    fn resident_dataplane_plan_rejects_unknown_utls_fingerprint() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=Chrome&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains("unsupported link fp Chrome"));
        assert!(err.contains("unknown uTLS Client Hello ID: Chrome"));
    }

    #[test]
    fn resident_dataplane_plan_rejects_non_document_no_fingerprint_aliases() {
        for value in ["no", "none", "off", "false", "0"] {
            let config = parse_config(&format!(
                r#"
        global {{
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }}
        node {{
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp={value}&alpn=h2,http/1.1'
        }}
        group {{
        proxy {{
            filter: name(vless_live)
            policy: fixed(0)
        }}
        }}
        routing {{
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }}
        "#
            ));
            let err = build_resident_dataplane_plan(&config).unwrap_err();
            assert!(err.contains(&format!("unsupported link fp {value}")));
            assert!(err.contains(&format!("unknown uTLS Client Hello ID: {value}")));
        }
    }

    #[test]
    fn resident_utls_fingerprint_resolution_uses_generic_registry() {
        for (name, canonical, family) in [
            ("chrome", "chrome_auto", "chrome"),
            ("firefox_105", "firefox_105", "firefox"),
            ("safari_16_0", "safari_16_0", "safari"),
            ("ios_14", "ios_14", "ios"),
            ("edge_106", "edge_106", "edge"),
            ("android_11_okhttp", "android_11_okhttp", "android"),
            ("randomizednoalpn", "randomizednoalpn", "random"),
        ] {
            let plan = resolve_resident_utls_fingerprint("test", name).unwrap();
            assert_eq!(plan.name, name);
            assert_eq!(plan.canonical, canonical);
            assert_eq!(plan.family, family);
        }

        let randomized_no_alpn =
            resolve_resident_utls_fingerprint("test", "randomizednoalpn").unwrap();
        assert!(randomized_no_alpn.randomized);
        assert_eq!(randomized_no_alpn.alpn_policy, "force-no-alpn");
    }
}
