use super::*;
use dae_routing::RoutingMatcher;
use std::collections::HashSet;

pub struct ResidentPreparedDataplane {
    pub(crate) plan: ResidentDataplanePlan,
    pub(crate) routing_matcher: RoutingMatcher,
    pub(crate) protocol_owner_specs: ResidentProtocolOwnerSpecs,
}
#[derive(Clone, Debug)]
pub(crate) struct ResidentDataplanePlan {
    pub(crate) enabled: bool,
    pub(crate) unsupported_reason: Option<String>,
    pub(crate) proxies: BTreeMap<u8, ResidentProxyGroupPlan>,
    pub(crate) default_outbound: Option<u8>,
    pub(crate) tcp_dial_mode: TcpDialMode,
    pub(crate) sniffing_timeout: Duration,
    pub(crate) dns: ResidentDnsPlan,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ResidentProtocolOwnerSpecs {
    pub(crate) hysteria2: bool,
    pub(crate) tuic: bool,
    pub(crate) juicity: bool,
    pub(crate) anytls: bool,
    pub(crate) h2_carrier: bool,
    pub(crate) meek: bool,
    pub(crate) vless_mux: bool,
    pub(crate) xhttp_xmux: bool,
}

impl ResidentDataplanePlan {
    pub(crate) fn default_proxy_group(&self) -> Option<&ResidentProxyGroupPlan> {
        self.default_outbound
            .and_then(|outbound| self.proxies.get(&outbound))
    }

    pub(crate) fn default_proxy_snapshot(&self) -> Option<Arc<ResidentProxyPlan>> {
        self.default_proxy_binding()
            .map(ResidentProxyBinding::into_shared_plan)
    }

    pub(crate) fn default_proxy_binding(&self) -> Option<ResidentProxyBinding> {
        self.default_proxy_group()
            .and_then(ResidentProxyGroupPlan::default_proxy_snapshot)
    }

    pub(crate) fn protocol_owner_specs(&self) -> ResidentProtocolOwnerSpecs {
        ResidentProtocolOwnerSpecs {
            hysteria2: self
                .proxies
                .values()
                .any(ResidentProxyGroupPlan::requires_hysteria2_owner),
            tuic: self
                .proxies
                .values()
                .any(ResidentProxyGroupPlan::requires_tuic_transport_owner),
            juicity: self
                .proxies
                .values()
                .any(ResidentProxyGroupPlan::requires_juicity_transport_owner),
            anytls: self
                .proxies
                .values()
                .any(ResidentProxyGroupPlan::requires_anytls_transport_owner),
            h2_carrier: self
                .proxies
                .values()
                .any(ResidentProxyGroupPlan::requires_h2_carrier_owner),
            meek: self
                .proxies
                .values()
                .any(ResidentProxyGroupPlan::requires_meek_transport_owner),
            vless_mux: self
                .proxies
                .values()
                .any(ResidentProxyGroupPlan::requires_vless_mux_owner),
            xhttp_xmux: self
                .proxies
                .values()
                .any(ResidentProxyGroupPlan::requires_xhttp_xmux_owner),
        }
    }
}

pub(crate) fn build_resident_dataplane_plan(
    config: &Config,
) -> Result<ResidentDataplanePlan, String> {
    let geodata = ResidentGeodataStore::new(Vec::<PathBuf>::new());
    build_resident_dataplane_plan_with_geodata(config, &geodata)
}

pub(crate) fn build_resident_dataplane_plan_with_geodata(
    config: &Config,
    geodata: &ResidentGeodataStore,
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
    let dns = build_resident_dns_plan_with_refresh_interval(
        config,
        geodata,
        ResidentRuntimeResourceConfig::from_config(config).dns_upstream_refresh_interval(),
    )?;
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

pub fn build_resident_prepared_dataplane_with_geodata(
    config: &Config,
    geodata: &ResidentGeodataStore,
) -> Result<ResidentPreparedDataplane, String> {
    let plan = build_resident_dataplane_plan_with_geodata(config, geodata)?;
    let protocol_owner_specs = plan.protocol_owner_specs();
    let routing_matcher =
        crate::host_routing_plan::build_resident_userspace_routing_matcher_with_geodata(
            config, geodata,
        )?;
    Ok(ResidentPreparedDataplane {
        plan,
        routing_matcher,
        protocol_owner_specs,
    })
}

#[cfg(test)]
pub(crate) fn build_resident_manual_probe_plans(
    config: &Config,
) -> BTreeMap<String, Result<ResidentProxyProbePlan, String>> {
    let profile = manual_probe_profile(config);
    let mut plans = BTreeMap::new();
    for (node_tag, link) in tagged_node_links(config) {
        let plan = profile
            .as_ref()
            .map_err(|error| error.clone())
            .and_then(|profile| {
                build_resident_manual_probe_plan_with_profile(
                    config,
                    node_tag,
                    link.clone(),
                    Arc::clone(profile),
                )
            });
        plans.entry(link).or_insert(plan);
    }
    plans
}

pub(crate) fn build_resident_manual_probe_plans_for_helper(
    config: &Config,
    requested_links: &[String],
) -> BTreeMap<String, Result<ResidentProxyProbePlan, String>> {
    let profile = manual_probe_profile(config);
    let requested = requested_links
        .iter()
        .filter(|link| !link.is_empty())
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut plans = BTreeMap::new();
    for (node_tag, link) in tagged_node_links(config) {
        if !requested.contains(link.as_str()) {
            continue;
        }
        let plan = profile
            .as_ref()
            .map_err(|error| error.clone())
            .and_then(|profile| {
                build_resident_manual_probe_plan_with_profile(
                    config,
                    node_tag,
                    link.clone(),
                    Arc::clone(profile),
                )
            });
        plans.entry(link).or_insert(plan);
    }
    for link in requested_links.iter().filter(|link| !link.is_empty()) {
        if plans.contains_key(link.as_str()) {
            continue;
        }
        let node_tag = format!("manual_probe_{}", execution_link_hash(link));
        let plan = profile
            .as_ref()
            .map_err(|error| error.clone())
            .and_then(|profile| {
                build_resident_manual_probe_plan_with_profile(
                    config,
                    node_tag,
                    link.clone(),
                    Arc::clone(profile),
                )
            });
        plans.insert(link.clone(), plan);
    }
    for plan in plans.values_mut().filter_map(|plan| plan.as_mut().ok()) {
        plan.apply_latency_probe_control_mark(RESIDENT_CONTROL_PLANE_SO_MARK);
    }
    plans
}

fn manual_probe_profile(config: &Config) -> Result<Arc<ResidentProbeProfile>, String> {
    let group_name = "__manual_native_probe".to_owned();
    let group = Group {
        name: group_name,
        filter: Vec::new(),
        filter_annotation: Vec::new(),
        policy: DynamicFunctionValue::Nil,
        tcp_check_url: None,
        tcp_check_http_method: String::new(),
        udp_check_dns: None,
        check_interval: Default::default(),
        check_tolerance: Default::default(),
    };
    Ok(Arc::new(ResidentProbeProfile::new(
        group_tcp_check_plan(config, &group)?,
        group_udp_check_plan(config, &group)?,
        resident_tcp_latency_probe_timeout_from_config(config),
    )))
}

fn build_resident_manual_probe_plan_with_profile(
    config: &Config,
    node_tag: String,
    link: String,
    profile: Arc<ResidentProbeProfile>,
) -> Result<ResidentProxyProbePlan, String> {
    let mut proxy = build_proxy_plan(
        config,
        "__manual_native_probe".to_owned(),
        node_tag.clone(),
        link.clone(),
    )?;
    proxy.group_policy = "manual_probe".to_owned();
    proxy.compact_allocations();
    Ok(ResidentProxyProbePlan::new(
        node_tag,
        link_hash(&link),
        execution_link_hash(&link),
        redacted_link_source(&link),
        profile,
        ResidentProxyBinding::configuration(Arc::new(proxy))?.without_persistent_xhttp_reuse(),
    ))
}

pub(crate) fn resident_proxy_plans(
    config: &Config,
    node_links: &BTreeMap<String, String>,
) -> Result<(BTreeMap<u8, ResidentProxyGroupPlan>, Option<u8>), String> {
    let mut proxies = BTreeMap::new();
    let mut default_outbound = None;
    for outbound in referenced_user_outbounds(config) {
        if node_links.contains_key(&outbound) {
            return Err(format!(
                "resident dataplane cannot assign direct node outbound {outbound} to a stable compatible outbound index; put the node behind a group before enabling Rust resident dataplane",
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
        let outbound_index = OutboundIndex::try_from_user_offset(group_index)
            .map_err(|err| format!("resident dataplane group {}: {err}", group.name))?
            .value();
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
            proxy.compact_allocations();
            candidates.push(ResidentProxyCandidatePlan {
                match_index: node.match_index,
                annotation_add_latency_ms: node.annotation_add_latency_ms,
                link_hash: link_hash(&link),
                execution_identity: execution_link_hash(&link),
                redacted_link_source: redacted_link_source(&link),
                link,
                binding: ResidentProxyBinding::configuration(Arc::new(proxy))?,
                data_udp_observation: Arc::new(ResidentDataUdpObservation::default()),
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
        let admitted_candidate_count = candidates.len();
        let probe_profile = Arc::new(ResidentProbeProfile::new(
            group_tcp_check_plan(config, group)?,
            group_udp_check_plan(config, group)?,
            resident_tcp_health_probe_timeout(),
        ));
        let probe_candidates = share_group_probe_plans(&candidates, Arc::clone(&probe_profile));
        let mut candidate_index_by_node_tag =
            std::collections::HashMap::with_capacity(candidates.len());
        for (index, candidate) in candidates.iter().enumerate() {
            candidate_index_by_node_tag
                .entry(candidate.binding.plan().node_tag.clone())
                .or_insert(index);
        }
        let group_plan = ResidentProxyGroupPlan {
            group_name: group.name.clone(),
            group_policy,
            matched_candidate_count,
            selector: Arc::new(std::sync::RwLock::new(selector)),
            candidates,
            candidate_index_by_node_tag: Arc::new(candidate_index_by_node_tag),
            check_interval: group_check_interval(config, group),
            probe_profile,
            probe_candidates,
            resuscitation_last_unix_ms: Arc::new(
                (0..NETWORK_TYPE_COLLECTION_COUNT)
                    .map(|_| AtomicI64::new(0))
                    .collect(),
            ),
            health_bootstrap: ResidentGroupHealthBootstrap::new(admitted_candidate_count),
        };
        default_outbound.get_or_insert(outbound_index);
        proxies.insert(outbound_index, group_plan);
    }
    Ok((proxies, default_outbound))
}
