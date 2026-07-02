use super::*;
#[derive(Clone, Debug)]
pub(crate) struct ResidentDataplanePlan {
    pub(in crate::production_runtime_owner::resident_dataplane) enabled: bool,
    pub(in crate::production_runtime_owner::resident_dataplane) unsupported_reason: Option<String>,
    pub(in crate::production_runtime_owner::resident_dataplane) proxies:
        BTreeMap<u8, ResidentProxyGroupPlan>,
    pub(in crate::production_runtime_owner::resident_dataplane) default_outbound: Option<u8>,
    pub(in crate::production_runtime_owner::resident_dataplane) tcp_dial_mode: TcpDialMode,
    pub(in crate::production_runtime_owner::resident_dataplane) sniffing_timeout: Duration,
    pub(in crate::production_runtime_owner::resident_dataplane) dns: ResidentDnsPlan,
}

impl ResidentDataplanePlan {
    pub(in crate::production_runtime_owner::resident_dataplane) fn default_proxy_group(
        &self,
    ) -> Option<&ResidentProxyGroupPlan> {
        self.default_outbound
            .and_then(|outbound| self.proxies.get(&outbound))
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn default_proxy_snapshot(
        &self,
    ) -> Option<ResidentProxyPlan> {
        self.default_proxy_group()
            .and_then(ResidentProxyGroupPlan::default_proxy_snapshot)
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
    let dns = build_resident_dns_plan(config, geodata)?;
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

pub(crate) fn build_resident_manual_probe_plans(
    config: &Config,
) -> BTreeMap<String, Result<ResidentProxyProbePlan, String>> {
    let mut plans = BTreeMap::new();
    for (node_tag, link) in tagged_node_links(config) {
        let plan = build_resident_manual_probe_plan(config, node_tag, link.clone());
        plans.entry(link).or_insert(plan);
    }
    plans
}

pub(crate) fn build_resident_manual_probe_plans_for_helper(
    config: &Config,
) -> BTreeMap<String, Result<ResidentProxyProbePlan, String>> {
    let mut plans = build_resident_manual_probe_plans(config);
    for plan in plans.values_mut().filter_map(|plan| plan.as_mut().ok()) {
        plan.apply_latency_probe_control_mark(RESIDENT_CONTROL_PLANE_SO_MARK);
    }
    plans
}

pub(crate) fn build_resident_manual_probe_plan(
    config: &Config,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyProbePlan, String> {
    let group_name = "__manual_native_probe".to_owned();
    let mut proxy = build_proxy_plan(config, group_name.clone(), node_tag.clone(), link.clone())?;
    proxy.group_policy = "manual_probe".to_owned();
    proxy.disable_latency_probe_persistent_caches();
    proxy.compact_allocations();
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
    Ok(ResidentProxyProbePlan {
        node_tag,
        link_hash: link_hash(&link),
        redacted_link_source: redacted_link_source(&link),
        link,
        tcp_check: group_tcp_check_plan(config, &group)?,
        udp_check: group_udp_check_plan(config, &group)?,
        tcp_probe_timeout: resident_tcp_latency_probe_timeout_from_config(config),
        proxy: Arc::new(proxy),
    })
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
            proxy.compact_allocations();
            candidates.push(ResidentProxyCandidatePlan {
                match_index: node.match_index,
                annotation_add_latency_ms: node.annotation_add_latency_ms,
                link_hash: link_hash(&link),
                redacted_link_source: redacted_link_source(&link),
                link,
                proxy: Arc::new(proxy),
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
            tcp_probe_timeout: resident_tcp_latency_probe_timeout_from_config(config),
        };
        default_outbound.get_or_insert(outbound_index);
        proxies.insert(outbound_index, group_plan);
    }
    Ok((proxies, default_outbound))
}
