use super::super::*;

pub(super) async fn resolved_upstream_targets(
    upstream: &ResidentDnsUpstream,
) -> Result<Vec<SocketAddr>, String> {
    upstream.target.resolve_addrs().await
}

#[derive(Clone, Debug)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsUpstreamRoutedTarget
{
    pub(in crate::production_runtime_owner::resident_dataplane::dns) target: SocketAddr,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) selection:
        ResidentDnsUpstreamSelection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ResidentDnsUpstreamRouteKind {
    Direct,
    Proxy,
}

#[derive(Clone, Debug)]
struct ResidentDnsUpstreamRouteCandidate {
    order: usize,
    target: SocketAddr,
    selection: ResidentDnsUpstreamSelection,
    route_kind: ResidentDnsUpstreamRouteKind,
    requested_network_type: NetworkType,
    selected_network_type: NetworkType,
    latency_ms: i64,
}

impl ResidentDnsUpstreamRouteCandidate {
    fn target_family_matches_selection(&self) -> bool {
        self.requested_network_type.ipversion == self.selected_network_type.ipversion
    }

    fn into_routed_target(self) -> ResidentDnsUpstreamRoutedTarget {
        ResidentDnsUpstreamRoutedTarget {
            target: self.target,
            selection: self.selection,
        }
    }
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) fn select_dns_upstream_targets(
    plan: &ResidentDnsPlan,
    upstream: &ResidentDnsUpstream,
    targets: Vec<SocketAddr>,
    l4proto: L4Proto,
) -> Result<(Vec<ResidentDnsUpstreamRoutedTarget>, Vec<String>), String> {
    let mut failures = Vec::new();
    let mut candidates = Vec::new();
    for (order, target) in targets.into_iter().enumerate() {
        match select_dns_upstream_route_candidate(plan, upstream, target, l4proto, order) {
            Ok(candidate) => candidates.push(candidate),
            Err(err) => failures.push(format!("{target}: {err}")),
        }
    }
    candidates.sort_by(compare_dns_upstream_route_candidates);
    let routed = candidates
        .into_iter()
        .map(ResidentDnsUpstreamRouteCandidate::into_routed_target)
        .collect::<Vec<_>>();
    if routed.is_empty() {
        return Err(dns_upstream_targets_failed(
            upstream,
            "select DNS upstream target for",
            failures,
        ));
    }
    Ok((routed, failures))
}

fn select_dns_upstream_route_candidate(
    plan: &ResidentDnsPlan,
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    l4proto: L4Proto,
    order: usize,
) -> Result<ResidentDnsUpstreamRouteCandidate, String> {
    let requested_network_type = dns_upstream_proxy_network_type(target, l4proto);
    let Some(router) = plan.upstream_router.as_ref() else {
        return Ok(ResidentDnsUpstreamRouteCandidate {
            order,
            target,
            selection: ResidentDnsUpstreamSelection::Direct { mark: plan.mark },
            route_kind: ResidentDnsUpstreamRouteKind::Direct,
            requested_network_type,
            selected_network_type: requested_network_type,
            latency_ms: 0,
        });
    };
    let selected = router.select_candidate(upstream, target, l4proto, requested_network_type)?;
    let route_kind = match &selected.selection {
        ResidentDnsUpstreamSelection::Direct { .. } => ResidentDnsUpstreamRouteKind::Direct,
        ResidentDnsUpstreamSelection::Proxy { .. } => ResidentDnsUpstreamRouteKind::Proxy,
    };
    Ok(ResidentDnsUpstreamRouteCandidate {
        order,
        target,
        selection: selected.selection,
        route_kind,
        requested_network_type,
        selected_network_type: selected.network_type,
        latency_ms: selected.latency_ms,
    })
}

fn compare_dns_upstream_route_candidates(
    left: &ResidentDnsUpstreamRouteCandidate,
    right: &ResidentDnsUpstreamRouteCandidate,
) -> std::cmp::Ordering {
    if left.route_kind != ResidentDnsUpstreamRouteKind::Proxy
        || right.route_kind != ResidentDnsUpstreamRouteKind::Proxy
    {
        return left.order.cmp(&right.order);
    }
    match (
        left.target_family_matches_selection(),
        right.target_family_matches_selection(),
    ) {
        (true, false) => return std::cmp::Ordering::Less,
        (false, true) => return std::cmp::Ordering::Greater,
        _ => {}
    }
    if left.route_kind == ResidentDnsUpstreamRouteKind::Proxy
        && right.route_kind == ResidentDnsUpstreamRouteKind::Proxy
    {
        match left.latency_ms.cmp(&right.latency_ms) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    left.order.cmp(&right.order)
}

pub(super) fn dns_upstream_targets_failed(
    upstream: &ResidentDnsUpstream,
    operation: &str,
    failures: Vec<String>,
) -> String {
    let detail = if failures.is_empty() {
        "no target attempted".to_owned()
    } else {
        failures.join("; ")
    };
    format!(
        "{operation} upstream {} {} failed for all resolved targets: {detail}",
        upstream.tag, upstream.target.authority
    )
}

fn dns_upstream_proxy_network_type(target: SocketAddr, l4proto: L4Proto) -> NetworkType {
    match (l4proto, target.is_ipv6()) {
        (L4Proto::Tcp, false) => NetworkType::TCP4,
        (L4Proto::Tcp, true) => NetworkType::TCP6,
        (L4Proto::Udp, false) => NetworkType::DNS_UDP4,
        (L4Proto::Udp, true) => NetworkType::DNS_UDP6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route_candidate(
        order: usize,
        target: SocketAddr,
        route_kind: ResidentDnsUpstreamRouteKind,
        requested_network_type: NetworkType,
        selected_network_type: NetworkType,
        latency_ms: i64,
    ) -> ResidentDnsUpstreamRouteCandidate {
        ResidentDnsUpstreamRouteCandidate {
            order,
            target,
            selection: ResidentDnsUpstreamSelection::Direct { mark: 0 },
            route_kind,
            requested_network_type,
            selected_network_type,
            latency_ms,
        }
    }

    fn dns_upstream_target_v4() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DNS_DEFAULT_PORT)
    }

    fn dns_upstream_target_v6() -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), DNS_DEFAULT_PORT)
    }

    #[test]
    fn direct_route_candidates_keep_resolved_order() {
        let mut candidates = vec![
            route_candidate(
                0,
                dns_upstream_target_v4(),
                ResidentDnsUpstreamRouteKind::Proxy,
                NetworkType::DNS_UDP4,
                NetworkType::DNS_UDP6,
                10,
            ),
            route_candidate(
                1,
                dns_upstream_target_v6(),
                ResidentDnsUpstreamRouteKind::Direct,
                NetworkType::DNS_UDP6,
                NetworkType::DNS_UDP6,
                0,
            ),
        ];

        candidates.sort_by(compare_dns_upstream_route_candidates);

        assert_eq!(candidates[0].target, dns_upstream_target_v4());
        assert_eq!(candidates[1].target, dns_upstream_target_v6());
    }

    #[test]
    fn proxy_route_candidates_prefer_matching_family_then_latency() {
        let mut candidates = vec![
            route_candidate(
                0,
                dns_upstream_target_v4(),
                ResidentDnsUpstreamRouteKind::Proxy,
                NetworkType::DNS_UDP4,
                NetworkType::DNS_UDP6,
                10,
            ),
            route_candidate(
                1,
                dns_upstream_target_v6(),
                ResidentDnsUpstreamRouteKind::Proxy,
                NetworkType::DNS_UDP6,
                NetworkType::DNS_UDP6,
                30,
            ),
            route_candidate(
                2,
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), DNS_DEFAULT_PORT),
                ResidentDnsUpstreamRouteKind::Proxy,
                NetworkType::DNS_UDP6,
                NetworkType::DNS_UDP6,
                20,
            ),
        ];

        candidates.sort_by(compare_dns_upstream_route_candidates);

        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.order)
                .collect::<Vec<_>>(),
            vec![2, 1, 0]
        );
    }
}
