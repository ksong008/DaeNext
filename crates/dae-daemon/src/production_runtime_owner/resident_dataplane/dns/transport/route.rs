use super::super::*;
use super::ResidentDnsTransportError;
use futures_util::{StreamExt, stream::FuturesUnordered};

pub(super) async fn resolved_upstream_targets(
    upstream: &ResidentDnsUpstream,
) -> Result<ResidentDnsResolvedTargetSnapshot, String> {
    upstream.target.resolve_addrs().await
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsUpstreamCandidate
{
    pub(in crate::production_runtime_owner::resident_dataplane::dns) target: SocketAddr,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) l4proto: L4Proto,
}

#[derive(Clone, Debug)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsUpstreamRoutedTarget
{
    pub(in crate::production_runtime_owner::resident_dataplane::dns) target: SocketAddr,
    // Retained in the routed value so mixed TCP/UDP candidate plans preserve
    // the exact transport chosen during selection, even though current
    // single-transport executors already know it from their call site.
    #[allow(dead_code)]
    pub(in crate::production_runtime_owner::resident_dataplane::dns) l4proto: L4Proto,
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
            l4proto: self.requested_network_type.l4proto,
            selection: self.selection,
        }
    }
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) fn dns_upstream_candidates_for_l4protos(
    targets: &[SocketAddr],
    l4protos: &[L4Proto],
) -> Vec<ResidentDnsUpstreamCandidate> {
    let mut candidates = Vec::with_capacity(targets.len().saturating_mul(l4protos.len()));
    for l4proto in l4protos {
        for target in targets {
            candidates.push(ResidentDnsUpstreamCandidate {
                target: *target,
                l4proto: *l4proto,
            });
        }
    }
    candidates
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) fn select_dns_upstream_targets(
    plan: &ResidentDnsPlan,
    upstream: &ResidentDnsUpstream,
    targets: Vec<SocketAddr>,
    l4proto: L4Proto,
) -> Result<(Vec<ResidentDnsUpstreamRoutedTarget>, Vec<String>), String> {
    select_dns_upstream_candidates(
        plan,
        upstream,
        dns_upstream_candidates_for_l4protos(&targets, &[l4proto]),
    )
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) fn select_dns_upstream_candidates(
    plan: &ResidentDnsPlan,
    upstream: &ResidentDnsUpstream,
    candidates: Vec<ResidentDnsUpstreamCandidate>,
) -> Result<(Vec<ResidentDnsUpstreamRoutedTarget>, Vec<String>), String> {
    let mut failures = Vec::new();
    let mut routed_candidates = Vec::new();
    for (order, candidate) in candidates.into_iter().enumerate() {
        match select_dns_upstream_route_candidate(
            plan,
            upstream,
            candidate.target,
            candidate.l4proto,
            order,
        ) {
            Ok(candidate) => routed_candidates.push(candidate),
            Err(err) => failures.push(format!(
                "{} {}: {err}",
                candidate.target,
                candidate.l4proto.as_str()
            )),
        }
    }
    routed_candidates.sort_by(compare_dns_upstream_route_candidates);
    let routed = routed_candidates
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
    match left.latency_ms.cmp(&right.latency_ms) {
        std::cmp::Ordering::Equal => {}
        ordering => return ordering,
    }
    match (
        left.target_family_matches_selection(),
        right.target_family_matches_selection(),
    ) {
        (true, false) => return std::cmp::Ordering::Less,
        (false, true) => return std::cmp::Ordering::Greater,
        _ => {}
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

pub(super) async fn race_dns_upstream_targets<F, Fut>(
    upstream: &ResidentDnsUpstream,
    resolved: &ResidentDnsResolvedTargetSnapshot,
    operation: &str,
    targets: Vec<ResidentDnsUpstreamRoutedTarget>,
    mut failures: Vec<String>,
    width: usize,
    attempt: F,
) -> Result<Vec<u8>, ResidentDnsTransportError>
where
    F: Fn(ResidentDnsUpstreamRoutedTarget) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, ResidentDnsTransportError>>,
{
    let preserve_single_truncated_error = targets.len() == 1 && failures.is_empty();
    let mut remaining = targets.into_iter();
    let mut attempts = FuturesUnordered::new();
    let mut attempted = 0_usize;
    let mut every_attempt_invalidates_stale = true;
    let mut single_truncated_error = None;
    for _ in 0..width.max(1) {
        let Some(target) = remaining.next() else {
            break;
        };
        attempts.push(attempt(target));
    }
    while let Some(result) = attempts.next().await {
        match result {
            Ok(response) => return Ok(response),
            Err(error) => {
                if !error.allows_next_candidate() {
                    return Err(error);
                }
                attempted += 1;
                every_attempt_invalidates_stale &= error.invalidates_stale_target();
                if preserve_single_truncated_error && error.is_udp_truncated() {
                    single_truncated_error = Some(error);
                } else {
                    failures.push(error.to_string());
                }
            }
        }
        if let Some(target) = remaining.next() {
            attempts.push(attempt(target));
        }
    }
    if attempted > 0 && every_attempt_invalidates_stale && resolved.is_stale() {
        let _ = upstream.target.refresh_after_stale_failure(resolved).await;
    }
    if let Some(error) = single_truncated_error {
        return Err(error);
    }
    Err(ResidentDnsTransportError::message(
        dns_upstream_targets_failed(upstream, operation, failures),
    ))
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
    use std::time::Duration;

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

    fn test_upstream() -> ResidentDnsUpstream {
        ResidentDnsUpstream {
            index: 0,
            tag: "candidate-race".to_owned(),
            target: ResidentDnsUpstreamTarget {
                authority: "candidate-race.invalid:53".to_owned(),
                host: "candidate-race.invalid".to_owned(),
                port: DNS_DEFAULT_PORT,
                literal_addr: None,
                fallback_resolver: dns_upstream_target_v4(),
                resolver_mark: 0,
                resolved_addrs: Arc::default(),
            },
            scheme: ResidentDnsUpstreamScheme::Udp,
            path: String::new(),
        }
    }

    #[test]
    fn direct_route_candidates_keep_resolved_order() {
        let mut candidates = [
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
    fn proxy_route_candidates_prefer_latency_then_matching_family() {
        let mut candidates = [
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
            vec![0, 2, 1]
        );
    }

    #[test]
    fn proxy_route_candidates_use_matching_family_as_tie_breaker() {
        let mut candidates = [
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
                10,
            ),
        ];

        candidates.sort_by(compare_dns_upstream_route_candidates);

        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.order)
                .collect::<Vec<_>>(),
            vec![1, 0]
        );
    }

    #[tokio::test]
    async fn upstream_candidate_race_does_not_wait_for_an_earlier_blackhole() {
        let blackhole = dns_upstream_target_v4();
        let healthy = dns_upstream_target_v6();
        let targets = vec![
            ResidentDnsUpstreamRoutedTarget {
                target: blackhole,
                l4proto: L4Proto::Udp,
                selection: ResidentDnsUpstreamSelection::Direct { mark: 0 },
            },
            ResidentDnsUpstreamRoutedTarget {
                target: healthy,
                l4proto: L4Proto::Udp,
                selection: ResidentDnsUpstreamSelection::Direct { mark: 0 },
            },
        ];
        let upstream = test_upstream();
        let resolved = ResidentDnsResolvedTargetSnapshot::literal(blackhole);
        let response = time::timeout(
            Duration::from_millis(100),
            race_dns_upstream_targets(
                &upstream,
                &resolved,
                "race DNS fixture",
                targets,
                Vec::new(),
                2,
                move |target| async move {
                    if target.target == blackhole {
                        std::future::pending::<Result<Vec<u8>, ResidentDnsTransportError>>().await
                    } else {
                        time::sleep(Duration::from_millis(5)).await;
                        Ok(vec![0x12, 0x34, 0x81, 0x80])
                    }
                },
            ),
        )
        .await
        .expect("healthy DNS candidate waited for an earlier blackhole")
        .unwrap();

        assert_eq!(response, vec![0x12, 0x34, 0x81, 0x80]);
    }
}
