use super::super::*;
use super::ResidentDnsTransportError;
use crate::dns::upstream_model::ResidentDnsTargetRefreshError;
use futures_util::{StreamExt, stream::FuturesUnordered};

pub(super) async fn resolved_upstream_targets(
    upstream: &ResidentDnsUpstream,
    deadline: time::Instant,
) -> Result<ResidentDnsResolvedTargetSnapshot, String> {
    tokio::time::timeout_at(deadline, upstream.target.resolve_addrs())
        .await
        .map_err(|_| "DNS upstream target resolution deadline expired".to_owned())?
}

pub(super) async fn refresh_dns_upstream_targets(
    plan: &ResidentDnsPlan,
    upstream: &ResidentDnsUpstream,
    resolved: &ResidentDnsResolvedTargetSnapshot,
    l4proto: L4Proto,
    deadline: time::Instant,
) -> Result<
    Option<(
        ResidentDnsResolvedTargetSnapshot,
        Vec<ResidentDnsUpstreamRoutedTarget>,
        Vec<String>,
    )>,
    ResidentDnsTargetRefreshError,
> {
    let Some(fresh) = upstream
        .target
        .refresh_after_stale_failure_and_resolve(resolved, deadline)
        .await?
    else {
        return Ok(None);
    };
    let (targets, failures) = select_dns_upstream_targets(plan, upstream, fresh.to_vec(), l4proto)
        .map_err(ResidentDnsTargetRefreshError::Resolver)?;
    Ok(Some((fresh, targets, failures)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::dns) struct ResidentDnsUpstreamCandidate {
    pub(in crate::dns) target: SocketAddr,
    pub(in crate::dns) l4proto: L4Proto,
}

#[derive(Clone, Debug)]
pub(in crate::dns) struct ResidentDnsUpstreamRoutedTarget {
    pub(in crate::dns) target: SocketAddr,
    // Retained in the routed value so mixed TCP/UDP candidate plans preserve
    // the exact transport chosen during selection, even though current
    // single-transport executors already know it from their call site.
    #[allow(dead_code)]
    pub(in crate::dns) l4proto: L4Proto,
    pub(in crate::dns) selection: ResidentDnsUpstreamSelection,
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
    family_preference_rank: u8,
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

pub(in crate::dns) fn dns_upstream_candidates_for_l4protos(
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

pub(in crate::dns) fn select_dns_upstream_targets(
    plan: &ResidentDnsPlan,
    upstream: &ResidentDnsUpstream,
    targets: Vec<SocketAddr>,
    l4proto: L4Proto,
) -> Result<(Vec<ResidentDnsUpstreamRoutedTarget>, Vec<String>), String> {
    let targets = order_dns_upstream_targets_by_preference(plan, targets);
    select_dns_upstream_candidates(
        plan,
        upstream,
        dns_upstream_candidates_for_l4protos(&targets, &[l4proto]),
    )
}

pub(in crate::dns) fn select_dns_upstream_candidates(
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
            family_preference_rank: family_preference_rank(target, plan.ipversion_prefer),
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
        family_preference_rank: family_preference_rank(target, plan.ipversion_prefer),
    })
}

fn order_dns_upstream_targets_by_preference(
    plan: &ResidentDnsPlan,
    targets: Vec<SocketAddr>,
) -> Vec<SocketAddr> {
    let Some(preferred_qtype) = plan.ipversion_prefer else {
        return targets;
    };
    let preferred_ipv6 = preferred_qtype == DNS_QTYPE_AAAA;
    let mut preferred = Vec::with_capacity(targets.len());
    let mut fallback = Vec::with_capacity(targets.len());
    for target in targets {
        if target.is_ipv6() == preferred_ipv6 {
            preferred.push(target);
        } else {
            fallback.push(target);
        }
    }
    preferred.extend(fallback);
    preferred
}

fn family_preference_rank(target: SocketAddr, preferred_qtype: Option<u16>) -> u8 {
    match preferred_qtype {
        Some(DNS_QTYPE_A) if target.is_ipv4() => 0,
        Some(DNS_QTYPE_AAAA) if target.is_ipv6() => 0,
        Some(_) => 1,
        None => 0,
    }
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
    match left
        .family_preference_rank
        .cmp(&right.family_preference_rank)
    {
        std::cmp::Ordering::Equal => {}
        ordering => return ordering,
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

/// Race DNS candidates and, when a stale snapshot is proven dead, refresh the
/// target cache and retry the current request once with the newly published
/// candidates. The attempt closure is reused so its request context/deadline
/// remains unchanged; transport implementations enforce the original absolute
/// deadline through that context.
pub(super) async fn race_dns_upstream_targets_with_refresh<F, Fut, R, RFut>(
    upstream: &ResidentDnsUpstream,
    _resolved: &ResidentDnsResolvedTargetSnapshot,
    operation: &str,
    targets: Vec<ResidentDnsUpstreamRoutedTarget>,
    failures: Vec<String>,
    width: usize,
    context: ProxyDnsRequestContext,
    refresh: R,
    attempt: F,
) -> Result<Vec<u8>, ResidentDnsTransportError>
where
    F: Fn(ResidentDnsUpstreamRoutedTarget) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, ResidentDnsTransportError>>,
    R: Fn() -> RFut,
    RFut: std::future::Future<
            Output = Result<
                Option<(
                    ResidentDnsResolvedTargetSnapshot,
                    Vec<ResidentDnsUpstreamRoutedTarget>,
                    Vec<String>,
                )>,
                ResidentDnsTargetRefreshError,
            >,
        >,
{
    let mut current_targets = targets;
    let mut current_failures = failures;
    for pass in 0..=1 {
        let preserve_single_truncated_error =
            current_targets.len() == 1 && current_failures.is_empty();
        let mut remaining = current_targets.into_iter();
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
                        current_failures.push(error.to_string());
                    }
                }
            }
            if let Some(target) = remaining.next() {
                attempts.push(attempt(target));
            }
        }

        if attempted > 0 && every_attempt_invalidates_stale && pass == 0 {
            if context.ensure(ProxyDnsRequestStage::Retry).is_err() {
                return Err(ResidentDnsTransportError::proxy(
                    ProxyDnsRequestError::deadline(ProxyDnsRequestStage::Retry),
                ));
            }
            let refreshed = match tokio::time::timeout_at(context.deadline(), refresh()).await {
                Ok(result) => result,
                Err(_) => {
                    return Err(ResidentDnsTransportError::proxy(
                        ProxyDnsRequestError::deadline(ProxyDnsRequestStage::Retry),
                    ));
                }
            };
            match refreshed {
                Ok(Some((_fresh_resolved, fresh_targets, fresh_failures))) => {
                    current_targets = fresh_targets;
                    current_failures = fresh_failures;
                    continue;
                }
                Ok(None) => {}
                Err(ResidentDnsTargetRefreshError::Deadline) => {
                    return Err(ResidentDnsTransportError::proxy(
                        ProxyDnsRequestError::deadline(ProxyDnsRequestStage::Retry),
                    ));
                }
                Err(ResidentDnsTargetRefreshError::Resolver(error)) => {
                    return Err(ResidentDnsTransportError::refresh(format!(
                        "{operation} stale target refresh failed: {error}"
                    )));
                }
            }
        }
        if let Some(error) = single_truncated_error {
            return Err(error);
        }
        return Err(ResidentDnsTransportError::message(
            dns_upstream_targets_failed(upstream, operation, current_failures),
        ));
    }
    unreachable!("bounded stale retry loop exhausted")
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
    use std::sync::atomic::{AtomicUsize, Ordering};
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
            family_preference_rank: 0,
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
                authority: Arc::from("candidate-race.invalid:53"),
                host: "candidate-race.invalid".to_owned(),
                port: DNS_DEFAULT_PORT,
                literal_addr: None,
                fallback_resolver: dns_upstream_target_v4(),
                resolver_mark: 0,
                resolved_addrs: Arc::default(),
            },
            scheme: ResidentDnsUpstreamScheme::Udp,
            path: Arc::from(""),
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
            race_dns_upstream_targets_with_refresh(
                &upstream,
                &resolved,
                "race DNS fixture",
                targets,
                Vec::new(),
                2,
                ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
                || async {
                    Ok::<
                        Option<(
                            ResidentDnsResolvedTargetSnapshot,
                            Vec<ResidentDnsUpstreamRoutedTarget>,
                            Vec<String>,
                        )>,
                        ResidentDnsTargetRefreshError,
                    >(None)
                },
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

    #[tokio::test]
    async fn fresh_target_connect_failure_refreshes_and_retries_current_request_once() {
        let stale_target = dns_upstream_target_v4();
        let fresh_target = dns_upstream_target_v6();
        let upstream = test_upstream();
        let fresh = ResidentDnsResolvedTargetSnapshot::literal(stale_target);
        let attempts = Arc::new(AtomicUsize::new(0));
        let refreshes = Arc::new(AtomicUsize::new(0));
        let response = race_dns_upstream_targets_with_refresh(
            &upstream,
            &fresh,
            "stale retry fixture",
            vec![ResidentDnsUpstreamRoutedTarget {
                target: stale_target,
                l4proto: L4Proto::Udp,
                selection: ResidentDnsUpstreamSelection::Direct { mark: 0 },
            }],
            Vec::new(),
            1,
            ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
            {
                let refreshes = Arc::clone(&refreshes);
                move || {
                    refreshes.fetch_add(1, Ordering::Relaxed);
                    let fresh = ResidentDnsResolvedTargetSnapshot::literal(fresh_target);
                    async move {
                        Ok(Some((
                            fresh,
                            vec![ResidentDnsUpstreamRoutedTarget {
                                target: fresh_target,
                                l4proto: L4Proto::Udp,
                                selection: ResidentDnsUpstreamSelection::Direct { mark: 0 },
                            }],
                            Vec::new(),
                        )))
                    }
                }
            },
            {
                let attempts = Arc::clone(&attempts);
                move |target| {
                    attempts.fetch_add(1, Ordering::Relaxed);
                    async move {
                        if target.target == fresh_target {
                            Ok(vec![0x12, 0x34, 0x81, 0x80])
                        } else {
                            Err(ResidentDnsTransportError::TargetConnect(
                                "stale target refused".to_owned(),
                            ))
                        }
                    }
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(response, vec![0x12, 0x34, 0x81, 0x80]);
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
        assert_eq!(refreshes.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn stale_refresh_does_not_start_after_request_deadline() {
        let stale_target = dns_upstream_target_v4();
        let upstream = test_upstream();
        let stale = ResidentDnsResolvedTargetSnapshot::stale_literal(stale_target);
        let refreshes = Arc::new(AtomicUsize::new(0));
        let error = race_dns_upstream_targets_with_refresh(
            &upstream,
            &stale,
            "stale deadline fixture",
            vec![ResidentDnsUpstreamRoutedTarget {
                target: stale_target,
                l4proto: L4Proto::Udp,
                selection: ResidentDnsUpstreamSelection::Direct { mark: 0 },
            }],
            Vec::new(),
            1,
            ProxyDnsRequestContext::from_deadline(time::Instant::now() - Duration::from_millis(1)),
            {
                let refreshes = Arc::clone(&refreshes);
                move || {
                    refreshes.fetch_add(1, Ordering::Relaxed);
                    async { panic!("refresh must not start after the request deadline") }
                }
            },
            |_target| async {
                Err(ResidentDnsTransportError::TargetConnect(
                    "stale target refused".to_owned(),
                ))
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            ResidentDnsTransportError::Proxy(error)
                if error.stage() == ProxyDnsRequestStage::Retry
                    && error.failure() == ProxyDnsRequestFailure::Deadline
        ));
        assert_eq!(refreshes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn stale_refresh_failure_is_not_retried_with_old_target() {
        let stale_target = dns_upstream_target_v4();
        let upstream = test_upstream();
        let stale = ResidentDnsResolvedTargetSnapshot::stale_literal(stale_target);
        let attempts = Arc::new(AtomicUsize::new(0));
        let error = race_dns_upstream_targets_with_refresh(
            &upstream,
            &stale,
            "stale refresh failure fixture",
            vec![ResidentDnsUpstreamRoutedTarget {
                target: stale_target,
                l4proto: L4Proto::Udp,
                selection: ResidentDnsUpstreamSelection::Direct { mark: 0 },
            }],
            Vec::new(),
            1,
            ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
            || async {
                Err(ResidentDnsTargetRefreshError::Resolver(
                    "resolver unavailable".to_owned(),
                ))
            },
            {
                let attempts = Arc::clone(&attempts);
                move |_target| {
                    attempts.fetch_add(1, Ordering::Relaxed);
                    async {
                        Err(ResidentDnsTransportError::TargetConnect(
                            "stale target refused".to_owned(),
                        ))
                    }
                }
            },
        )
        .await
        .unwrap_err();

        assert!(
            matches!(error, ResidentDnsTransportError::Refresh(message) if message.contains("resolver unavailable"))
        );
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn response_timeout_does_not_evict_a_fresh_target() {
        let target = dns_upstream_target_v4();
        let upstream = test_upstream();
        let refreshes = Arc::new(AtomicUsize::new(0));
        let error = race_dns_upstream_targets_with_refresh(
            &upstream,
            &ResidentDnsResolvedTargetSnapshot::literal(target),
            "response-timeout fixture",
            vec![ResidentDnsUpstreamRoutedTarget {
                target,
                l4proto: L4Proto::Udp,
                selection: ResidentDnsUpstreamSelection::Direct { mark: 0 },
            }],
            Vec::new(),
            1,
            ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
            {
                let refreshes = Arc::clone(&refreshes);
                move || {
                    refreshes.fetch_add(1, Ordering::Relaxed);
                    async { panic!("response timeout must not refresh the target") }
                }
            },
            |_target| async {
                Err(ResidentDnsTransportError::response_timeout(
                    "upstream response timeout",
                ))
            },
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("response-timeout fixture"));
        assert_eq!(refreshes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn mixed_target_failures_do_not_evict_or_refresh() {
        let connect_target = dns_upstream_target_v4();
        let timeout_target = dns_upstream_target_v6();
        let upstream = test_upstream();
        let refreshes = Arc::new(AtomicUsize::new(0));
        let error = race_dns_upstream_targets_with_refresh(
            &upstream,
            &ResidentDnsResolvedTargetSnapshot::literal(connect_target),
            "mixed-error fixture",
            vec![
                ResidentDnsUpstreamRoutedTarget {
                    target: connect_target,
                    l4proto: L4Proto::Udp,
                    selection: ResidentDnsUpstreamSelection::Direct { mark: 0 },
                },
                ResidentDnsUpstreamRoutedTarget {
                    target: timeout_target,
                    l4proto: L4Proto::Udp,
                    selection: ResidentDnsUpstreamSelection::Direct { mark: 0 },
                },
            ],
            Vec::new(),
            2,
            ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
            {
                let refreshes = Arc::clone(&refreshes);
                move || {
                    refreshes.fetch_add(1, Ordering::Relaxed);
                    async { panic!("mixed candidate failures must not refresh") }
                }
            },
            move |target| async move {
                if target.target == connect_target {
                    Err(ResidentDnsTransportError::TargetConnect(
                        "connection refused".to_owned(),
                    ))
                } else {
                    Err(ResidentDnsTransportError::response_timeout(
                        "response timeout",
                    ))
                }
            },
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("mixed-error fixture"));
        assert_eq!(refreshes.load(Ordering::Relaxed), 0);
    }
}
