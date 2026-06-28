use super::super::*;

pub(super) async fn resolved_upstream_targets(
    upstream: &ResidentDnsUpstream,
) -> Result<Vec<SocketAddr>, String> {
    upstream.target.resolve_addrs().await
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

pub(super) fn select_dns_upstream_target(
    plan: &ResidentDnsPlan,
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    l4proto: L4Proto,
) -> Result<ResidentDnsUpstreamSelection, String> {
    let Some(router) = plan.upstream_router.as_ref() else {
        return Ok(ResidentDnsUpstreamSelection::Direct { mark: plan.mark });
    };
    router.select(
        upstream,
        target,
        l4proto,
        dns_upstream_proxy_network_type(target, l4proto),
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
