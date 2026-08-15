use super::*;
use crate::ResidentHealthResuscitationHandle;

#[derive(Clone, Debug)]
pub(crate) struct ResidentDnsUpstreamRouter {
    pub(in crate::dns) routing_matcher: RoutingMatcher,
    pub(in crate::dns) proxy_groups: SharedResidentProxyGroupMap,
    pub(in crate::dns) so_mark_from_dae: u32,
    health_resuscitation: Option<ResidentHealthResuscitationHandle>,
}

#[derive(Clone, Debug)]
pub(in crate::dns) enum ResidentDnsUpstreamSelection {
    Direct { mark: u32 },
    Proxy { binding: ResidentProxyBinding },
}

#[derive(Clone, Debug)]
pub(in crate::dns) struct ResidentDnsUpstreamSelectionCandidate {
    pub(in crate::dns) selection: ResidentDnsUpstreamSelection,
    pub(in crate::dns) network_type: NetworkType,
    pub(in crate::dns) latency_ms: i64,
}

impl ResidentDnsUpstreamRouter {
    pub(crate) fn new(
        routing_matcher: RoutingMatcher,
        proxy_groups: SharedResidentProxyGroupMap,
        so_mark_from_dae: u32,
        health_resuscitation: Option<ResidentHealthResuscitationHandle>,
    ) -> Self {
        Self {
            routing_matcher,
            proxy_groups,
            so_mark_from_dae: effective_so_mark_from_dae(so_mark_from_dae),
            health_resuscitation,
        }
    }

    pub(in crate::dns) fn select_candidate(
        &self,
        upstream: &ResidentDnsUpstream,
        target: SocketAddr,
        route_l4proto: L4Proto,
        proxy_network_type: NetworkType,
    ) -> Result<ResidentDnsUpstreamSelectionCandidate, String> {
        let query = match route_l4proto {
            L4Proto::Tcp => Query::tcp(target.ip(), target.port(), upstream.target.host.clone()),
            L4Proto::Udp => Query::udp(target.ip(), target.port(), upstream.target.host.clone()),
        };
        let outcome = self
            .routing_matcher
            .match_query_detail(&query)
            .map_err(|err| {
                format!(
                    "route DNS upstream {} {} {}: {err}",
                    upstream.tag, upstream.target.authority, target,
                )
            })?;
        let mark = if outcome.mark == 0 {
            self.so_mark_from_dae
        } else {
            outcome.mark
        };
        match outcome.outbound.value() {
            OUTBOUND_DIRECT => Ok(ResidentDnsUpstreamSelectionCandidate {
                selection: ResidentDnsUpstreamSelection::Direct { mark },
                network_type: proxy_network_type,
                latency_ms: 0,
            }),
            OUTBOUND_BLOCK => Err(format!(
                "DNS upstream {} {} routed to block for {}",
                upstream.tag, upstream.target.authority, target
            )),
            OUTBOUND_CONTROL_PLANE_ROUTING => Err(format!(
                "DNS upstream {} {} still requires control-plane routing for {}; no recursive DNS upstream routing is admitted",
                upstream.tag, upstream.target.authority, target
            )),
            outbound => {
                let Some(proxy_group) = self.proxy_groups.get(&outbound) else {
                    return Err(format!(
                        "DNS upstream {} {} selected outbound {} but no Rust proxy plan is available",
                        upstream.tag,
                        upstream.target.authority,
                        OutboundIndex(outbound)
                    ));
                };
                let proxy = match proxy_group
                    .select_proxy_for_dns_upstream_candidate_detail(proxy_network_type)
                {
                    Ok(proxy) => proxy,
                    Err(err) => {
                        if err.no_alive
                            && let Some(resuscitator) = self.health_resuscitation.as_ref()
                        {
                            resuscitator.trigger(outbound, proxy_network_type);
                        }
                        return Err(err.message);
                    }
                };
                Ok(ResidentDnsUpstreamSelectionCandidate {
                    selection: ResidentDnsUpstreamSelection::Proxy {
                        binding: proxy.proxy.with_route_socket_mark(mark),
                    },
                    network_type: proxy.network_type,
                    latency_ms: proxy.latency_ms,
                })
            }
        }
    }
}
