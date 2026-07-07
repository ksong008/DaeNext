use super::*;

#[derive(Clone, Debug)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentDnsUpstreamRouter {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) routing_matcher:
        RoutingMatcher,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) proxy_groups:
        Arc<BTreeMap<u8, ResidentProxyGroupPlan>>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) so_mark_from_dae: u32,
}

#[derive(Clone, Debug)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) enum ResidentDnsUpstreamSelection {
    Direct { mark: u32 },
    Proxy { proxy: Arc<ResidentProxyPlan> },
}

#[derive(Clone, Debug)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsUpstreamSelectionCandidate
{
    pub(in crate::production_runtime_owner::resident_dataplane::dns) selection:
        ResidentDnsUpstreamSelection,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) network_type: NetworkType,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) latency_ms: i64,
}

impl ResidentDnsUpstreamRouter {
    pub(in crate::production_runtime_owner::resident_dataplane) fn new(
        routing_matcher: RoutingMatcher,
        proxy_groups: Arc<BTreeMap<u8, ResidentProxyGroupPlan>>,
        so_mark_from_dae: u32,
    ) -> Self {
        Self {
            routing_matcher,
            proxy_groups,
            so_mark_from_dae: effective_so_mark_from_dae(so_mark_from_dae),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn select_candidate(
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
                let proxy =
                    proxy_group.select_proxy_for_dns_upstream_candidate(proxy_network_type)?;
                Ok(ResidentDnsUpstreamSelectionCandidate {
                    selection: ResidentDnsUpstreamSelection::Proxy {
                        proxy: proxy_with_dns_upstream_mark(proxy.proxy, mark),
                    },
                    network_type: proxy.network_type,
                    latency_ms: proxy.latency_ms,
                })
            }
        }
    }
}

fn proxy_with_dns_upstream_mark(
    proxy: Arc<ResidentProxyPlan>,
    mark: u32,
) -> Arc<ResidentProxyPlan> {
    if mark == 0 || proxy.mark == mark {
        return proxy;
    }
    let mut overridden = proxy.as_ref().clone();
    overridden.mark = mark;
    Arc::new(overridden)
}
