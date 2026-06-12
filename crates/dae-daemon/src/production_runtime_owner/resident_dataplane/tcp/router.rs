use super::*;
pub(crate) const BPF_L4_TCP: u8 = 6;
pub(crate) const ROUTING_L4_TCP: u8 = 1;
pub(crate) const ROUTING_IP_VERSION_4: u8 = 1;
pub(crate) const ROUTING_IP_VERSION_6: u8 = 2;
pub(crate) const TCP_SNIFF_BUFFER_LIMIT: usize = 64 * 1024;
pub(crate) const ANYTLS_LOCAL_CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

pub(crate) struct ResidentTcpRouter {
    pub(in crate::production_runtime_owner::resident_dataplane) proxies:
        BTreeMap<u8, ResidentProxyGroupPlan>,
    pub(in crate::production_runtime_owner::resident_dataplane) routing_tuple_map_id: u32,
    routing_tuple_map_fd: OwnedFd,
    pub(in crate::production_runtime_owner::resident_dataplane) routing_matcher: RoutingMatcher,
    pub(in crate::production_runtime_owner::resident_dataplane) dial_mode: TcpDialMode,
    pub(in crate::production_runtime_owner::resident_dataplane) sniffing_timeout: Duration,
    pub(in crate::production_runtime_owner::resident_dataplane) so_mark_from_dae: u32,
    pub(in crate::production_runtime_owner::resident_dataplane) mptcp: bool,
}

impl ResidentTcpRouter {
    pub(in crate::production_runtime_owner::resident_dataplane) fn new(
        proxies: BTreeMap<u8, ResidentProxyGroupPlan>,
        routing_tuple_map_id: Option<u32>,
        routing_matcher: RoutingMatcher,
        dial_mode: TcpDialMode,
        sniffing_timeout: Duration,
        so_mark_from_dae: u32,
        mptcp: bool,
    ) -> Result<Self, String> {
        if proxies.is_empty() {
            return Err("resident TCP router needs at least one proxy outbound".to_owned());
        }
        let routing_tuple_map_id = routing_tuple_map_id.ok_or_else(|| {
            "resident TCP router needs routing_tuples_map id for compatible per-flow outbound selection"
                .to_owned()
        })?;
        let routing_tuple_map_fd = open_map_fd(routing_tuple_map_id).map_err(|err| {
            format!("open routing_tuples_map id {routing_tuple_map_id} for resident TCP: {err}")
        })?;
        Self::from_open_routing_tuple_map(
            proxies,
            routing_tuple_map_id,
            routing_tuple_map_fd,
            routing_matcher,
            dial_mode,
            sniffing_timeout,
            so_mark_from_dae,
            mptcp,
        )
    }

    fn from_open_routing_tuple_map(
        proxies: BTreeMap<u8, ResidentProxyGroupPlan>,
        routing_tuple_map_id: u32,
        routing_tuple_map_fd: OwnedFd,
        routing_matcher: RoutingMatcher,
        dial_mode: TcpDialMode,
        sniffing_timeout: Duration,
        so_mark_from_dae: u32,
        mptcp: bool,
    ) -> Result<Self, String> {
        if proxies.is_empty() {
            return Err("resident TCP router needs at least one proxy outbound".to_owned());
        }
        Ok(Self {
            proxies,
            routing_tuple_map_id,
            routing_tuple_map_fd,
            routing_matcher,
            dial_mode,
            sniffing_timeout,
            so_mark_from_dae,
            mptcp,
        })
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn new_for_test(
        proxies: BTreeMap<u8, ResidentProxyGroupPlan>,
        routing_matcher: RoutingMatcher,
        dial_mode: TcpDialMode,
        sniffing_timeout: Duration,
        so_mark_from_dae: u32,
        mptcp: bool,
    ) -> Result<Self, String> {
        let routing_tuple_map_fd: OwnedFd = std::fs::File::open("/dev/null")
            .map_err(|err| format!("open /dev/null for resident TCP router test fd: {err}"))?
            .into();
        Self::from_open_routing_tuple_map(
            proxies,
            1,
            routing_tuple_map_fd,
            routing_matcher,
            dial_mode,
            sniffing_timeout,
            so_mark_from_dae,
            mptcp,
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn proxy_count(&self) -> usize {
        self.proxies.len()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn dial_mode_name(
        &self,
    ) -> &'static str {
        self.dial_mode.as_str()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn sniffing_timeout(
        &self,
    ) -> Duration {
        self.sniffing_timeout
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn select(
        &self,
        peer: SocketAddr,
        original_dst: SocketAddr,
        sniffed_domain: &str,
    ) -> Result<TcpSelection, String> {
        let initial = self.lookup_routing_result(peer, original_dst)?;
        self.select_from_routing_result(peer, original_dst, sniffed_domain, initial)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn select_from_routing_result(
        &self,
        peer: SocketAddr,
        original_dst: SocketAddr,
        sniffed_domain: &str,
        initial: BpfRoutingResult,
    ) -> Result<TcpSelection, String> {
        let destination = original_dst;
        let first_choose = choose_dial_target(
            self.dial_mode,
            initial.outbound,
            destination,
            sniffed_domain,
            false,
        );
        let mut final_outbound = initial.outbound;
        let mut final_mark = initial.mark;
        let mut userspace_route_executed = false;
        let mut userspace_route_must = false;

        if first_choose.should_reroute || final_outbound == OUTBOUND_CONTROL_PLANE_ROUTING {
            let outcome = self
                .routing_matcher
                .match_query_detail(&Query {
                    source: Some(peer.ip()),
                    dest: original_dst.ip(),
                    source_port: Some(peer.port()),
                    dest_port: original_dst.port(),
                    ip_version: Some(routing_ip_version(original_dst.ip())),
                    l4proto: Some(ROUTING_L4_TCP),
                    domain: sniffed_domain.to_owned(),
                    process_name: process_name(&initial.pname),
                    dscp: Some(initial.dscp),
                    mac: Some(initial.mac),
                })
                .map_err(|err| format!("resident TCP userspace reroute: {err}"))?;
            final_outbound = outcome.outbound.value();
            final_mark = outcome.mark;
            userspace_route_executed = true;
            userspace_route_must = outcome.must;
        }

        let second_choose = userspace_route_executed.then(|| {
            choose_dial_target(
                self.dial_mode,
                final_outbound,
                destination,
                sniffed_domain,
                false,
            )
        });
        let final_choose = second_choose.as_ref().unwrap_or(&first_choose);
        if final_mark == 0 {
            final_mark = self.so_mark_from_dae;
        }
        let route = TcpRouteSelection {
            initial_outbound: initial.outbound,
            final_outbound,
            final_mark,
            userspace_route_executed,
            userspace_route_must,
            dial_target: final_choose.dial_target.clone(),
            dial_ip: final_choose.dial_ip,
            log_metadata: TcpRoutingLogMetadata::from_bpf(&initial),
        };
        match final_outbound {
            OUTBOUND_DIRECT => Ok(TcpSelection::Direct(TcpDirectSelection {
                route,
                mptcp: self.mptcp,
            })),
            OUTBOUND_BLOCK => Ok(TcpSelection::Block(TcpBlockSelection { route })),
            _ => {
                let Some(proxy_group) = self.proxies.get(&final_outbound) else {
                    return Err(format!(
                        "resident TCP selected outbound {} but no Rust proxy plan is available; unsupported protocol must stay fail-closed until implemented",
                        OutboundIndex(final_outbound)
                    ));
                };
                let proxy = proxy_group.select_proxy_for_tcp()?;
                Ok(TcpSelection::Proxy(TcpProxySelection {
                    mark: route.final_mark,
                    mptcp: self.mptcp,
                    route,
                    proxy,
                }))
            }
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn lookup_routing_result(
        &self,
        peer: SocketAddr,
        original_dst: SocketAddr,
    ) -> Result<BpfRoutingResult, String> {
        let key = BpfTuplesKey {
            sip: ip_addr_bytes(peer.ip()),
            dip: ip_addr_bytes(original_dst.ip()),
            sport: peer.port().to_be(),
            dport: original_dst.port().to_be(),
            l4proto: BPF_L4_TCP,
            padding: [0; 3],
        };
        let mut result = BpfRoutingResult::default();
        lookup_map_elem_bytes(
            self.routing_tuple_map_fd.as_raw_fd(),
            bytes_of(&key),
            bytes_of_mut(&mut result),
        )
        .map_err(|err| {
            format!(
                "lookup routing_tuples_map id {} for {} -> {} tcp: {err}",
                self.routing_tuple_map_id, peer, original_dst
            )
        })?;
        Ok(result)
    }
}

fn routing_ip_version(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => ROUTING_IP_VERSION_4,
        IpAddr::V6(_) => ROUTING_IP_VERSION_6,
    }
}

#[derive(Debug)]
pub(crate) struct TcpRouteSelection {
    pub(in crate::production_runtime_owner::resident_dataplane) initial_outbound: u8,
    pub(in crate::production_runtime_owner::resident_dataplane) final_outbound: u8,
    pub(in crate::production_runtime_owner::resident_dataplane) final_mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane) userspace_route_executed: bool,
    pub(in crate::production_runtime_owner::resident_dataplane) userspace_route_must: bool,
    pub(in crate::production_runtime_owner::resident_dataplane) dial_target: String,
    pub(in crate::production_runtime_owner::resident_dataplane) dial_ip: bool,
    pub(in crate::production_runtime_owner::resident_dataplane) log_metadata: TcpRoutingLogMetadata,
}

#[derive(Debug)]
pub(crate) struct TcpRoutingLogMetadata {
    pub(in crate::production_runtime_owner::resident_dataplane) pid: u32,
    pub(in crate::production_runtime_owner::resident_dataplane) dscp: u8,
    pub(in crate::production_runtime_owner::resident_dataplane) pname: String,
    pub(in crate::production_runtime_owner::resident_dataplane) mac: String,
}

impl TcpRoutingLogMetadata {
    pub(in crate::production_runtime_owner::resident_dataplane) fn from_bpf(
        result: &BpfRoutingResult,
    ) -> Self {
        Self {
            pid: result.pid,
            dscp: result.dscp,
            pname: process_name(&result.pname).unwrap_or_default(),
            mac: mac_string(&result.mac),
        }
    }
}

#[derive(Debug)]
pub(crate) struct TcpProxySelection {
    pub(in crate::production_runtime_owner::resident_dataplane) route: TcpRouteSelection,
    pub(in crate::production_runtime_owner::resident_dataplane) proxy: Arc<ResidentProxyPlan>,
    pub(in crate::production_runtime_owner::resident_dataplane) mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane) mptcp: bool,
}

#[derive(Debug)]
pub(crate) struct TcpDirectSelection {
    pub(in crate::production_runtime_owner::resident_dataplane) route: TcpRouteSelection,
    pub(in crate::production_runtime_owner::resident_dataplane) mptcp: bool,
}

#[derive(Debug)]
pub(crate) struct TcpBlockSelection {
    pub(in crate::production_runtime_owner::resident_dataplane) route: TcpRouteSelection,
}

#[derive(Debug)]
pub(crate) enum TcpSelection {
    Proxy(TcpProxySelection),
    Direct(TcpDirectSelection),
    Block(TcpBlockSelection),
}

pub(crate) struct TcpSniffReport {
    pub(in crate::production_runtime_owner::resident_dataplane) payload: Vec<u8>,
    pub(in crate::production_runtime_owner::resident_dataplane) domain: String,
    pub(in crate::production_runtime_owner::resident_dataplane) error: Option<String>,
}
