const BPF_L4_TCP: u8 = 6;
const ROUTING_L4_TCP: u8 = 1;
const ROUTING_IP_VERSION_4: u8 = 1;
const TCP_SNIFF_BUFFER_LIMIT: usize = 64 * 1024;
const ANYTLS_LOCAL_CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

pub(super) struct ResidentTcpRouter {
    proxies: BTreeMap<u8, ResidentProxyGroupPlan>,
    routing_tuple_map_id: u32,
    routing_matcher: RoutingMatcher,
    dial_mode: TcpDialMode,
    sniffing_timeout: Duration,
    so_mark_from_dae: u32,
    mptcp: bool,
}

impl ResidentTcpRouter {
    pub(super) fn new(
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
            "resident TCP router needs routing_tuples_map id for Go-compatible per-flow outbound selection"
                .to_owned()
        })?;
        Ok(Self {
            proxies,
            routing_tuple_map_id,
            routing_matcher,
            dial_mode,
            sniffing_timeout,
            so_mark_from_dae,
            mptcp,
        })
    }

    pub(super) fn proxy_count(&self) -> usize {
        self.proxies.len()
    }

    pub(super) fn dial_mode_name(&self) -> &'static str {
        self.dial_mode.as_str()
    }

    pub(super) fn sniffing_timeout(&self) -> Duration {
        self.sniffing_timeout
    }

    fn select(
        &self,
        peer: SocketAddrV4,
        original_dst: SocketAddrV4,
        sniffed_domain: &str,
    ) -> Result<TcpSelection, String> {
        let initial = self.lookup_routing_result(peer, original_dst)?;
        self.select_from_routing_result(peer, original_dst, sniffed_domain, initial)
    }

    fn select_from_routing_result(
        &self,
        peer: SocketAddrV4,
        original_dst: SocketAddrV4,
        sniffed_domain: &str,
        initial: BpfRoutingResult,
    ) -> Result<TcpSelection, String> {
        let destination = SocketAddr::V4(original_dst);
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
                    source: Some(IpAddr::V4(*peer.ip())),
                    dest: IpAddr::V4(*original_dst.ip()),
                    source_port: Some(peer.port()),
                    dest_port: original_dst.port(),
                    ip_version: Some(ROUTING_IP_VERSION_4),
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
                        "resident TCP selected outbound {} but no Rust proxy plan is available; unsupported protocol must stay on Go control plane until implemented",
                        OutboundIndex(final_outbound)
                    ));
                };
                let mut proxy = proxy_group.select_proxy_for_tcp()?;
                proxy.mark = route.final_mark;
                proxy.mptcp = self.mptcp;
                Ok(TcpSelection::Proxy(TcpProxySelection { route, proxy }))
            }
        }
    }

    fn lookup_routing_result(
        &self,
        peer: SocketAddrV4,
        original_dst: SocketAddrV4,
    ) -> Result<BpfRoutingResult, String> {
        let key = BpfTuplesKey {
            sip: ipv4_mapped_ip_bytes(*peer.ip()),
            dip: ipv4_mapped_ip_bytes(*original_dst.ip()),
            sport: peer.port().to_be(),
            dport: original_dst.port().to_be(),
            l4proto: BPF_L4_TCP,
            padding: [0; 3],
        };
        let fd = open_map_fd(self.routing_tuple_map_id).map_err(|err| {
            format!(
                "open routing_tuples_map id {} for resident TCP: {err}",
                self.routing_tuple_map_id
            )
        })?;
        let mut result = BpfRoutingResult::default();
        lookup_map_elem_bytes(fd.as_raw_fd(), bytes_of(&key), bytes_of_mut(&mut result)).map_err(
            |err| {
                format!(
                    "lookup routing_tuples_map for {} -> {} tcp: {err}",
                    peer, original_dst
                )
            },
        )?;
        Ok(result)
    }
}

#[derive(Debug)]
struct TcpRouteSelection {
    initial_outbound: u8,
    final_outbound: u8,
    final_mark: u32,
    userspace_route_executed: bool,
    userspace_route_must: bool,
    dial_target: String,
    dial_ip: bool,
    log_metadata: TcpRoutingLogMetadata,
}

#[derive(Debug)]
struct TcpRoutingLogMetadata {
    pid: u32,
    dscp: u8,
    pname: String,
    mac: String,
}

impl TcpRoutingLogMetadata {
    fn from_bpf(result: &BpfRoutingResult) -> Self {
        Self {
            pid: result.pid,
            dscp: result.dscp,
            pname: process_name(&result.pname).unwrap_or_default(),
            mac: mac_string(&result.mac),
        }
    }
}

#[derive(Debug)]
struct TcpProxySelection {
    route: TcpRouteSelection,
    proxy: ResidentProxyPlan,
}

#[derive(Debug)]
struct TcpDirectSelection {
    route: TcpRouteSelection,
    mptcp: bool,
}

#[derive(Debug)]
struct TcpBlockSelection {
    route: TcpRouteSelection,
}

#[derive(Debug)]
enum TcpSelection {
    Proxy(TcpProxySelection),
    Direct(TcpDirectSelection),
    Block(TcpBlockSelection),
}

struct TcpSniffReport {
    payload: Vec<u8>,
    domain: String,
    error: Option<String>,
}
