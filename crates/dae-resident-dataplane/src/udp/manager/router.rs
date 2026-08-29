use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::slice;

use dae_core_types::OutboundIndex;
use dae_datapath::{
    OUTBOUND_BLOCK, OUTBOUND_CONTROL_PLANE_ROUTING, OUTBOUND_DIRECT, TcpDialMode,
    outbound_is_reserved,
};
use dae_dns::DNS_DEFAULT_PORT;
use dae_ebpf_support::{
    BpfIpBytes, BpfRoutingResult, BpfTuplesKey, lookup_map_elem_bytes, open_map_fd,
};
use dae_outbound::NetworkType;
use dae_routing::{Query, RoutingMatcher};

use super::super::super::plan::{
    ResidentProxySelection, effective_so_mark_from_dae, resident_data_udp_network_type,
    resident_udp_check_network_type,
};
use super::*;

const BPF_L4_UDP: u8 = 17;

pub(super) struct ResidentUdpRouter {
    proxy_groups: SharedResidentProxyGroupMap,
    default_outbound: u8,
    routing_tuple_map_id: u32,
    routing_tuple_map_fd: Option<OwnedFd>,
    routing_matcher: RoutingMatcher,
    dial_mode: TcpDialMode,
    so_mark_from_dae: u32,
    resuscitator: Option<Arc<dyn ResidentHealthResuscitation>>,
}

impl ResidentUdpRouter {
    pub(super) fn new(
        proxy_groups: SharedResidentProxyGroupMap,
        default_outbound: u8,
        routing_tuple_map_id: Option<u32>,
        routing_matcher: RoutingMatcher,
        dial_mode: TcpDialMode,
        so_mark_from_dae: u32,
        resuscitator: Arc<dyn ResidentHealthResuscitation>,
    ) -> Result<Self, String> {
        let routing_tuple_map_id = routing_tuple_map_id.ok_or_else(|| {
            "resident UDP router needs routing_tuples_map id for compatible per-packet outbound selection"
                .to_owned()
        })?;
        let routing_tuple_map_fd = open_map_fd(routing_tuple_map_id).map_err(|err| {
            format!("open routing_tuples_map id {routing_tuple_map_id} for resident UDP: {err}")
        })?;
        Self::from_validated_parts(
            proxy_groups,
            default_outbound,
            routing_tuple_map_id,
            Some(routing_tuple_map_fd),
            routing_matcher,
            dial_mode,
            so_mark_from_dae,
            Some(resuscitator),
        )
    }

    #[cfg(test)]
    pub(super) fn from_parts(
        proxy_groups: SharedResidentProxyGroupMap,
        default_outbound: u8,
        routing_tuple_map_id: u32,
        routing_tuple_map_fd: Option<OwnedFd>,
        routing_matcher: RoutingMatcher,
        dial_mode: TcpDialMode,
        so_mark_from_dae: u32,
    ) -> Result<Self, String> {
        Self::from_validated_parts(
            proxy_groups,
            default_outbound,
            routing_tuple_map_id,
            routing_tuple_map_fd,
            routing_matcher,
            dial_mode,
            so_mark_from_dae,
            None,
        )
    }

    fn from_validated_parts(
        proxy_groups: SharedResidentProxyGroupMap,
        default_outbound: u8,
        routing_tuple_map_id: u32,
        routing_tuple_map_fd: Option<OwnedFd>,
        routing_matcher: RoutingMatcher,
        dial_mode: TcpDialMode,
        so_mark_from_dae: u32,
        resuscitator: Option<Arc<dyn ResidentHealthResuscitation>>,
    ) -> Result<Self, String> {
        if proxy_groups.is_empty() {
            return Err("resident UDP router needs at least one proxy outbound".to_owned());
        }
        if !proxy_groups.contains_key(&default_outbound) {
            return Err(format!(
                "resident UDP default outbound {} has no Rust proxy plan",
                OutboundIndex(default_outbound)
            ));
        }
        Ok(Self {
            proxy_groups,
            default_outbound,
            routing_tuple_map_id,
            routing_tuple_map_fd,
            routing_matcher,
            dial_mode,
            so_mark_from_dae: effective_so_mark_from_dae(so_mark_from_dae),
            resuscitator,
        })
    }

    pub(super) const fn routing_tuple_map_id(&self) -> u32 {
        self.routing_tuple_map_id
    }

    pub(super) const fn default_outbound(&self) -> u8 {
        self.default_outbound
    }

    pub(super) fn default_proxy_group(&self) -> &ResidentProxyGroupPlan {
        self.proxy_groups
            .get(&self.default_outbound)
            .expect("default outbound was validated")
    }

    #[cfg(test)]
    pub(super) fn select_from_routing_result(
        &self,
        original_dst: SocketAddr,
        initial: BpfRoutingResult,
    ) -> Result<ResidentUdpSelection, String> {
        self.select_from_routing_result_with_domain(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            original_dst,
            initial,
            "",
        )
    }

    pub(super) fn select_from_routing_result_with_domain(
        &self,
        peer: SocketAddr,
        original_dst: SocketAddr,
        initial: BpfRoutingResult,
        sniffed_domain: &str,
    ) -> Result<ResidentUdpSelection, String> {
        let force_proxy_packet = original_dst.port() == DNS_DEFAULT_PORT && initial.must > 0;
        if original_dst.port() == DNS_DEFAULT_PORT && !force_proxy_packet {
            return Ok(ResidentUdpSelection::ResidentDns);
        }
        let userspace_route_executed =
            self.should_userspace_reroute(initial.outbound, sniffed_domain);
        let final_result = if userspace_route_executed {
            self.userspace_reroute(peer, original_dst, initial, sniffed_domain)?
        } else {
            initial
        };
        let final_mark = if final_result.mark == 0 {
            self.so_mark_from_dae
        } else {
            final_result.mark
        };
        let route = ResidentUdpRouteSelection {
            initial_outbound: initial.outbound,
            final_outbound: final_result.outbound,
            final_mark,
            userspace_route_executed,
            userspace_route_must: userspace_route_executed && final_result.must > 0,
        };
        match final_result.outbound {
            OUTBOUND_BLOCK => Ok(ResidentUdpSelection::Block(route)),
            OUTBOUND_DIRECT => Ok(ResidentUdpSelection::Direct(ResidentUdpDirectSelection {
                route,
            })),
            OUTBOUND_CONTROL_PLANE_ROUTING => Err(
                "resident UDP selected control-plane routing but no UDP domain/SNI was available for userspace reroute; DNS domain_routing_map or QUIC sniffing must resolve this before userspace"
                    .to_owned(),
            ),
            outbound => self
                .select_proxy_from_group(outbound, final_mark, original_dst, force_proxy_packet)
                .map(|(selection, data_udp_availability)| {
                    let route = ResidentUdpRouteSelection {
                        final_mark: selection.proxy.effective_socket_mark(),
                        ..route
                    };
                    ResidentUdpSelection::Proxy(ResidentUdpProxySelection {
                        proxy: selection.proxy,
                        selected_network_type: selection.network_type,
                        force_proxy_packet,
                        route,
                        data_udp_availability,
                    })
                }),
        }
    }

    pub(super) fn needs_sniffed_domain_for_reroute(
        &self,
        original_dst: SocketAddr,
        initial: BpfRoutingResult,
    ) -> bool {
        original_dst.port() != DNS_DEFAULT_PORT
            && (initial.outbound == OUTBOUND_CONTROL_PLANE_ROUTING
                || (self.dial_mode == TcpDialMode::DomainPlusPlus
                    && !outbound_is_reserved(initial.outbound)))
    }

    fn should_userspace_reroute(&self, outbound: u8, sniffed_domain: &str) -> bool {
        !sniffed_domain.is_empty()
            && (outbound == OUTBOUND_CONTROL_PLANE_ROUTING
                || (self.dial_mode == TcpDialMode::DomainPlusPlus
                    && !outbound_is_reserved(outbound)))
    }

    fn userspace_reroute(
        &self,
        peer: SocketAddr,
        original_dst: SocketAddr,
        initial: BpfRoutingResult,
        sniffed_domain: &str,
    ) -> Result<BpfRoutingResult, String> {
        let mut query = Query::udp(original_dst.ip(), original_dst.port(), sniffed_domain);
        query.source = Some(peer.ip());
        query.source_port = Some(peer.port());
        query.ip_version = Some(routing_ip_version(original_dst.ip()));
        query.process_name = udp_process_name(&initial.pname);
        query.dscp = Some(initial.dscp);
        query.mac = Some(initial.mac);
        let outcome = self
            .routing_matcher
            .match_query_detail(&query)
            .map_err(|err| format!("resident UDP userspace reroute: {err}"))?;
        Ok(BpfRoutingResult {
            outbound: outcome.outbound.value(),
            mark: outcome.mark,
            must: u8::from(outcome.must),
            mac: initial.mac,
            pname: initial.pname,
            pid: initial.pid,
            dscp: initial.dscp,
            padding: initial.padding,
        })
    }

    fn select_proxy_from_group(
        &self,
        outbound: u8,
        mark: u32,
        original_dst: SocketAddr,
        force_proxy_packet: bool,
    ) -> Result<(ResidentProxySelection, ResidentDataUdpAvailabilityHandle), String> {
        let Some(proxy_group) = self.proxy_groups.get(&outbound) else {
            return Err(format!(
                "resident UDP selected outbound {} but no Rust proxy plan is available; unsupported protocol must stay fail-closed until implemented",
                OutboundIndex(outbound)
            ));
        };
        let network_type = if force_proxy_packet {
            resident_udp_check_network_type(original_dst)
        } else {
            resident_data_udp_network_type(original_dst)
        };
        let selection =
            match proxy_group.select_proxy_for_udp_runtime_candidate_detail(network_type, true) {
                Ok(selection) => selection,
                Err(err) => {
                    if network_type.is_data_udp()
                        && err.no_alive
                        && let Some(resuscitator) = self.resuscitator.as_ref()
                    {
                        resuscitator.trigger(outbound, network_type.into());
                    }
                    return Err(err.message);
                }
            };
        let ResidentProxySelection {
            proxy,
            network_type,
            latency_ms,
        } = selection;
        let data_udp_availability = proxy_group.data_udp_availability_handle(&proxy.node_tag)?;
        Ok((
            ResidentProxySelection {
                proxy: proxy.with_route_socket_mark(mark),
                network_type,
                latency_ms,
            },
            data_udp_availability,
        ))
    }

    pub(super) fn lookup_routing_result(
        &self,
        peer: SocketAddr,
        original_dst: SocketAddr,
    ) -> Result<BpfRoutingResult, String> {
        let Some(fd) = self.routing_tuple_map_fd.as_ref() else {
            return Err("resident UDP router has no routing_tuples_map fd".to_owned());
        };
        let key = BpfTuplesKey {
            sip: udp_ip_addr_bytes(peer.ip()),
            dip: udp_ip_addr_bytes(original_dst.ip()),
            sport: peer.port().to_be(),
            dport: original_dst.port().to_be(),
            l4proto: BPF_L4_UDP,
            padding: [0; 3],
        };
        let mut result = BpfRoutingResult::default();
        lookup_map_elem_bytes(fd.as_raw_fd(), bytes_of(&key), bytes_of_mut(&mut result)).map_err(
            |err| {
                format!(
                    "lookup routing_tuples_map id {} for {} -> {} udp: {err}",
                    self.routing_tuple_map_id, peer, original_dst
                )
            },
        )?;
        Ok(result)
    }
}

pub(super) struct ResidentUdpProxySelection {
    pub(super) proxy: ResidentProxyBinding,
    pub(super) selected_network_type: NetworkType,
    pub(super) force_proxy_packet: bool,
    pub(super) route: ResidentUdpRouteSelection,
    pub(super) data_udp_availability: ResidentDataUdpAvailabilityHandle,
}

pub(super) struct ResidentUdpDirectSelection {
    pub(super) route: ResidentUdpRouteSelection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ResidentUdpRouteSelection {
    pub(super) initial_outbound: u8,
    pub(super) final_outbound: u8,
    pub(super) final_mark: u32,
    pub(super) userspace_route_executed: bool,
    pub(super) userspace_route_must: bool,
}

pub(super) enum ResidentUdpSelection {
    ResidentDns,
    Proxy(ResidentUdpProxySelection),
    Direct(ResidentUdpDirectSelection),
    Block(ResidentUdpRouteSelection),
}

fn udp_ip_addr_bytes(addr: IpAddr) -> BpfIpBytes {
    match addr {
        IpAddr::V4(addr) => udp_ipv4_mapped_ip_bytes(addr),
        IpAddr::V6(addr) => BpfIpBytes {
            u6_addr8: addr.octets(),
        },
    }
}

fn udp_ipv4_mapped_ip_bytes(addr: Ipv4Addr) -> BpfIpBytes {
    let mut out = [0_u8; 16];
    out[10] = 0xff;
    out[11] = 0xff;
    out[12..16].copy_from_slice(&addr.octets());
    BpfIpBytes { u6_addr8: out }
}

fn routing_ip_version(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 1,
        IpAddr::V6(_) => 2,
    }
}

fn udp_process_name(raw: &[u8; 16]) -> Option<String> {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    (end > 0).then(|| String::from_utf8_lossy(&raw[..end]).into_owned())
}

fn bytes_of<T>(value: &T) -> &[u8] {
    unsafe { slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) }
}

fn bytes_of_mut<T>(value: &mut T) -> &mut [u8] {
    unsafe { slice::from_raw_parts_mut((value as *mut T).cast::<u8>(), size_of::<T>()) }
}
