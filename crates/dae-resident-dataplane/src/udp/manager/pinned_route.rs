use super::*;
use dae_outbound::NetworkType;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct ResidentUdpRetainedResources {
    pub(super) has_pin: bool,
    pub(super) router: bool,
    pub(super) dns_runtime: bool,
}

#[derive(Clone)]
pub(super) enum ResidentUdpPinnedRoute {
    ResidentDns,
    Proxy {
        proxy: ResidentProxyBinding,
        graph_identity_hash: String,
        selected_network_type: NetworkType,
        force_proxy_packet: bool,
        route: ResidentUdpRouteSelection,
        data_udp_availability: ResidentDataUdpAvailabilityHandle,
        sniffed_domain: SharedUdpSniffedDomain,
        dscp: u8,
    },
    Direct {
        route: ResidentUdpRouteSelection,
        sniffed_domain: SharedUdpSniffedDomain,
        dscp: u8,
    },
    Block {
        route: ResidentUdpRouteSelection,
        sniffed_domain: SharedUdpSniffedDomain,
        dscp: u8,
    },
}

impl ResidentUdpPinnedRoute {
    fn uses_dns_fast_path(&self) -> bool {
        matches!(self, Self::ResidentDns)
    }

    pub(super) fn follows_active_generation(&self) -> bool {
        matches!(self, Self::ResidentDns)
    }

    pub(super) fn idle_timeout(
        &self,
        session_idle_timeout: Duration,
        proxy_session_idle_timeout: Duration,
    ) -> Duration {
        match self {
            Self::ResidentDns => RESIDENT_UDP_DNS_SESSION_IDLE_TIMEOUT,
            Self::Proxy { .. } => proxy_session_idle_timeout,
            Self::Direct { .. } | Self::Block { .. } => session_idle_timeout,
        }
    }

    pub(super) fn dispatch(
        &self,
        packet: UdpOriginalDstPacket,
        event_file: &Path,
        event_lock: &Arc<Mutex<()>>,
        dns_fast_path: Option<&ResidentDnsFastPathHandle>,
        session_shards: &ResidentUdpSessionShardHandle,
        forced_dns_session_lanes: usize,
    ) {
        let Some(original_dst) = packet.original_dst else {
            append_event(
                event_file,
                event_lock,
                json!({"event": "udp_packet_skipped", "reason": "missing original destination", "peer": resident_socket_addr_display(packet.peer)}),
            );
            return;
        };
        match self {
            Self::ResidentDns => {
                if let Some(dns_fast_path) = dns_fast_path {
                    dns_fast_path.try_dispatch(packet, original_dst);
                } else {
                    append_udp_route_selection_failed(
                        event_file,
                        event_lock,
                        packet.peer,
                        original_dst,
                        None,
                        "pinned resident DNS runtime is unavailable".to_owned(),
                    );
                }
            }
            Self::Proxy {
                proxy,
                graph_identity_hash,
                selected_network_type,
                force_proxy_packet,
                route,
                data_udp_availability,
                sniffed_domain,
                dscp,
            } => {
                let key = if *force_proxy_packet && resident_udp_dns_fast_path_applies(original_dst)
                {
                    let dispatch_lane =
                        dns_request_dispatch_lane(&packet.payload, forced_dns_session_lanes);
                    UdpSessionKey::with_dispatch_lane_and_graph_identity_hash(
                        proxy,
                        graph_identity_hash,
                        packet.peer,
                        original_dst,
                        dispatch_lane,
                    )
                } else {
                    UdpSessionKey::new_with_graph_identity_hash(
                        proxy,
                        graph_identity_hash,
                        packet.peer,
                        original_dst,
                    )
                };
                let managed = ManagedUdpPacket {
                    packet,
                    original_dst,
                    proxy: proxy.clone(),
                    data_udp_network_type: if *force_proxy_packet {
                        None
                    } else if selected_network_type.is_data_udp() {
                        Some(*selected_network_type)
                    } else {
                        Some(resident_data_udp_network_type(original_dst))
                    },
                    data_udp_availability: data_udp_availability.clone(),
                    force_proxy_packet: *force_proxy_packet,
                    dscp: *dscp,
                };
                session_shards.try_dispatch_proxy(key, managed, *route, sniffed_domain.clone());
            }
            Self::Direct {
                route,
                sniffed_domain,
                dscp,
            } => {
                let key = UdpDirectSessionKey::new(packet.peer, original_dst, route.final_mark);
                let managed = ManagedDirectUdpPacket {
                    packet,
                    original_dst,
                    dscp: *dscp,
                };
                session_shards.try_dispatch_direct(key, managed, *route, sniffed_domain.clone());
            }
            Self::Block {
                route,
                sniffed_domain,
                dscp,
            } => {
                let sniffed_domain = sniffed_domain.as_deref().unwrap_or_default();
                append_event_with_metadata(
                    event_file,
                    event_lock,
                    ResidentEventMetadata::new(ResidentEventKind::UdpRouteChosen),
                    || {
                        udp_route_chosen_event(
                            packet.peer,
                            original_dst,
                            route,
                            None,
                            None,
                            sniffed_domain,
                            *dscp,
                            false,
                            UDP_ROUTE_REASON_BLOCK,
                        )
                    },
                );
                append_event_with_metadata(
                    event_file,
                    event_lock,
                    ResidentEventMetadata::new(ResidentEventKind::UdpPacketDropped),
                    || {
                        json!({
                            "event": "udp_packet_dropped",
                            "reason": "resident UDP selected block outbound",
                            "peer": resident_socket_addr_display(packet.peer),
                            "original_dst": resident_socket_addr_display(original_dst),
                            "initial_outbound": route.initial_outbound,
                            "final_outbound": route.final_outbound,
                            "network": resident_udp_network_name(original_dst),
                            "dscp": dscp,
                        })
                    },
                );
            }
        }
    }
}

pub(super) fn retained_udp_resources_for_generation(
    pins: &HashMap<UdpGenerationPinKey, UdpGenerationPin>,
    generation: u64,
) -> ResidentUdpRetainedResources {
    let mut retained = ResidentUdpRetainedResources::default();
    for pin in pins.values().filter(|pin| pin.generation == generation) {
        retained.has_pin = true;
        match pin.route.as_ref() {
            Some(route) => {
                retained.dns_runtime |= route.uses_dns_fast_path();
            }
            None => {
                retained.router = true;
                retained.dns_runtime = true;
            }
        }
    }
    retained
}
