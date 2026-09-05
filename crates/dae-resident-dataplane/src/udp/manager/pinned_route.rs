use super::*;
use dae_outbound_core::NetworkType;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct ResidentUdpRetainedResources {
    pub(super) has_pin: bool,
    pub(super) router: bool,
    pub(super) dns_runtime: bool,
}

// The proxy route keeps its reusable session key inline. Boxing it would add a
// heap allocation and pointer indirection to every pinned proxy route without
// changing ownership or the packet dispatch contract. Keep the existing
// bounded layout explicit while retaining the strict Clippy gate elsewhere.
#[expect(
    clippy::large_enum_variant,
    reason = "pinned proxy route intentionally keeps the reusable session key inline"
)]
#[derive(Clone)]
pub(super) enum ResidentUdpPinnedRoute {
    ResidentDns,
    Proxy {
        proxy: ResidentProxyBinding,
        session_key: UdpSessionKey,
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
            append_event_with_metadata(
                event_file,
                event_lock,
                ResidentEventMetadata::new(ResidentEventKind::UdpPacketSkipped),
                || json!({"event": "udp_packet_skipped", "reason": "missing original destination", "peer": resident_socket_addr_display(packet.peer)}),
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
                session_key,
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
                    session_key.with_dispatch_lane_for_session(dispatch_lane)
                } else {
                    session_key.clone()
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
