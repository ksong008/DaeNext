use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use dae_ebpf_support::BpfRoutingResult;
use dae_sniffing::{PacketSniffer, is_sniffing_error};

use super::router::ResidentUdpRouter;
use super::*;

const UDP_PACKET_SNIFFER_TTL: Duration = Duration::from_secs(3);
const UDP_PACKET_SNIFFER_MAX_ENTRIES: usize = 1024;

#[derive(Clone, Copy, Eq)]
pub(super) struct UdpSniffKey {
    peer: SocketAddr,
    original_dst: SocketAddr,
}

impl UdpSniffKey {
    const fn new(peer: SocketAddr, original_dst: SocketAddr) -> Self {
        Self { peer, original_dst }
    }
}

impl PartialEq for UdpSniffKey {
    fn eq(&self, other: &Self) -> bool {
        self.peer == other.peer && self.original_dst == other.original_dst
    }
}

impl Hash for UdpSniffKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.peer.hash(state);
        self.original_dst.hash(state);
    }
}

pub(super) struct UdpPendingSniffer {
    sniffer: PacketSniffer,
    packets: Vec<UdpOriginalDstPacket>,
    initial: BpfRoutingResult,
    created_at: Instant,
}

pub(super) struct UdpSniffReady {
    pub(super) packets: Vec<UdpOriginalDstPacket>,
    pub(super) initial: BpfRoutingResult,
    pub(super) sniffed_domain: String,
}

pub(super) enum UdpSniffDecision {
    Ready(UdpSniffReady),
    Pending,
}

pub(super) fn udp_sniff_reroute_decision(
    packet: UdpOriginalDstPacket,
    router: &ResidentUdpRouter,
    original_dst: SocketAddr,
    initial: BpfRoutingResult,
    sniffers: &mut HashMap<UdpSniffKey, UdpPendingSniffer>,
) -> UdpSniffDecision {
    prune_udp_sniffers(sniffers);
    if !router.needs_sniffed_domain_for_reroute(original_dst, initial) {
        return UdpSniffDecision::Ready(UdpSniffReady {
            packets: vec![packet],
            initial,
            sniffed_domain: String::new(),
        });
    }

    let key = UdpSniffKey::new(packet.peer, original_dst);
    if !sniffers.contains_key(&key) {
        if sniffers.len() >= UDP_PACKET_SNIFFER_MAX_ENTRIES {
            evict_oldest_udp_sniffer(sniffers);
        }
        sniffers.insert(
            key,
            UdpPendingSniffer {
                sniffer: PacketSniffer::new(&packet.payload),
                packets: vec![packet],
                initial,
                created_at: Instant::now(),
            },
        );
    } else if let Some(entry) = sniffers.get_mut(&key) {
        entry.sniffer.append_data(&packet.payload);
        entry.packets.push(packet);
    }

    let Some(entry) = sniffers.get_mut(&key) else {
        return UdpSniffDecision::Pending;
    };
    match entry.sniffer.sniff_udp() {
        Ok(sniffed_domain) => {
            let entry = sniffers.remove(&key).expect("sniffer entry exists");
            UdpSniffDecision::Ready(UdpSniffReady {
                packets: entry.packets,
                initial: entry.initial,
                sniffed_domain,
            })
        }
        Err(err) if entry.sniffer.need_more() && is_sniffing_error(&err) => {
            UdpSniffDecision::Pending
        }
        Err(_) => {
            let entry = sniffers.remove(&key).expect("sniffer entry exists");
            UdpSniffDecision::Ready(UdpSniffReady {
                packets: entry.packets,
                initial: entry.initial,
                sniffed_domain: String::new(),
            })
        }
    }
}

fn prune_udp_sniffers(sniffers: &mut HashMap<UdpSniffKey, UdpPendingSniffer>) {
    let now = Instant::now();
    sniffers.retain(|_, entry| now.duration_since(entry.created_at) <= UDP_PACKET_SNIFFER_TTL);
}

fn evict_oldest_udp_sniffer(sniffers: &mut HashMap<UdpSniffKey, UdpPendingSniffer>) {
    let Some(oldest) = sniffers
        .iter()
        .min_by_key(|(_, entry)| entry.created_at)
        .map(|(key, _)| *key)
    else {
        return;
    };
    sniffers.remove(&oldest);
}
