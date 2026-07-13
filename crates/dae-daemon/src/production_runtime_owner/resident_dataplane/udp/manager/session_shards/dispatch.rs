use super::*;

impl ResidentUdpSessionShardHandle {
    pub(in super::super) fn try_dispatch_proxy(
        &self,
        key: UdpSessionKey,
        managed: ManagedUdpPacket,
        route: ResidentUdpRouteSelection,
        sniffed_domain: SharedUdpSniffedDomain,
    ) {
        let shard_index = stable_udp_shard_index(&key, self.senders.len());
        let packet = ResidentUdpShardPacket::Proxy(ResidentUdpProxyShardPacket {
            key,
            managed,
            route,
            sniffed_domain,
        });
        self.try_dispatch(shard_index, packet);
    }

    pub(in super::super) fn try_dispatch_direct(
        &self,
        key: UdpDirectSessionKey,
        managed: ManagedDirectUdpPacket,
        route: ResidentUdpRouteSelection,
        sniffed_domain: SharedUdpSniffedDomain,
    ) {
        let shard_index = stable_udp_shard_index(&key, self.senders.len());
        let packet = ResidentUdpShardPacket::Direct(ResidentUdpDirectShardPacket {
            key,
            managed,
            route,
            sniffed_domain,
        });
        self.try_dispatch(shard_index, packet);
    }

    fn try_dispatch(&self, shard_index: usize, packet: ResidentUdpShardPacket) {
        if self.closing.load(Ordering::Acquire) {
            self.record_dispatch_rejected(packet, "resident UDP sessions are closing");
            return;
        }
        let Some(sender) = self.senders.get(shard_index) else {
            self.record_dispatch_rejected(packet, "resident UDP session actor is missing");
            return;
        };
        match sender.try_send(packet) {
            Ok(()) => self.metrics.udp_session_dispatch_queued(),
            Err(mpsc::error::TrySendError::Full(packet)) => {
                self.metrics.udp_session_dispatch_queue_full();
                self.record_dispatch_rejected(packet, UDP_ROUTE_REASON_DISPATCH_QUEUE_FULL);
            }
            Err(mpsc::error::TrySendError::Closed(packet)) => {
                self.record_dispatch_rejected(packet, "resident UDP session actor stopped");
            }
        }
    }

    fn record_dispatch_rejected(&self, packet: ResidentUdpShardPacket, reason: &str) {
        match packet {
            ResidentUdpShardPacket::Proxy(packet) => append_event(
                &self.event_file,
                &self.event_lock,
                udp_route_chosen_event(
                    packet.managed.packet.peer,
                    packet.managed.original_dst,
                    &packet.route,
                    Some(&packet.managed.proxy),
                    Some(&packet.key),
                    packet.sniffed_domain.as_deref().unwrap_or_default(),
                    packet.managed.dscp,
                    false,
                    reason,
                ),
            ),
            ResidentUdpShardPacket::Direct(packet) => append_event(
                &self.event_file,
                &self.event_lock,
                udp_direct_route_chosen_event(
                    packet.managed.packet.peer,
                    packet.managed.original_dst,
                    &packet.route,
                    &packet.key,
                    packet.sniffed_domain.as_deref().unwrap_or_default(),
                    packet.managed.dscp,
                    false,
                    reason,
                ),
            ),
        }
    }
}
