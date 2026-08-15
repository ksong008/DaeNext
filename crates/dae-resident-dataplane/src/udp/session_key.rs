use std::hash::{Hash, Hasher};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::*;

const STABLE_UDP_SHARD_HASH_OFFSET: u64 = 0xcbf29ce484222325;
const STABLE_UDP_SHARD_HASH_PRIME: u64 = 0x100000001b3;

struct StableUdpShardHasher(u64);

impl Default for StableUdpShardHasher {
    fn default() -> Self {
        Self(STABLE_UDP_SHARD_HASH_OFFSET)
    }
}

impl Hasher for StableUdpShardHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(STABLE_UDP_SHARD_HASH_PRIME);
        }
    }
}

pub(super) fn stable_udp_shard_index<T>(key: &T, shard_count: usize) -> usize
where
    T: Hash + ?Sized,
{
    let shard_count = shard_count.max(1);
    let mut hasher = StableUdpShardHasher::default();
    key.hash(&mut hasher);
    (hasher.finish() as usize) % shard_count
}

#[derive(Clone, Debug)]
pub(super) struct UdpSessionKey {
    graph_id: String,
    graph_identity_hash: String,
    graph_link_hash: String,
    redacted_link_source: String,
    outbound: String,
    peer: SocketAddr,
    original_destination: SocketAddr,
    packet_semantics: UdpPacketSemantics,
    wire_identity: ResidentUdpWireIdentityContract,
    dispatch_lane: Option<u16>,
}

impl UdpSessionKey {
    pub(super) fn new(
        proxy: &ResidentProxyPlan,
        peer: SocketAddr,
        original_dst: SocketAddr,
    ) -> Self {
        Self::build(proxy, peer, original_dst, None)
    }

    #[cfg(test)]
    pub(super) fn with_dispatch_lane(
        proxy: &ResidentProxyPlan,
        peer: SocketAddr,
        original_dst: SocketAddr,
        dispatch_lane: u16,
    ) -> Self {
        Self::build(proxy, peer, original_dst, Some(dispatch_lane))
    }

    pub(super) fn new_with_graph_identity_hash(
        proxy: &ResidentProxyPlan,
        graph_identity_hash: &str,
        peer: SocketAddr,
        original_dst: SocketAddr,
    ) -> Self {
        Self::build_with_graph_identity_hash(proxy, graph_identity_hash, peer, original_dst, None)
    }

    pub(super) fn with_dispatch_lane_and_graph_identity_hash(
        proxy: &ResidentProxyPlan,
        graph_identity_hash: &str,
        peer: SocketAddr,
        original_dst: SocketAddr,
        dispatch_lane: u16,
    ) -> Self {
        Self::build_with_graph_identity_hash(
            proxy,
            graph_identity_hash,
            peer,
            original_dst,
            Some(dispatch_lane),
        )
    }

    fn build(
        proxy: &ResidentProxyPlan,
        peer: SocketAddr,
        original_dst: SocketAddr,
        dispatch_lane: Option<u16>,
    ) -> Self {
        let graph_identity_hash = graph_identity_hash(proxy);
        Self::build_with_graph_identity_hash(
            proxy,
            &graph_identity_hash,
            peer,
            original_dst,
            dispatch_lane,
        )
    }

    fn build_with_graph_identity_hash(
        proxy: &ResidentProxyPlan,
        graph_identity_hash: &str,
        peer: SocketAddr,
        original_dst: SocketAddr,
        dispatch_lane: Option<u16>,
    ) -> Self {
        let packet_semantics = udp_packet_semantics_for_destination(proxy, original_dst);
        let source_contract = udp_source_contract(proxy, packet_semantics);
        Self {
            graph_id: proxy.graph_id.clone(),
            graph_identity_hash: graph_identity_hash.to_owned(),
            graph_link_hash: proxy.graph_link_hash.clone(),
            redacted_link_source: proxy.redacted_link_source.clone(),
            outbound: proxy.group_name.clone(),
            peer,
            original_destination: original_dst,
            packet_semantics,
            wire_identity: source_contract.wire_identity(),
            dispatch_lane,
        }
    }

    pub(super) fn to_value(&self) -> Value {
        let mut value = packet_session_value(
            UdpPacketSessionIdentity {
                graph_id: self.graph_id.clone(),
                graph_identity_hash: self.graph_identity_hash.clone(),
                graph_link_hash: self.graph_link_hash.clone(),
                redacted_link_source: self.redacted_link_source.clone(),
                outbound: self.outbound.clone(),
                source_display: resident_socket_addr_display(self.peer),
                destination_display: resident_socket_addr_display(self.original_destination),
                peer: Some(self.peer),
                original_destination: self.original_destination,
                packet_semantics: self.packet_semantics,
                wire_identity: self.wire_identity,
                session_hash: session_hash(
                    &self.graph_identity_hash,
                    &self.outbound,
                    self.peer,
                    self.original_destination,
                    self.packet_semantics,
                ),
            },
            None,
        );
        if let Some(dispatch_lane) = self.dispatch_lane {
            let lane_hash = session_lane_hash(
                &self.graph_identity_hash,
                &self.outbound,
                self.peer,
                self.original_destination,
                self.packet_semantics,
                dispatch_lane,
            );
            value["dispatchLane"] = json!(dispatch_lane);
            value["sessionHash"] = json!(&lane_hash);
            value["sessionIdentity"]["dispatchLane"] = json!(dispatch_lane);
            value["sessionIdentity"]["sessionHash"] = json!(lane_hash);
        }
        value["sourceContract"] =
            source_contract_from_identity(self.packet_semantics, self.wire_identity).json();
        value
    }

    pub(super) fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub(super) fn original_destination(&self) -> SocketAddr {
        self.original_destination
    }

    pub(super) fn idle_timeout(&self, session_idle_timeout: Duration) -> Duration {
        match self.packet_semantics {
            UdpPacketSemantics::Dns => RESIDENT_UDP_DNS_SESSION_IDLE_TIMEOUT,
            _ => session_idle_timeout,
        }
    }
}

impl PartialEq for UdpSessionKey {
    fn eq(&self, other: &Self) -> bool {
        self.graph_identity_hash == other.graph_identity_hash
            && self.outbound == other.outbound
            && self.peer == other.peer
            && self.original_destination == other.original_destination
            && self.packet_semantics == other.packet_semantics
            && self.dispatch_lane == other.dispatch_lane
    }
}

impl Eq for UdpSessionKey {}

impl Hash for UdpSessionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.graph_identity_hash.hash(state);
        self.outbound.hash(state);
        self.peer.hash(state);
        self.original_destination.hash(state);
        self.packet_semantics.hash(state);
        self.dispatch_lane.hash(state);
    }
}

pub(super) fn dns_request_dispatch_lane(payload: &[u8], lane_count: usize) -> u16 {
    let lane_count = lane_count.max(1).min(u16::MAX as usize + 1);
    if lane_count == 1 {
        return 0;
    }
    let transaction_id = match payload {
        [high, low, ..] => u16::from_be_bytes([*high, *low]) as usize,
        [byte] => *byte as usize,
        [] => 0,
    };
    (transaction_id % lane_count) as u16
}

pub(super) struct UdpPacketSessionIdentity {
    graph_id: String,
    graph_identity_hash: String,
    graph_link_hash: String,
    redacted_link_source: String,
    outbound: String,
    source_display: String,
    destination_display: String,
    peer: Option<SocketAddr>,
    original_destination: SocketAddr,
    packet_semantics: UdpPacketSemantics,
    wire_identity: ResidentUdpWireIdentityContract,
    session_hash: String,
}

impl UdpPacketSessionIdentity {
    pub(super) fn from_socket(
        proxy: &ResidentProxyPlan,
        peer: SocketAddr,
        original_dst: SocketAddr,
        packet_semantics: UdpPacketSemantics,
    ) -> Self {
        let graph_identity_hash = graph_identity_hash(proxy);
        let outbound = proxy.group_name.clone();
        Self {
            graph_id: proxy.graph_id.clone(),
            graph_identity_hash: graph_identity_hash.clone(),
            graph_link_hash: proxy.graph_link_hash.clone(),
            redacted_link_source: proxy.redacted_link_source.clone(),
            outbound: outbound.clone(),
            source_display: resident_socket_addr_display(peer),
            destination_display: resident_socket_addr_display(original_dst),
            peer: Some(peer),
            original_destination: original_dst,
            packet_semantics,
            wire_identity: udp_source_contract(proxy, packet_semantics).wire_identity(),
            session_hash: session_hash(
                &graph_identity_hash,
                &outbound,
                peer,
                original_dst,
                packet_semantics,
            ),
        }
    }

    pub(super) fn probe(
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        packet_semantics: UdpPacketSemantics,
    ) -> Self {
        let graph_identity_hash = graph_identity_hash(proxy);
        let outbound = proxy.group_name.clone();
        let source_display = "probe".to_owned();
        Self {
            graph_id: proxy.graph_id.clone(),
            graph_identity_hash: graph_identity_hash.clone(),
            graph_link_hash: proxy.graph_link_hash.clone(),
            redacted_link_source: proxy.redacted_link_source.clone(),
            outbound: outbound.clone(),
            source_display,
            destination_display: resident_socket_addr_display(original_dst),
            peer: None,
            original_destination: original_dst,
            packet_semantics,
            wire_identity: udp_source_contract(proxy, packet_semantics).wire_identity(),
            session_hash: probe_session_hash(
                &graph_identity_hash,
                &outbound,
                original_dst,
                packet_semantics,
            ),
        }
    }
}

pub(super) fn packet_session_value(
    identity: UdpPacketSessionIdentity,
    handler: Option<&str>,
) -> Value {
    let peer = identity
        .peer
        .map(resident_socket_addr_display)
        .unwrap_or_else(|| identity.source_display.clone());
    let packet_semantics = identity.packet_semantics.as_str();
    let mut value = json!({
        "schemaVersion": 1,
        "manager": "resident-udp-session-manager",
        "graphId": &identity.graph_id,
        "graphIdentityHash": &identity.graph_identity_hash,
        "graphLinkHash": &identity.graph_link_hash,
        "redactedLinkSource": &identity.redacted_link_source,
        "outbound": &identity.outbound,
        "peer": peer,
        "originalDestination": resident_socket_addr_display(identity.original_destination),
        "sourceDisplay": &identity.source_display,
        "destinationDisplay": &identity.destination_display,
        "packetSemantics": packet_semantics,
        "sessionHash": &identity.session_hash,
        "limitSource": "resident-udp-session-limit",
        "sourceContract": source_contract_from_identity(
            identity.packet_semantics,
            identity.wire_identity,
        ).json(),
        "sessionIdentity": {
            "schemaVersion": 1,
            "graphIdentityHash": &identity.graph_identity_hash,
            "outbound": &identity.outbound,
            "sourceDisplay": &identity.source_display,
            "destinationDisplay": &identity.destination_display,
            "packetSemantics": packet_semantics,
            "sessionHash": &identity.session_hash,
        },
    });
    if let Some(handler) = handler {
        value["handler"] = json!(handler);
    }
    value
}

fn udp_source_contract(
    proxy: &ResidentProxyPlan,
    packet_semantics: UdpPacketSemantics,
) -> ResidentUdpSourceContract {
    if packet_semantics == UdpPacketSemantics::Dns {
        ResidentUdpSourceContract::managed_dns()
    } else {
        proxy.execution_plan().udp.source_contract()
    }
}

fn source_contract_from_identity(
    packet_semantics: UdpPacketSemantics,
    wire_identity: ResidentUdpWireIdentityContract,
) -> ResidentUdpSourceContract {
    if wire_identity == ResidentUdpWireIdentityContract::PolicyClosed {
        ResidentUdpSourceContract::policy_closed()
    } else if packet_semantics == UdpPacketSemantics::Dns {
        ResidentUdpSourceContract::managed_dns()
    } else {
        ResidentUdpSourceContract::fixed_target(wire_identity)
    }
}

pub(super) fn graph_identity_hash(proxy: &ResidentProxyPlan) -> String {
    compact_sha256("graph", &[&proxy.graph_id, &proxy.graph_link_hash])
}

fn session_hash(
    graph_identity_hash: &str,
    outbound: &str,
    peer: SocketAddr,
    original_dst: SocketAddr,
    packet_semantics: UdpPacketSemantics,
) -> String {
    full_sha256(
        "udp-session",
        &[
            graph_identity_hash,
            outbound,
            &peer.to_string(),
            &original_dst.to_string(),
            packet_semantics.as_str(),
        ],
    )
}

fn session_lane_hash(
    graph_identity_hash: &str,
    outbound: &str,
    peer: SocketAddr,
    original_dst: SocketAddr,
    packet_semantics: UdpPacketSemantics,
    dispatch_lane: u16,
) -> String {
    full_sha256(
        "udp-session-lane",
        &[
            graph_identity_hash,
            outbound,
            &peer.to_string(),
            &original_dst.to_string(),
            packet_semantics.as_str(),
            &dispatch_lane.to_string(),
        ],
    )
}

fn probe_session_hash(
    graph_identity_hash: &str,
    outbound: &str,
    original_dst: SocketAddr,
    packet_semantics: UdpPacketSemantics,
) -> String {
    full_sha256(
        "udp-probe-session",
        &[
            graph_identity_hash,
            outbound,
            "probe",
            &original_dst.to_string(),
            packet_semantics.as_str(),
        ],
    )
}

fn compact_sha256(domain: &str, parts: &[&str]) -> String {
    let digest = sha256_digest(domain, parts);
    format!("sha256:{}", &digest[..16])
}

fn full_sha256(domain: &str, parts: &[&str]) -> String {
    format!("sha256:{}", sha256_digest(domain, parts))
}

fn sha256_digest(domain: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    update_hash_part(&mut hasher, domain);
    for part in parts {
        update_hash_part(&mut hasher, part);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn update_hash_part(hasher: &mut Sha256, part: &str) {
    hasher.update((part.len() as u64).to_be_bytes());
    hasher.update(part.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_transaction_ids_distribute_stably_across_bounded_lanes() {
        assert_eq!(dns_request_dispatch_lane(&[0x00, 0x05], 1), 0);
        assert_eq!(dns_request_dispatch_lane(&[0x00, 0x05], 4), 1);
        assert_eq!(dns_request_dispatch_lane(&[0x00, 0x09], 4), 1);
        assert_eq!(dns_request_dispatch_lane(&[0x00, 0x06], 4), 2);
        assert_eq!(dns_request_dispatch_lane(&[0x03], 4), 3);
        assert_eq!(dns_request_dispatch_lane(&[], 4), 0);
    }

    #[test]
    fn stable_shard_hash_is_repeatable_and_bounded() {
        let key = ("graph", "outbound", "192.0.2.1:53");
        let first = stable_udp_shard_index(&key, 7);
        assert_eq!(first, stable_udp_shard_index(&key, 7));
        assert!(first < 7);
        assert_eq!(stable_udp_shard_index(&key, 1), 0);
    }
}
