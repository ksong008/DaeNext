use std::hash::{Hash, Hasher};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::*;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum UdpPacketSemantics {
    Dns,
    Xudp,
    MultiplexedStream,
    UdpAssociate,
    ProtocolClosed,
    DatagramAead,
    DatagramAead2022,
    PluginUdpPolicyClosed,
    LegacyUdpFailClosed,
    UdpOverStream,
    QuicDatagram,
    QuicPacket,
    QuicStreamPacket,
}

impl UdpPacketSemantics {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Xudp => "xudp",
            Self::MultiplexedStream => "multiplexed-stream",
            Self::UdpAssociate => "udp-associate",
            Self::ProtocolClosed => "protocol-closed",
            Self::DatagramAead => "datagram-aead",
            Self::DatagramAead2022 => "datagram-aead-2022",
            Self::PluginUdpPolicyClosed => "plugin-udp-policy-closed",
            Self::LegacyUdpFailClosed => "legacy-udp-fail-closed",
            Self::UdpOverStream => "udp-over-stream",
            Self::QuicDatagram => "quic-datagram",
            Self::QuicPacket => "quic-packet",
            Self::QuicStreamPacket => "quic-stream-packet",
        }
    }
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
}

impl UdpSessionKey {
    pub(super) fn new(
        proxy: &ResidentProxyPlan,
        peer: SocketAddr,
        original_dst: SocketAddr,
    ) -> Self {
        Self {
            graph_id: proxy.graph_id.clone(),
            graph_identity_hash: graph_identity_hash(proxy),
            graph_link_hash: proxy.graph_link_hash.clone(),
            redacted_link_source: proxy.redacted_link_source.clone(),
            outbound: proxy.group_name.clone(),
            peer,
            original_destination: original_dst,
            packet_semantics: udp_packet_semantics_for_destination(proxy, original_dst),
        }
    }

    pub(super) fn to_value(&self) -> Value {
        packet_session_value(
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
                session_hash: session_hash(
                    &self.graph_identity_hash,
                    &self.outbound,
                    self.peer,
                    self.original_destination,
                    self.packet_semantics,
                ),
            },
            None,
        )
    }

    pub(super) fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub(super) fn original_destination(&self) -> SocketAddr {
        self.original_destination
    }
}

impl PartialEq for UdpSessionKey {
    fn eq(&self, other: &Self) -> bool {
        self.graph_identity_hash == other.graph_identity_hash
            && self.outbound == other.outbound
            && self.peer == other.peer
            && self.original_destination == other.original_destination
            && self.packet_semantics == other.packet_semantics
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
    }
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

fn graph_identity_hash(proxy: &ResidentProxyPlan) -> String {
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
