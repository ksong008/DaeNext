#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum UdpPacketSemantics {
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
    Direct,
}

impl UdpPacketSemantics {
    pub(crate) fn as_str(self) -> &'static str {
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
            Self::Direct => "direct",
        }
    }
}
