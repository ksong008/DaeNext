use super::*;
pub(in crate::production_runtime_owner::resident_dataplane) fn resident_udp_handler_name(
    handler: &ResidentProxyProtocolPlan,
) -> &'static str {
    match handler {
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. } => "vless-vision-tcp-tls",
        ResidentProxyProtocolPlan::VlessMuxTcpTls { .. } => "vless-mux-tcp-tls",
        ResidentProxyProtocolPlan::Socks5Tcp { .. } => "socks5-tcp",
        ResidentProxyProtocolPlan::HttpProxyTcp { .. } => "http-proxy-tcp",
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp { .. } => "shadowsocks-aead-tcp",
        ResidentProxyProtocolPlan::Shadowsocks2022Tcp { .. } => "shadowsocks-2022-tcp",
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. } => {
            "shadowsocks-simple-obfs-http-tcp"
        }
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp { .. } => {
            "shadowsocks-simple-obfs-tls-tcp"
        }
        ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. } => {
            "shadowsocks-v2ray-plugin-tls-websocket-tcp"
        }
        ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. } => {
            "shadowsocks-2022-simple-obfs-http-tcp"
        }
        ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp { .. } => {
            "shadowsocksr-http-simple-tcp"
        }
        ResidentProxyProtocolPlan::TrojanTcpTls { .. } => "trojan-tcp-tls",
        ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls { .. } => {
            "trojan-inner-shadowsocks-tcp-tls"
        }
        ResidentProxyProtocolPlan::AnyTlsTcpTls { .. } => "anytls-tcp-tls",
        ResidentProxyProtocolPlan::VmessAeadTcp { .. } => "vmess-aead-tcp",
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. } => "hysteria2-quic-tcp",
        ResidentProxyProtocolPlan::TuicQuicTcp { .. } => "tuic-quic-tcp",
        ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => "juicity-quic-tcp",
    }
}

pub(super) fn udp_packet_session_value(
    proxy: &ResidentProxyPlan,
    peer: &str,
    original_dst: &str,
    handler: &str,
    packet_semantics: &str,
) -> serde_json::Value {
    json!({
        "schemaVersion": 1,
        "manager": "resident-udp-session-manager",
        "graphId": proxy.graph_id,
        "outbound": proxy.group_name,
        "peer": peer,
        "originalDestination": original_dst,
        "packetSemantics": packet_semantics,
        "handler": handler,
        "limitSource": "resident-udp-session-limit",
    })
}

pub(super) fn udp_packet_semantics_for_destination(
    handler: &ResidentProxyProtocolPlan,
    original_dst: SocketAddrV4,
) -> &'static str {
    if original_dst.port() == 53 {
        "dns"
    } else {
        udp_packet_semantics(handler)
    }
}

pub(super) fn udp_packet_semantics(handler: &ResidentProxyProtocolPlan) -> &'static str {
    match handler {
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. } => "xudp",
        ResidentProxyProtocolPlan::VlessMuxTcpTls { .. } => "multiplexed-stream",
        ResidentProxyProtocolPlan::Socks5Tcp { .. } => "udp-associate",
        ResidentProxyProtocolPlan::HttpProxyTcp { .. } => "protocol-closed",
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp { .. } => "datagram-aead",
        ResidentProxyProtocolPlan::Shadowsocks2022Tcp { .. } => "datagram-aead-2022",
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. }
        | ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. } => {
            "plugin-udp-policy-closed"
        }
        ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp { .. } => "legacy-udp-fail-closed",
        ResidentProxyProtocolPlan::TrojanTcpTls { .. }
        | ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls { .. }
        | ResidentProxyProtocolPlan::AnyTlsTcpTls { .. }
        | ResidentProxyProtocolPlan::VmessAeadTcp { .. } => "udp-over-stream",
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. } => "quic-datagram",
        ResidentProxyProtocolPlan::TuicQuicTcp { .. } => "quic-packet",
        ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => "quic-stream-packet",
    }
}
