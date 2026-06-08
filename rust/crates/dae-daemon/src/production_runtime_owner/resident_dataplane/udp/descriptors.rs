use super::*;
pub(super) fn resident_udp_handler_name(handler: &ResidentProxyProtocolPlan) -> &'static str {
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
) -> serde_json::Value {
    json!({
        "schemaVersion": 1,
        "manager": "bounded-resident-packet-session",
        "graphId": proxy.graph_id,
        "outbound": proxy.group_name,
        "peer": peer,
        "originalDestination": original_dst,
        "packetSemantics": udp_packet_semantics(&proxy.handler),
        "handler": handler,
        "limitSource": "resident-udp-packet-worker-limit",
    })
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
        | ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp { .. } => "plugin-wrapper-stream",
        ResidentProxyProtocolPlan::TrojanTcpTls { .. }
        | ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls { .. }
        | ResidentProxyProtocolPlan::AnyTlsTcpTls { .. }
        | ResidentProxyProtocolPlan::VmessAeadTcp { .. } => "udp-over-stream",
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. } => "quic-datagram",
        ResidentProxyProtocolPlan::TuicQuicTcp { .. } => "quic-packet",
        ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => "quic-stream-packet",
    }
}
