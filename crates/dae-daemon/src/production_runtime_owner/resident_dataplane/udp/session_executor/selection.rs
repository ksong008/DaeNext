use super::*;
use dae_dns::DNS_DEFAULT_PORT;

impl UdpSessionExecutor {
    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn new(
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
    ) -> Self {
        if original_dst.port() == DNS_DEFAULT_PORT {
            return Self::Dns;
        }
        Self::new_proxy_packet(proxy)
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn new_proxy_packet(
        proxy: &ResidentProxyPlan,
    ) -> Self {
        if let Some(reason) = resident_udp_chain_admission(proxy).unsupported_reason() {
            return Self::fail_closed(reason);
        }
        match &proxy.handler {
            ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
                cipher,
                password,
                salt_len,
            } => Self::ShadowsocksAead(ShadowsocksAeadDatagramSession::new(
                cipher.clone(),
                password.clone(),
                *salt_len,
            )),
            ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
                cipher,
                password,
                packet_nonce_len,
                ..
            } => Self::Shadowsocks2022(Shadowsocks2022DatagramSession::new(
                cipher.clone(),
                password.clone(),
                *packet_nonce_len,
            )),
            ResidentProxyProtocolPlan::Socks5Tcp { .. } => {
                Self::Socks5(Socks5UdpAssociateSession::default())
            }
            ResidentProxyProtocolPlan::VlessVisionTcpTls { .. } => {
                if matches!(proxy.net.as_str(), "" | "tcp") && is_xtls_rprx_vision_flow(&proxy.flow)
                {
                    Self::VlessVision(VlessXudpStreamSession::default())
                } else if proxy.flow.is_empty() {
                    match (proxy.net.as_str(), proxy.tls.as_str()) {
                        ("" | "tcp", "" | "none") => {
                            Self::VlessStandard(VlessStandardUdpOverStreamSession::plain())
                        }
                        ("" | "tcp", _) => {
                            Self::VlessStandard(VlessStandardUdpOverStreamSession::tls())
                        }
                        ("websocket", "" | "none") => {
                            Self::VlessStandard(VlessStandardUdpOverStreamSession::websocket_plain())
                        }
                        ("websocket", _) => {
                            Self::VlessStandard(VlessStandardUdpOverStreamSession::websocket_tls())
                        }
                        ("httpupgrade", "" | "none") => Self::VlessStandard(
                            VlessStandardUdpOverStreamSession::httpupgrade_plain(),
                        ),
                        ("httpupgrade", _) => {
                            Self::VlessStandard(VlessStandardUdpOverStreamSession::httpupgrade_tls())
                        }
                        ("grpc", "" | "none") | ("h2", "" | "none") => Self::fail_closed(
                            "VLESS HTTP/2 UDP transport requires a TLS or Reality underlay",
                        ),
                        ("grpc", _) => {
                            Self::VlessStandard(VlessStandardUdpOverStreamSession::grpc_tls())
                        }
                        ("h2", _) => {
                            Self::VlessStandard(VlessStandardUdpOverStreamSession::h2_tls())
                        }
                        _ if proxy.net == "xhttp" && resident_xhttp_uses_h3(proxy) => {
                            Self::VlessXhttpH3(VlessXhttpH3UdpSession::default())
                        }
                        _ if proxy.net == "xhttp" => {
                            Self::VlessXhttpH2(VlessXhttpH2UdpSession::default())
                        }
                        _ => Self::fail_closed(
                            "VLESS wrapped-stream UDP requires a matching packet-over-wrapper executor for this transport and flow combination",
                        ),
                    }
                } else {
                    Self::fail_closed(
                        "VLESS wrapped-stream UDP requires a matching packet-over-wrapper executor for this transport and flow combination",
                    )
                }
            }
            ResidentProxyProtocolPlan::TrojanTcpTls { password } => match proxy.net.as_str() {
                "" | "tcp" => Self::Trojan(TrojanUdpStreamSession::new(password.clone())),
                "websocket" | "httpupgrade" | "grpc" => Self::fail_closed(
                    "Trojan wrapped-stream UDP requires a matching packet-over-wrapper executor for this transport",
                ),
                _ => Self::fail_closed(
                    "Trojan UDP requires a supported stream transport before resident UDP can admit this shape",
                ),
            },
            ResidentProxyProtocolPlan::VmessAeadTcp { id } => {
                match (proxy.net.as_str(), proxy.tls.as_str()) {
                    ("" | "tcp", "" | "none") => {
                        Self::VmessAead(VmessAeadUdpOverTcpSession::plain(id.clone()))
                    }
                    ("" | "tcp", "tls") => {
                        Self::VmessAead(VmessAeadUdpOverTcpSession::tls(id.clone()))
                    }
                    ("websocket", "" | "none") => {
                        Self::VmessAead(VmessAeadUdpOverTcpSession::websocket_plain(id.clone()))
                    }
                    ("websocket", "tls") => {
                        Self::VmessAead(VmessAeadUdpOverTcpSession::websocket_tls(id.clone()))
                    }
                    ("httpupgrade", "" | "none") => {
                        Self::VmessAead(VmessAeadUdpOverTcpSession::httpupgrade_plain(id.clone()))
                    }
                    ("httpupgrade", "tls") => {
                        Self::VmessAead(VmessAeadUdpOverTcpSession::httpupgrade_tls(id.clone()))
                    }
                    ("grpc", "tls") => {
                        Self::VmessAead(VmessAeadUdpOverTcpSession::grpc_tls(id.clone()))
                    }
                    _ => Self::fail_closed(
                        "VMess UDP wrapper requires a matching packet-over-wrapper executor for this transport and security combination",
                    ),
                }
            }
            ResidentProxyProtocolPlan::AnyTlsTcpTls { auth } => {
                Self::AnyTls(AnyTlsPacketStreamSession::new(auth.clone()))
            }
            ResidentProxyProtocolPlan::Hysteria2QuicTcp {
                auth,
                allow_insecure,
                pin_sha256,
                max_rx,
                obfs,
                port_hop_ports,
            } => Self::Hysteria2(Hysteria2QuicDatagramSession::new(
                auth.clone(),
                *allow_insecure,
                pin_sha256.clone(),
                *max_rx,
                obfs.clone(),
                port_hop_ports.clone(),
            )),
            ResidentProxyProtocolPlan::TuicQuicTcp {
                uuid,
                password,
                alpn,
                allow_insecure,
            } => Self::Tuic(TuicQuicDatagramSession::new(
                uuid.clone(),
                password.clone(),
                alpn.clone(),
                *allow_insecure,
            )),
            ResidentProxyProtocolPlan::JuicityQuicTcp {
                uuid,
                password,
                allow_insecure,
                pinned_certchain_sha256,
            } => Self::Juicity(JuicityQuicStreamPacketSession::new(
                uuid.clone(),
                password.clone(),
                *allow_insecure,
                pinned_certchain_sha256.clone(),
            )),
            ResidentProxyProtocolPlan::VlessMuxTcpTls { .. } => Self::fail_closed(
                "resident VLESS mux handler does not admit UDP packets; mux row is TCP stream scoped",
            ),
            ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. }
            | ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp { .. }
            | ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. }
            | ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. } => {
                Self::fail_closed(
                    "SIP003 plugin UDP is not part of the required plugin contract; resident UDP keeps plugin UDP policy-closed without alternate execution",
                )
            }
            ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp { .. } => Self::fail_closed(
                "ShadowsocksR legacy UDP requires an SSR protocol and obfs packet executor before resident UDP can admit this shape",
            ),
            ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls { .. } => Self::fail_closed(
                "Trojan inner-encryption UDP requires inner-encrypted packet semantics before resident UDP can admit this shape",
            ),
            ResidentProxyProtocolPlan::HttpProxyTcp { .. } => {
                Self::fail_closed("HTTP CONNECT has no UDP relay semantics in resident dataplane")
            }
        }
    }

    fn fail_closed(reason: &str) -> Self {
        Self::FailClosed {
            reason: reason.to_owned(),
        }
    }
}
