use super::*;
use dae_dns::DNS_DEFAULT_PORT;

impl UdpSessionExecutor {
    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn new(
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
    ) -> Self {
        if original_dst.port() == DNS_DEFAULT_PORT {
            return Self::Dns;
        }
        Self::new_proxy_packet(proxy)
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn new_proxy_packet(
        proxy: &ResidentProxyPlan,
    ) -> Self {
        Self::new_proxy_packet_with_optional_transport_owner(
            Arc::new(proxy.clone()),
            None,
            None,
            None,
            None,
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn new_with_transport_owner(
        proxy: Arc<ResidentProxyPlan>,
        original_dst: SocketAddr,
        owner_registry: Hysteria2OwnerRegistryHandle,
        tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
        juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
        anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    ) -> Self {
        if original_dst.port() == DNS_DEFAULT_PORT {
            return Self::Dns;
        }
        Self::new_proxy_packet_with_transport_owner(
            proxy,
            owner_registry,
            tuic_owner_registry,
            juicity_owner_registry,
            anytls_owner_registry,
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn new_proxy_packet_with_transport_owner(
        proxy: Arc<ResidentProxyPlan>,
        owner_registry: Hysteria2OwnerRegistryHandle,
        tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
        juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
        anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    ) -> Self {
        Self::new_proxy_packet_with_optional_transport_owner(
            proxy,
            Some(owner_registry),
            tuic_owner_registry,
            juicity_owner_registry,
            anytls_owner_registry,
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn new_proxy_packet_with_optional_transport_owner(
        proxy: Arc<ResidentProxyPlan>,
        owner_registry: Option<Hysteria2OwnerRegistryHandle>,
        tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
        juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
        anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    ) -> Self {
        if let Some(reason) = resident_udp_chain_admission(&proxy).unsupported_reason() {
            return Self::fail_closed(reason);
        }

        let factory = proxy.execution_plan().udp;
        match (&proxy.handler, factory) {
            (
                ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
                    cipher,
                    password,
                    salt_len,
                },
                ResidentUdpExecutorFactory::ShadowsocksAead,
            ) => Self::ShadowsocksAead(ShadowsocksAeadDatagramSession::new(
                cipher.clone(),
                password.clone(),
                *salt_len,
            )),
            (
                ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
                    cipher,
                    password,
                    packet_nonce_len,
                    ..
                },
                ResidentUdpExecutorFactory::Shadowsocks2022,
            ) => Self::Shadowsocks2022(Shadowsocks2022DatagramSession::new(
                cipher.clone(),
                password.clone(),
                *packet_nonce_len,
            )),
            (
                ResidentProxyProtocolPlan::Socks5Tcp { .. },
                ResidentUdpExecutorFactory::Socks5Associate,
            ) => Self::Socks5(Socks5UdpAssociateSession::default()),
            (
                ResidentProxyProtocolPlan::VlessVisionTcpTls { .. },
                ResidentUdpExecutorFactory::VlessVisionXudp,
            ) => Self::VlessVision(VlessXudpStreamSession::default()),
            (
                ResidentProxyProtocolPlan::VlessVisionTcpTls { .. },
                ResidentUdpExecutorFactory::VlessStandard(transport),
            ) => Self::new_vless_standard(transport),
            (
                ResidentProxyProtocolPlan::TrojanTcpTls { password },
                ResidentUdpExecutorFactory::Trojan(transport),
            ) => Self::new_trojan(password, transport),
            (
                ResidentProxyProtocolPlan::VmessAeadTcp { id, body_security },
                ResidentUdpExecutorFactory::Vmess(transport),
            ) => Self::new_vmess(id, *body_security, transport),
            (
                ResidentProxyProtocolPlan::AnyTlsTcpTls { .. },
                ResidentUdpExecutorFactory::AnyTlsPacketStream,
            ) => Self::AnyTls(AnyTlsPacketStreamSession::new(
                Arc::clone(&proxy),
                anytls_owner_registry,
            )),
            (
                ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. },
                ResidentUdpExecutorFactory::Hysteria2Datagram,
            ) => Self::Hysteria2(Hysteria2QuicDatagramSession::new(
                Arc::clone(&proxy),
                owner_registry,
            )),
            (
                ResidentProxyProtocolPlan::TuicQuicTcp { .. },
                ResidentUdpExecutorFactory::TuicPacket,
            ) => Self::Tuic(TuicQuicDatagramSession::new(
                Arc::clone(&proxy),
                tuic_owner_registry,
            )),
            (
                ResidentProxyProtocolPlan::JuicityQuicTcp { .. },
                ResidentUdpExecutorFactory::JuicityStreamPacket,
            ) => Self::Juicity(JuicityQuicStreamPacketSession::new(
                Arc::clone(&proxy),
                juicity_owner_registry,
            )),
            (_, ResidentUdpExecutorFactory::PolicyClosed(reason)) => {
                Self::fail_closed(reason.reason())
            }
            _ => Self::fail_closed(
                "resident UDP executor factory does not match materialized protocol credentials",
            ),
        }
    }

    fn new_vless_standard(transport: ResidentStreamPacketTransport) -> Self {
        let session = match transport {
            ResidentStreamPacketTransport::PlainTcp => VlessStandardUdpOverStreamSession::plain(),
            ResidentStreamPacketTransport::TlsTcp => VlessStandardUdpOverStreamSession::tls(),
            ResidentStreamPacketTransport::WebSocketPlain => {
                VlessStandardUdpOverStreamSession::websocket_plain()
            }
            ResidentStreamPacketTransport::WebSocketTls => {
                VlessStandardUdpOverStreamSession::websocket_tls()
            }
            ResidentStreamPacketTransport::HttpUpgradePlain => {
                VlessStandardUdpOverStreamSession::httpupgrade_plain()
            }
            ResidentStreamPacketTransport::HttpUpgradeTls => {
                VlessStandardUdpOverStreamSession::httpupgrade_tls()
            }
            ResidentStreamPacketTransport::GrpcTls => VlessStandardUdpOverStreamSession::grpc_tls(),
            ResidentStreamPacketTransport::H2Tls => VlessStandardUdpOverStreamSession::h2_tls(),
            ResidentStreamPacketTransport::XhttpH1 | ResidentStreamPacketTransport::XhttpH2 => {
                return Self::VlessXhttpH2(VlessXhttpH2UdpSession::default());
            }
            ResidentStreamPacketTransport::XhttpH3 => {
                return Self::VlessXhttpH3(VlessXhttpH3UdpSession::default());
            }
        };
        Self::VlessStandard(session)
    }

    fn new_trojan(password: &str, transport: ResidentStreamPacketTransport) -> Self {
        let session = match transport {
            ResidentStreamPacketTransport::TlsTcp => {
                TrojanUdpStreamSession::tls(password.to_owned())
            }
            ResidentStreamPacketTransport::WebSocketTls => {
                TrojanUdpStreamSession::websocket(password.to_owned())
            }
            ResidentStreamPacketTransport::HttpUpgradeTls => {
                TrojanUdpStreamSession::httpupgrade(password.to_owned())
            }
            ResidentStreamPacketTransport::GrpcTls => {
                TrojanUdpStreamSession::grpc(password.to_owned())
            }
            _ => return Self::fail_closed("materialized Trojan UDP transport is invalid"),
        };
        Self::Trojan(session)
    }

    fn new_vmess(
        id: &str,
        body_security: dae_outbound::vmess::VMessBodySecurity,
        transport: ResidentStreamPacketTransport,
    ) -> Self {
        let session = match transport {
            ResidentStreamPacketTransport::PlainTcp => {
                VmessAeadUdpOverTcpSession::plain(id.to_owned(), body_security)
            }
            ResidentStreamPacketTransport::TlsTcp => {
                VmessAeadUdpOverTcpSession::tls(id.to_owned(), body_security)
            }
            ResidentStreamPacketTransport::WebSocketPlain => {
                VmessAeadUdpOverTcpSession::websocket_plain(id.to_owned(), body_security)
            }
            ResidentStreamPacketTransport::WebSocketTls => {
                VmessAeadUdpOverTcpSession::websocket_tls(id.to_owned(), body_security)
            }
            ResidentStreamPacketTransport::HttpUpgradePlain => {
                VmessAeadUdpOverTcpSession::httpupgrade_plain(id.to_owned(), body_security)
            }
            ResidentStreamPacketTransport::HttpUpgradeTls => {
                VmessAeadUdpOverTcpSession::httpupgrade_tls(id.to_owned(), body_security)
            }
            ResidentStreamPacketTransport::GrpcTls => {
                VmessAeadUdpOverTcpSession::grpc_tls(id.to_owned(), body_security)
            }
            _ => return Self::fail_closed("materialized VMess UDP transport is invalid"),
        };
        Self::VmessAead(session)
    }

    fn fail_closed(reason: &str) -> Self {
        Self::FailClosed {
            reason: reason.to_owned(),
        }
    }
}
