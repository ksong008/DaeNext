use super::*;

#[derive(Clone, Debug)]
pub(crate) enum ResidentProxyProtocolPlan {
    VlessVisionTcpTls {
        key: [u8; 16],
    },
    VlessMuxTcpTls {
        key: [u8; 16],
    },
    Socks5Tcp {
        username: String,
        password: String,
    },
    HttpProxyTcp {
        username: String,
        password: String,
        transport: bool,
        transport_host: String,
        transport_path: String,
    },
    ShadowsocksAeadTcp {
        cipher: String,
        password: String,
        salt_len: usize,
    },
    Shadowsocks2022Tcp {
        cipher: String,
        password: String,
        salt_len: usize,
        packet_nonce_len: usize,
    },
    ShadowsocksSimpleObfsHttpTcp {
        cipher: String,
        password: String,
        salt_len: usize,
        host: String,
        path: String,
    },
    ShadowsocksSimpleObfsTlsTcp {
        cipher: String,
        password: String,
        salt_len: usize,
        host: String,
    },
    ShadowsocksV2rayPluginTlsWsTcp {
        cipher: String,
        password: String,
        salt_len: usize,
        host: String,
        path: String,
    },
    Shadowsocks2022SimpleObfsHttpTcp {
        cipher: String,
        password: String,
        salt_len: usize,
        host: String,
        path: String,
    },
    ShadowsocksRHttpSimpleTcp {
        cipher: String,
        password: String,
        obfs_host: String,
        obfs_port: u16,
    },
    TrojanTcpTls {
        password: String,
    },
    TrojanInnerShadowsocksTcpTls {
        password: String,
        inner_cipher: String,
        inner_password: String,
    },
    AnyTlsTcpTls {
        auth: String,
    },
    VmessAeadTcp {
        id: String,
        body_security: dae_outbound::vmess::VMessBodySecurity,
    },
    Hysteria2QuicTcp {
        auth: String,
        tls_identity: dae_outbound::hysteria2::Hysteria2TlsIdentity,
        max_tx: u64,
        max_rx: u64,
        congestion: Hysteria2CongestionConfig,
        obfs: ResidentHysteria2ObfsPlan,
        port_hop_ports: Vec<u16>,
        port_hop_interval: Duration,
    },
    TuicQuicTcp {
        uuid: String,
        password: String,
        alpn: Vec<String>,
        allow_insecure: bool,
        congestion: dae_outbound::tuic::TuicCongestionController,
        udp_relay_mode: dae_outbound::tuic::TuicUdpRelayMode,
    },
    JuicityQuicTcp {
        uuid: String,
        password: String,
        allow_insecure: bool,
        pinned_certchain_sha256: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentProtocolExecutorContract
{
    pub(in crate::production_runtime_owner::resident_dataplane) tcp_executor: &'static str,
    pub(in crate::production_runtime_owner::resident_dataplane) udp_executor: &'static str,
    pub(in crate::production_runtime_owner::resident_dataplane) packet_semantics: &'static str,
    pub(in crate::production_runtime_owner::resident_dataplane) udp_policy_closed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentHysteria2ObfsPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) mode: String,
    pub(in crate::production_runtime_owner::resident_dataplane) password: String,
}

impl ResidentHysteria2ObfsPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) fn none() -> Self {
        Self {
            mode: String::new(),
            password: String::new(),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn salamander(
        password: String,
    ) -> Self {
        Self {
            mode: "salamander".to_owned(),
            password,
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn is_salamander(&self) -> bool {
        self.mode == "salamander"
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn udp_packet_overhead(
        &self,
    ) -> usize {
        if self.is_salamander() {
            dae_outbound::hysteria2::HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD
        } else {
            0
        }
    }
}

impl ResidentProxyProtocolPlan {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::production_runtime_owner::resident_dataplane) fn executor_contract(
        &self,
    ) -> ResidentProtocolExecutorContract {
        match self {
            Self::VlessVisionTcpTls { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-vless-vision-tcp",
                udp_executor: "resident-vless-xudp",
                packet_semantics: "xudp",
                udp_policy_closed: false,
            },
            Self::VlessMuxTcpTls { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-vless-mux-tcp",
                // Policy-closed: this resident mux row is scoped to TCP stream
                // carriage and has no admitted UDP packet executor.
                udp_executor: "policy-closed",
                packet_semantics: "multiplexed-stream",
                udp_policy_closed: true,
            },
            Self::Socks5Tcp { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-socks5-connect",
                udp_executor: "resident-socks5-udp-associate",
                packet_semantics: "udp-associate",
                udp_policy_closed: false,
            },
            Self::HttpProxyTcp { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-http-connect",
                // Protocol-closed: RFC HTTP CONNECT establishes a TCP tunnel;
                // UDP requires a different protocol such as CONNECT-UDP/MASQUE.
                udp_executor: "protocol-closed",
                packet_semantics: "protocol-closed",
                udp_policy_closed: true,
            },
            Self::ShadowsocksAeadTcp { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-shadowsocks-aead-stream",
                udp_executor: "resident-shadowsocks-aead-datagram",
                packet_semantics: "datagram-aead",
                udp_policy_closed: false,
            },
            Self::Shadowsocks2022Tcp { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-shadowsocks-2022-stream",
                udp_executor: "resident-shadowsocks-2022-datagram",
                packet_semantics: "datagram-aead-2022",
                udp_policy_closed: false,
            },
            Self::ShadowsocksSimpleObfsHttpTcp { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-shadowsocks-simple-obfs-http-stream",
                // Policy-closed by the plugin contract: SIP003/plugin wrappers
                // are TCP stream wrappers here, not resident UDP packet relays.
                udp_executor: "plugin-udp-policy-closed",
                packet_semantics: "tcp-stream-wrapper",
                udp_policy_closed: true,
            },
            Self::ShadowsocksSimpleObfsTlsTcp { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-shadowsocks-simple-obfs-tls-stream",
                // Policy-closed by the plugin contract: simple-obfs TLS is a
                // TCP stream wrapper here, not a resident UDP packet relay.
                udp_executor: "plugin-udp-policy-closed",
                packet_semantics: "tcp-stream-wrapper",
                udp_policy_closed: true,
            },
            Self::ShadowsocksV2rayPluginTlsWsTcp { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-shadowsocks-v2ray-plugin-tls-websocket-stream",
                // Policy-closed by the plugin contract: v2ray-plugin over TLS
                // WebSocket is admitted as a TCP stream wrapper only.
                udp_executor: "plugin-udp-policy-closed",
                packet_semantics: "tcp-stream-wrapper",
                udp_policy_closed: true,
            },
            Self::Shadowsocks2022SimpleObfsHttpTcp { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-shadowsocks-2022-simple-obfs-http-stream",
                // Policy-closed by the plugin contract: AEAD-2022 simple-obfs
                // HTTP does not provide a resident UDP packet executor.
                udp_executor: "plugin-udp-policy-closed",
                packet_semantics: "tcp-stream-wrapper",
                udp_policy_closed: true,
            },
            Self::ShadowsocksRHttpSimpleTcp { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-shadowsocksr-http-simple-stream",
                // Policy-closed for this legacy row: SSR UDP needs a separate
                // legacy packet executor before resident UDP can admit it.
                udp_executor: "legacy-udp-policy-closed",
                packet_semantics: "tcp-stream-wrapper",
                udp_policy_closed: true,
            },
            Self::TrojanTcpTls { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-trojan-tls-stream",
                udp_executor: "resident-trojan-udp-over-tcp",
                packet_semantics: "udp-over-stream",
                udp_policy_closed: false,
            },
            Self::TrojanInnerShadowsocksTcpTls { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-trojan-inner-shadowsocks-stream",
                // Policy-closed: Trojan inner Shadowsocks wraps the TCP stream;
                // UDP needs explicit inner-encrypted packet semantics.
                udp_executor: "inner-encryption-udp-policy-closed",
                packet_semantics: "tcp-stream-wrapper",
                udp_policy_closed: true,
            },
            Self::AnyTlsTcpTls { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-anytls-frame-stream",
                udp_executor: "resident-anytls-packet-stream",
                packet_semantics: "udp-over-stream-or-datagram",
                udp_policy_closed: false,
            },
            Self::VmessAeadTcp { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-vmess-aead-stream",
                udp_executor: "resident-vmess-udp-over-tcp",
                packet_semantics: "udp-over-stream-or-datagram",
                udp_policy_closed: false,
            },
            Self::Hysteria2QuicTcp { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-hysteria2-quic-stream",
                udp_executor: "resident-hysteria2-quic-datagram",
                packet_semantics: "quic-datagram-or-stream",
                udp_policy_closed: false,
            },
            Self::TuicQuicTcp { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-tuic-quic-stream",
                udp_executor: "resident-tuic-quic-packet",
                packet_semantics: "quic-datagram-or-stream",
                udp_policy_closed: false,
            },
            Self::JuicityQuicTcp { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-juicity-quic-stream",
                udp_executor: "resident-juicity-quic-stream-packet",
                packet_semantics: "quic-datagram-or-stream",
                udp_policy_closed: false,
            },
        }
    }
}

impl ResidentProxyProtocolPlan {
    pub(super) fn compact_allocations(&mut self) {
        match self {
            Self::VlessVisionTcpTls { .. } | Self::VlessMuxTcpTls { .. } => {}
            Self::Socks5Tcp { username, password } => {
                compact_string(username);
                compact_string(password);
            }
            Self::HttpProxyTcp {
                username,
                password,
                transport_host,
                transport_path,
                ..
            } => {
                compact_string(username);
                compact_string(password);
                compact_string(transport_host);
                compact_string(transport_path);
            }
            Self::ShadowsocksAeadTcp {
                cipher, password, ..
            }
            | Self::Shadowsocks2022Tcp {
                cipher, password, ..
            } => {
                compact_string(cipher);
                compact_string(password);
            }
            Self::ShadowsocksSimpleObfsHttpTcp {
                cipher,
                password,
                host,
                path,
                ..
            }
            | Self::ShadowsocksV2rayPluginTlsWsTcp {
                cipher,
                password,
                host,
                path,
                ..
            }
            | Self::Shadowsocks2022SimpleObfsHttpTcp {
                cipher,
                password,
                host,
                path,
                ..
            } => {
                compact_string(cipher);
                compact_string(password);
                compact_string(host);
                compact_string(path);
            }
            Self::ShadowsocksSimpleObfsTlsTcp {
                cipher,
                password,
                host,
                ..
            } => {
                compact_string(cipher);
                compact_string(password);
                compact_string(host);
            }
            Self::ShadowsocksRHttpSimpleTcp {
                cipher,
                password,
                obfs_host,
                ..
            } => {
                compact_string(cipher);
                compact_string(password);
                compact_string(obfs_host);
            }
            Self::TrojanTcpTls { password }
            | Self::AnyTlsTcpTls { auth: password }
            | Self::VmessAeadTcp {
                id: password,
                body_security: _,
            } => compact_string(password),
            Self::TrojanInnerShadowsocksTcpTls {
                password,
                inner_cipher,
                inner_password,
            } => {
                compact_string(password);
                compact_string(inner_cipher);
                compact_string(inner_password);
            }
            Self::Hysteria2QuicTcp {
                auth,
                obfs,
                port_hop_ports,
                ..
            } => {
                compact_string(auth);
                compact_string(&mut obfs.mode);
                compact_string(&mut obfs.password);
                port_hop_ports.shrink_to_fit();
            }
            Self::TuicQuicTcp {
                uuid,
                password,
                alpn,
                ..
            } => {
                compact_string(uuid);
                compact_string(password);
                compact_string_vec(alpn);
            }
            Self::JuicityQuicTcp {
                uuid,
                password,
                pinned_certchain_sha256,
                ..
            } => {
                compact_string(uuid);
                compact_string(password);
                compact_string(pinned_certchain_sha256);
            }
        }
    }
}
