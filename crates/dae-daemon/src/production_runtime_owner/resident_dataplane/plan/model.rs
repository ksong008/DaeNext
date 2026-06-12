use super::*;
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SelectedGroupNode {
    pub(in crate::production_runtime_owner::resident_dataplane) match_index: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) tag: String,
    pub(in crate::production_runtime_owner::resident_dataplane) link: String,
    pub(in crate::production_runtime_owner::resident_dataplane) annotation_add_latency_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentNodeLinkShape {
    pub(in crate::production_runtime_owner::resident_dataplane) tag: String,
    pub(in crate::production_runtime_owner::resident_dataplane) scheme: String,
    pub(in crate::production_runtime_owner::resident_dataplane) link: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentUtlsFingerprintPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) source: &'static str,
    pub(in crate::production_runtime_owner::resident_dataplane) requested: String,
    pub(in crate::production_runtime_owner::resident_dataplane) name: String,
    pub(in crate::production_runtime_owner::resident_dataplane) canonical: String,
    pub(in crate::production_runtime_owner::resident_dataplane) family: String,
    pub(in crate::production_runtime_owner::resident_dataplane) client: String,
    pub(in crate::production_runtime_owner::resident_dataplane) randomized: bool,
    pub(in crate::production_runtime_owner::resident_dataplane) alpn_policy: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentRealityUnderlayPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) public_key: [u8; 32],
    pub(in crate::production_runtime_owner::resident_dataplane) short_id: Vec<u8>,
    pub(in crate::production_runtime_owner::resident_dataplane) spider_x: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentXhttpEndpointPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) server_host: String,
    pub(in crate::production_runtime_owner::resident_dataplane) server_port: u16,
    pub(in crate::production_runtime_owner::resident_dataplane) server_name: String,
    pub(in crate::production_runtime_owner::resident_dataplane) alpn: Vec<String>,
    pub(in crate::production_runtime_owner::resident_dataplane) stream_host: String,
    pub(in crate::production_runtime_owner::resident_dataplane) stream_path: String,
    pub(in crate::production_runtime_owner::resident_dataplane) allow_insecure: bool,
    pub(in crate::production_runtime_owner::resident_dataplane) tls_fragment:
        Option<TlsFragmentOptions>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GroupNodeSelection {
    Selected(Vec<SelectedGroupNode>),
    NoCandidate {
        explicit_name_filter: bool,
        unresolved_names: Vec<String>,
    },
}

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
    },
    Hysteria2QuicTcp {
        auth: String,
        pin_sha256: String,
        max_rx: u64,
        port_hop_ports: Vec<u16>,
    },
    TuicQuicTcp {
        uuid: String,
        password: String,
        alpn: Vec<String>,
        allow_insecure: bool,
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
                udp_executor: "plugin-udp-policy-closed",
                packet_semantics: "tcp-stream-wrapper",
                udp_policy_closed: true,
            },
            Self::ShadowsocksSimpleObfsTlsTcp { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-shadowsocks-simple-obfs-tls-stream",
                udp_executor: "plugin-udp-policy-closed",
                packet_semantics: "tcp-stream-wrapper",
                udp_policy_closed: true,
            },
            Self::ShadowsocksV2rayPluginTlsWsTcp { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-shadowsocks-v2ray-plugin-tls-websocket-stream",
                udp_executor: "plugin-udp-policy-closed",
                packet_semantics: "tcp-stream-wrapper",
                udp_policy_closed: true,
            },
            Self::Shadowsocks2022SimpleObfsHttpTcp { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-shadowsocks-2022-simple-obfs-http-stream",
                udp_executor: "plugin-udp-policy-closed",
                packet_semantics: "tcp-stream-wrapper",
                udp_policy_closed: true,
            },
            Self::ShadowsocksRHttpSimpleTcp { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-shadowsocksr-http-simple-stream",
                udp_executor: "legacy-udp-policy-closed",
                packet_semantics: "tcp-stream-wrapper",
                udp_policy_closed: true,
            },
            Self::TrojanTcpTls { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-trojan-tls-stream",
                udp_executor: "resident-trojan-udp-over-tcp",
                packet_semantics: "udp-over-stream-or-datagram",
                udp_policy_closed: false,
            },
            Self::TrojanInnerShadowsocksTcpTls { .. } => ResidentProtocolExecutorContract {
                tcp_executor: "resident-trojan-inner-shadowsocks-stream",
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

#[derive(Clone, Debug)]
pub(crate) struct ResidentProxyPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) graph_id: String,
    pub(in crate::production_runtime_owner::resident_dataplane) graph_link_hash: String,
    pub(in crate::production_runtime_owner::resident_dataplane) redacted_link_source: String,
    pub(in crate::production_runtime_owner::resident_dataplane) protocol: String,
    pub(in crate::production_runtime_owner::resident_dataplane) group_name: String,
    pub(in crate::production_runtime_owner::resident_dataplane) group_policy: String,
    pub(in crate::production_runtime_owner::resident_dataplane) node_tag: String,
    pub(in crate::production_runtime_owner::resident_dataplane) server_host: String,
    pub(in crate::production_runtime_owner::resident_dataplane) server_port: u16,
    pub(in crate::production_runtime_owner::resident_dataplane) server_name: String,
    pub(in crate::production_runtime_owner::resident_dataplane) alpn: Vec<String>,
    pub(in crate::production_runtime_owner::resident_dataplane) flow: String,
    pub(in crate::production_runtime_owner::resident_dataplane) net: String,
    pub(in crate::production_runtime_owner::resident_dataplane) stream_host: String,
    pub(in crate::production_runtime_owner::resident_dataplane) stream_path: String,
    pub(in crate::production_runtime_owner::resident_dataplane) xhttp_download:
        Option<ResidentXhttpEndpointPlan>,
    pub(in crate::production_runtime_owner::resident_dataplane) tls: String,
    pub(in crate::production_runtime_owner::resident_dataplane) allow_insecure: bool,
    pub(in crate::production_runtime_owner::resident_dataplane) tls_fragment:
        Option<TlsFragmentOptions>,
    pub(in crate::production_runtime_owner::resident_dataplane) utls_fingerprint:
        Option<ResidentUtlsFingerprintPlan>,
    pub(in crate::production_runtime_owner::resident_dataplane) reality:
        Option<ResidentRealityUnderlayPlan>,
    pub(in crate::production_runtime_owner::resident_dataplane) handler: ResidentProxyProtocolPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) chain_parent:
        Option<Arc<ResidentProxyPlan>>,
    pub(in crate::production_runtime_owner::resident_dataplane) mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane) mptcp: bool,
}

impl ResidentProxyPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) fn compact_allocations(&mut self) {
        compact_string(&mut self.graph_id);
        compact_string(&mut self.graph_link_hash);
        compact_string(&mut self.redacted_link_source);
        compact_string(&mut self.protocol);
        compact_string(&mut self.group_name);
        compact_string(&mut self.group_policy);
        compact_string(&mut self.node_tag);
        compact_string(&mut self.server_host);
        compact_string(&mut self.server_name);
        compact_string_vec(&mut self.alpn);
        compact_string(&mut self.flow);
        compact_string(&mut self.net);
        compact_string(&mut self.stream_host);
        compact_string(&mut self.stream_path);
        if let Some(download) = &mut self.xhttp_download {
            download.compact_allocations();
        }
        compact_string(&mut self.tls);
        if let Some(fingerprint) = &mut self.utls_fingerprint {
            fingerprint.compact_allocations();
        }
        if let Some(reality) = &mut self.reality {
            reality.compact_allocations();
        }
        self.handler.compact_allocations();
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn executable_graph_descriptor(
        &self,
    ) -> ResidentExecutableGraphDescriptor {
        ResidentExecutableGraphDescriptor::from_proxy(self)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn executable_graph_value(
        &self,
    ) -> Value {
        self.executable_graph_descriptor().to_value()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn executable_graph_value_for_reload_generation(
        &self,
        reload_generation: u64,
    ) -> Value {
        self.executable_graph_descriptor()
            .to_value_for_reload_generation(reload_generation)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn runtime_component_evidence_value(
        &self,
    ) -> Value {
        self.executable_graph_descriptor()
            .runtime_component_evidence_value()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn runtime_component_evidence_value_for_reload_generation(
        &self,
        reload_generation: u64,
    ) -> Value {
        self.executable_graph_descriptor()
            .runtime_component_evidence_value_for_reload_generation(reload_generation)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn vless_key(
        &self,
    ) -> Result<[u8; 16], String> {
        match self.handler {
            ResidentProxyProtocolPlan::VlessVisionTcpTls { key }
            | ResidentProxyProtocolPlan::VlessMuxTcpTls { key } => Ok(key),
            _ => Err(format!(
                "resident proxy {} node {} is not a VLESS handler",
                self.protocol, self.node_tag
            )),
        }
    }
}

impl ResidentXhttpEndpointPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) fn from_proxy(
        proxy: &ResidentProxyPlan,
    ) -> Self {
        Self {
            server_host: proxy.server_host.clone(),
            server_port: proxy.server_port,
            server_name: proxy.server_name.clone(),
            alpn: proxy.alpn.clone(),
            stream_host: proxy.stream_host.clone(),
            stream_path: proxy.stream_path.clone(),
            allow_insecure: proxy.allow_insecure,
            tls_fragment: proxy.tls_fragment.clone(),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn uses_h3(&self) -> bool {
        self.alpn.len() == 1 && self.alpn[0].trim().eq_ignore_ascii_case("h3")
    }

    fn compact_allocations(&mut self) {
        compact_string(&mut self.server_host);
        compact_string(&mut self.server_name);
        compact_string_vec(&mut self.alpn);
        compact_string(&mut self.stream_host);
        compact_string(&mut self.stream_path);
    }
}

impl ResidentUtlsFingerprintPlan {
    fn compact_allocations(&mut self) {
        compact_string(&mut self.requested);
        compact_string(&mut self.name);
        compact_string(&mut self.canonical);
        compact_string(&mut self.family);
        compact_string(&mut self.client);
        compact_string(&mut self.alpn_policy);
    }
}

impl ResidentRealityUnderlayPlan {
    fn compact_allocations(&mut self) {
        self.short_id.shrink_to_fit();
        compact_string(&mut self.spider_x);
    }
}

impl ResidentProxyProtocolPlan {
    fn compact_allocations(&mut self) {
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
            | Self::VmessAeadTcp { id: password } => compact_string(password),
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
                pin_sha256,
                port_hop_ports,
                ..
            } => {
                compact_string(auth);
                compact_string(pin_sha256);
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

fn compact_string(value: &mut String) {
    value.shrink_to_fit();
}

fn compact_string_vec(values: &mut Vec<String>) {
    for value in values.iter_mut() {
        compact_string(value);
    }
    values.shrink_to_fit();
}
