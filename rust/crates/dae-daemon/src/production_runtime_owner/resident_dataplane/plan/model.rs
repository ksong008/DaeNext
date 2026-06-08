#[derive(Clone, Debug, Eq, PartialEq)]
struct SelectedGroupNode {
    match_index: usize,
    tag: String,
    link: String,
    annotation_add_latency_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentNodeLinkShape {
    pub(super) tag: String,
    pub(super) scheme: String,
    pub(super) link: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentUtlsFingerprintPlan {
    pub(super) source: &'static str,
    pub(super) requested: String,
    pub(super) name: String,
    pub(super) canonical: String,
    pub(super) family: String,
    pub(super) client: String,
    pub(super) randomized: bool,
    pub(super) alpn_policy: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum GroupNodeSelection {
    Selected(Vec<SelectedGroupNode>),
    NoCandidate {
        explicit_name_filter: bool,
        unresolved_names: Vec<String>,
    },
}

#[derive(Clone, Debug)]
pub(super) enum ResidentProxyProtocolPlan {
    VlessVisionTcpTls {
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

#[derive(Clone, Debug)]
pub(super) struct ResidentProxyPlan {
    pub(super) graph_id: String,
    pub(super) graph_link_hash: String,
    pub(super) redacted_link_source: String,
    pub(super) protocol: String,
    pub(super) group_name: String,
    pub(super) group_policy: String,
    pub(super) node_tag: String,
    pub(super) server_host: String,
    pub(super) server_port: u16,
    pub(super) server_name: String,
    pub(super) alpn: Vec<String>,
    pub(super) flow: String,
    pub(super) net: String,
    pub(super) stream_host: String,
    pub(super) stream_path: String,
    pub(super) tls: String,
    pub(super) allow_insecure: bool,
    pub(super) utls_fingerprint: Option<ResidentUtlsFingerprintPlan>,
    pub(super) handler: ResidentProxyProtocolPlan,
    pub(super) chain_parent: Option<Box<ResidentProxyPlan>>,
    pub(super) mark: u32,
    pub(super) mptcp: bool,
}

impl ResidentProxyPlan {
    fn executable_graph_descriptor(&self) -> ResidentExecutableGraphDescriptor {
        ResidentExecutableGraphDescriptor::from_proxy(self)
    }

    pub(super) fn executable_graph_value(&self) -> Value {
        self.executable_graph_descriptor().to_value()
    }

    pub(super) fn executable_graph_value_for_reload_generation(
        &self,
        reload_generation: u64,
    ) -> Value {
        self.executable_graph_descriptor()
            .to_value_for_reload_generation(reload_generation)
    }

    pub(super) fn runtime_component_evidence_value(&self) -> Value {
        self.executable_graph_descriptor()
            .runtime_component_evidence_value()
    }

    pub(super) fn runtime_component_evidence_value_for_reload_generation(
        &self,
        reload_generation: u64,
    ) -> Value {
        self.executable_graph_descriptor()
            .runtime_component_evidence_value_for_reload_generation(reload_generation)
    }

    pub(super) fn vless_key(&self) -> Result<[u8; 16], String> {
        match self.handler {
            ResidentProxyProtocolPlan::VlessVisionTcpTls { key } => Ok(key),
            _ => Err(format!(
                "resident proxy {} node {} is not a VLESS handler",
                self.protocol, self.node_tag
            )),
        }
    }
}
