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
    pub(in crate::production_runtime_owner::resident_dataplane) tls: String,
    pub(in crate::production_runtime_owner::resident_dataplane) allow_insecure: bool,
    pub(in crate::production_runtime_owner::resident_dataplane) tls_fragment:
        Option<TlsFragmentOptions>,
    pub(in crate::production_runtime_owner::resident_dataplane) utls_fingerprint:
        Option<ResidentUtlsFingerprintPlan>,
    pub(in crate::production_runtime_owner::resident_dataplane) handler: ResidentProxyProtocolPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) chain_parent:
        Option<Box<ResidentProxyPlan>>,
    pub(in crate::production_runtime_owner::resident_dataplane) mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane) mptcp: bool,
}

impl ResidentProxyPlan {
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
            ResidentProxyProtocolPlan::VlessVisionTcpTls { key } => Ok(key),
            _ => Err(format!(
                "resident proxy {} node {} is not a VLESS handler",
                self.protocol, self.node_tag
            )),
        }
    }
}
