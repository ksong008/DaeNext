use super::*;
pub(in crate::production_runtime_owner::resident_dataplane) const RESIDENT_CONTROL_PLANE_SO_MARK:
    u32 = 0x100;

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
    pub(in crate::production_runtime_owner::resident_dataplane) mode: ResidentXhttpMode,
    pub(in crate::production_runtime_owner::resident_dataplane) settings: ResidentXhttpSettingsPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) xmux: Option<ResidentXhttpXmuxPlan>,
    pub(in crate::production_runtime_owner::resident_dataplane) allow_insecure: bool,
    pub(in crate::production_runtime_owner::resident_dataplane) tls_fragment:
        Option<TlsFragmentOptions>,
    pub(in crate::production_runtime_owner::resident_dataplane) reality:
        Option<ResidentRealityUnderlayPlan>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentXhttpSettingsPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) headers: BTreeMap<String, String>,
    pub(in crate::production_runtime_owner::resident_dataplane) x_padding_bytes: Option<(i32, i32)>,
    pub(in crate::production_runtime_owner::resident_dataplane) x_padding_obfs_mode: bool,
    pub(in crate::production_runtime_owner::resident_dataplane) x_padding_key: String,
    pub(in crate::production_runtime_owner::resident_dataplane) x_padding_header: String,
    pub(in crate::production_runtime_owner::resident_dataplane) x_padding_placement:
        ResidentXhttpPaddingPlacement,
    pub(in crate::production_runtime_owner::resident_dataplane) x_padding_method:
        ResidentXhttpPaddingMethod,
    pub(in crate::production_runtime_owner::resident_dataplane) uplink_http_method: String,
    pub(in crate::production_runtime_owner::resident_dataplane) session_id_placement:
        ResidentXhttpMetaPlacement,
    pub(in crate::production_runtime_owner::resident_dataplane) session_id_key: String,
    pub(in crate::production_runtime_owner::resident_dataplane) session_id_table: String,
    pub(in crate::production_runtime_owner::resident_dataplane) session_id_length:
        Option<(i32, i32)>,
    pub(in crate::production_runtime_owner::resident_dataplane) seq_placement:
        ResidentXhttpMetaPlacement,
    pub(in crate::production_runtime_owner::resident_dataplane) seq_key: String,
    pub(in crate::production_runtime_owner::resident_dataplane) uplink_data_placement:
        ResidentXhttpUplinkDataPlacement,
    pub(in crate::production_runtime_owner::resident_dataplane) uplink_data_key: String,
    pub(in crate::production_runtime_owner::resident_dataplane) uplink_chunk_size:
        Option<(i32, i32)>,
    pub(in crate::production_runtime_owner::resident_dataplane) no_grpc_header: bool,
    pub(in crate::production_runtime_owner::resident_dataplane) no_sse_header: bool,
    pub(in crate::production_runtime_owner::resident_dataplane) sc_max_each_post_bytes:
        Option<(i32, i32)>,
    pub(in crate::production_runtime_owner::resident_dataplane) sc_min_posts_interval_ms:
        Option<(i32, i32)>,
    pub(in crate::production_runtime_owner::resident_dataplane) sc_max_buffered_posts: i64,
    pub(in crate::production_runtime_owner::resident_dataplane) sc_stream_up_server_secs:
        Option<(i32, i32)>,
    pub(in crate::production_runtime_owner::resident_dataplane) server_max_header_bytes: i32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentXhttpPaddingPlacement {
    Cookie,
    Header,
    Query,
    QueryInHeader,
}

impl ResidentXhttpPaddingPlacement {
    pub(in crate::production_runtime_owner::resident_dataplane) fn as_str(self) -> &'static str {
        match self {
            Self::Cookie => "cookie",
            Self::Header => "header",
            Self::Query => "query",
            Self::QueryInHeader => "queryInHeader",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentXhttpPaddingMethod {
    RepeatX,
    Tokenish,
}

impl ResidentXhttpPaddingMethod {
    pub(in crate::production_runtime_owner::resident_dataplane) fn as_str(self) -> &'static str {
        match self {
            Self::RepeatX => "repeat-x",
            Self::Tokenish => "tokenish",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentXhttpMetaPlacement {
    Path,
    Cookie,
    Header,
    Query,
}

impl ResidentXhttpMetaPlacement {
    pub(in crate::production_runtime_owner::resident_dataplane) fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Cookie => "cookie",
            Self::Header => "header",
            Self::Query => "query",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentXhttpUplinkDataPlacement {
    Auto,
    Body,
    Cookie,
    Header,
}

impl ResidentXhttpUplinkDataPlacement {
    pub(in crate::production_runtime_owner::resident_dataplane) fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Body => "body",
            Self::Cookie => "cookie",
            Self::Header => "header",
        }
    }
}

impl ResidentXhttpSettingsPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) fn official_default() -> Self {
        Self {
            headers: BTreeMap::new(),
            x_padding_bytes: None,
            x_padding_obfs_mode: false,
            x_padding_key: "x_padding".to_owned(),
            x_padding_header: "X-Padding".to_owned(),
            x_padding_placement: ResidentXhttpPaddingPlacement::QueryInHeader,
            x_padding_method: ResidentXhttpPaddingMethod::RepeatX,
            uplink_http_method: "POST".to_owned(),
            session_id_placement: ResidentXhttpMetaPlacement::Path,
            session_id_key: String::new(),
            session_id_table: String::new(),
            session_id_length: None,
            seq_placement: ResidentXhttpMetaPlacement::Path,
            seq_key: String::new(),
            uplink_data_placement: ResidentXhttpUplinkDataPlacement::Auto,
            uplink_data_key: "X-Data".to_owned(),
            uplink_chunk_size: None,
            no_grpc_header: false,
            no_sse_header: false,
            sc_max_each_post_bytes: None,
            sc_min_posts_interval_ms: None,
            sc_max_buffered_posts: 0,
            sc_stream_up_server_secs: None,
            server_max_header_bytes: 0,
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn normalized_x_padding_bytes(
        &self,
    ) -> (i32, i32) {
        match self.x_padding_bytes {
            Some((from, to)) if to > 0 => (from, to),
            _ => (100, 1000),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn normalized_sc_max_each_post_bytes(
        &self,
    ) -> (i32, i32) {
        match self.sc_max_each_post_bytes {
            Some((from, to)) if to > 0 => (from, to),
            _ => (1_000_000, 1_000_000),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn normalized_sc_min_posts_interval_ms(
        &self,
    ) -> (i32, i32) {
        match self.sc_min_posts_interval_ms {
            Some((from, to)) if to > 0 => (from, to),
            _ => (30, 30),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn normalized_sc_max_buffered_posts(
        &self,
    ) -> i64 {
        if self.sc_max_buffered_posts == 0 {
            30
        } else {
            self.sc_max_buffered_posts
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn normalized_sc_stream_up_server_secs(
        &self,
    ) -> (i32, i32) {
        match self.sc_stream_up_server_secs {
            Some((from, to)) if to > 0 => (from, to),
            _ => (20, 80),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn normalized_server_max_header_bytes(
        &self,
    ) -> i32 {
        if self.server_max_header_bytes <= 0 {
            8192
        } else {
            self.server_max_header_bytes
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn normalized_uplink_chunk_size(
        &self,
    ) -> (i32, i32) {
        match self.uplink_chunk_size {
            Some((from, to)) if to > 0 => {
                if from < 64 {
                    (64, to.max(64))
                } else {
                    (from, to)
                }
            }
            _ => match self.uplink_data_placement {
                ResidentXhttpUplinkDataPlacement::Cookie => (2 * 1024, 3 * 1024),
                ResidentXhttpUplinkDataPlacement::Header => (3 * 1000, 4 * 1000),
                ResidentXhttpUplinkDataPlacement::Auto | ResidentXhttpUplinkDataPlacement::Body => {
                    self.normalized_sc_max_each_post_bytes()
                }
            },
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn normalized_session_key(
        &self,
    ) -> &str {
        if !self.session_id_key.is_empty() {
            return &self.session_id_key;
        }
        match self.session_id_placement {
            ResidentXhttpMetaPlacement::Header => "X-Session",
            ResidentXhttpMetaPlacement::Cookie | ResidentXhttpMetaPlacement::Query => "x_session",
            ResidentXhttpMetaPlacement::Path => "",
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn normalized_seq_key(
        &self,
    ) -> &str {
        if !self.seq_key.is_empty() {
            return &self.seq_key;
        }
        match self.seq_placement {
            ResidentXhttpMetaPlacement::Header => "X-Seq",
            ResidentXhttpMetaPlacement::Cookie | ResidentXhttpMetaPlacement::Query => "x_seq",
            ResidentXhttpMetaPlacement::Path => "",
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn normalized_uplink_data_key(
        &self,
    ) -> &str {
        if !self.uplink_data_key.is_empty() {
            return &self.uplink_data_key;
        }
        match self.uplink_data_placement {
            ResidentXhttpUplinkDataPlacement::Cookie => "x_data",
            ResidentXhttpUplinkDataPlacement::Auto | ResidentXhttpUplinkDataPlacement::Header => {
                "X-Data"
            }
            ResidentXhttpUplinkDataPlacement::Body => "",
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn sample_range(
        range: (i32, i32),
    ) -> i32 {
        if range.0 == range.1 {
            return range.0;
        }
        fastrand::i32(range.0..=range.1)
    }

    fn compact_allocations(&mut self) {
        for value in self.headers.values_mut() {
            compact_string(value);
        }
        compact_string(&mut self.x_padding_key);
        compact_string(&mut self.x_padding_header);
        compact_string(&mut self.uplink_http_method);
        compact_string(&mut self.session_id_key);
        compact_string(&mut self.session_id_table);
        compact_string(&mut self.seq_key);
        compact_string(&mut self.uplink_data_key);
    }
}

impl Default for ResidentXhttpSettingsPlan {
    fn default() -> Self {
        Self::official_default()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentXhttpMode {
    PacketUp,
    StreamUp,
    StreamOne,
}

impl ResidentXhttpMode {
    pub(in crate::production_runtime_owner::resident_dataplane) fn as_str(self) -> &'static str {
        match self {
            Self::PacketUp => "packet-up",
            Self::StreamUp => "stream-up",
            Self::StreamOne => "stream-one",
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentXhttpXmuxPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) max_concurrency: Option<(i32, i32)>,
    pub(in crate::production_runtime_owner::resident_dataplane) max_connections: Option<(i32, i32)>,
    pub(in crate::production_runtime_owner::resident_dataplane) c_max_reuse_times:
        Option<(i32, i32)>,
    pub(in crate::production_runtime_owner::resident_dataplane) h_max_request_times:
        Option<(i32, i32)>,
    pub(in crate::production_runtime_owner::resident_dataplane) h_max_reusable_secs:
        Option<(i32, i32)>,
    pub(in crate::production_runtime_owner::resident_dataplane) h_keep_alive_period: i64,
}

impl ResidentXhttpXmuxPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) fn official_default() -> Self {
        Self {
            max_concurrency: Some((1, 1)),
            max_connections: None,
            c_max_reuse_times: None,
            h_max_request_times: Some((600, 900)),
            h_max_reusable_secs: Some((1800, 3000)),
            h_keep_alive_period: 0,
        }
    }

    fn is_official_zero_value(&self) -> bool {
        Self::range_is_zero_or_none(self.max_concurrency)
            && Self::range_is_zero_or_none(self.max_connections)
            && Self::range_is_zero_or_none(self.c_max_reuse_times)
            && Self::range_is_zero_or_none(self.h_max_request_times)
            && Self::range_is_zero_or_none(self.h_max_reusable_secs)
            && self.h_keep_alive_period == 0
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn official_normalized(
        self,
    ) -> Self {
        if self.is_official_zero_value() {
            Self::official_default()
        } else {
            self
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn validate_official(
        &self,
        field: &str,
        node_tag: &str,
    ) -> Result<(), String> {
        if self.range_to(self.max_connections) > 0 && self.range_to(self.max_concurrency) > 0 {
            return Err(format!(
                "resident dataplane vless xHTTP {field} rejects maxConnections together with maxConcurrency for node {node_tag}"
            ));
        }
        Ok(())
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn sample_range(
        range: Option<(i32, i32)>,
    ) -> i32 {
        let Some((from, to)) = range else {
            return 0;
        };
        if from == to {
            return from;
        }
        fastrand::i32(from..=to)
    }

    fn range_to(&self, range: Option<(i32, i32)>) -> i32 {
        range.map_or(0, |(_, to)| to)
    }

    fn range_is_zero_or_none(range: Option<(i32, i32)>) -> bool {
        matches!(range, None | Some((0, 0)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentXhttpHttpVersion {
    H1,
    H2,
    H3,
}

impl ResidentXhttpHttpVersion {
    pub(in crate::production_runtime_owner::resident_dataplane) fn from_tls_alpn(
        alpn: &[String],
    ) -> Self {
        if alpn.len() == 1 && alpn[0].trim().eq_ignore_ascii_case("http/1.1") {
            Self::H1
        } else if alpn.len() == 1 && alpn[0].trim().eq_ignore_ascii_case("h3") {
            Self::H3
        } else {
            Self::H2
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn alpn_label(
        self,
    ) -> &'static str {
        match self {
            Self::H1 => "http/1.1",
            Self::H2 => "h2",
            Self::H3 => "h3",
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn provider_for_mode(
        self,
        mode: ResidentXhttpMode,
    ) -> &'static str {
        match self {
            Self::H1 => match mode {
                ResidentXhttpMode::PacketUp => "resident-xhttp-h1-packet-up",
                ResidentXhttpMode::StreamUp => "resident-xhttp-h1-stream-up",
                ResidentXhttpMode::StreamOne => "resident-xhttp-h1-stream-one",
            },
            Self::H2 => match mode {
                ResidentXhttpMode::PacketUp => "resident-xhttp-h2-packet-up",
                ResidentXhttpMode::StreamUp => "resident-xhttp-h2-stream-up",
                ResidentXhttpMode::StreamOne => "resident-xhttp-h2-stream-one",
            },
            Self::H3 => match mode {
                ResidentXhttpMode::PacketUp => "resident-xhttp-h3-packet-up",
                ResidentXhttpMode::StreamUp => "resident-xhttp-h3-stream-up",
                ResidentXhttpMode::StreamOne => "resident-xhttp-h3-stream-one",
            },
        }
    }
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
        allow_insecure: bool,
        pin_sha256: String,
        max_rx: u64,
        obfs: ResidentHysteria2ObfsPlan,
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
                packet_semantics: "udp-over-stream-or-datagram",
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
    pub(in crate::production_runtime_owner::resident_dataplane) xhttp_mode: ResidentXhttpMode,
    pub(in crate::production_runtime_owner::resident_dataplane) xhttp_settings:
        ResidentXhttpSettingsPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) xhttp_xmux:
        Option<ResidentXhttpXmuxPlan>,
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
        self.xhttp_settings.compact_allocations();
        compact_string(&mut self.tls);
        if let Some(fingerprint) = &mut self.utls_fingerprint {
            fingerprint.compact_allocations();
        }
        if let Some(reality) = &mut self.reality {
            reality.compact_allocations();
        }
        self.handler.compact_allocations();
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn disable_latency_probe_persistent_caches(
        &mut self,
    ) {
        self.xhttp_xmux = None;
        if let Some(download) = &mut self.xhttp_download {
            download.xmux = None;
        }
        if let Some(parent) = self.chain_parent.as_mut() {
            Arc::make_mut(parent).disable_latency_probe_persistent_caches();
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn apply_latency_probe_control_mark(
        &mut self,
        mark: u32,
    ) {
        if mark == 0 {
            return;
        }
        if self.mark == 0 {
            self.mark = mark;
        }
        if let Some(parent) = self.chain_parent.as_mut() {
            Arc::make_mut(parent).apply_latency_probe_control_mark(mark);
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn latency_probe_proxy(
        &self,
    ) -> Self {
        let mut proxy = self.clone();
        proxy.disable_latency_probe_persistent_caches();
        proxy.compact_allocations();
        proxy
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
            mode: proxy.xhttp_mode,
            settings: proxy.xhttp_settings.clone(),
            xmux: proxy.xhttp_xmux.clone(),
            allow_insecure: proxy.allow_insecure,
            tls_fragment: proxy.tls_fragment.clone(),
            reality: proxy.reality.clone(),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn http_version(
        &self,
    ) -> ResidentXhttpHttpVersion {
        ResidentXhttpHttpVersion::from_tls_alpn(&self.alpn)
    }

    fn compact_allocations(&mut self) {
        compact_string(&mut self.server_host);
        compact_string(&mut self.server_name);
        compact_string_vec(&mut self.alpn);
        compact_string(&mut self.stream_host);
        compact_string(&mut self.stream_path);
        self.settings.compact_allocations();
        if let Some(reality) = &mut self.reality {
            reality.compact_allocations();
        }
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
                allow_insecure: _,
                pin_sha256,
                obfs,
                port_hop_ports,
                ..
            } => {
                compact_string(auth);
                compact_string(pin_sha256);
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

fn compact_string(value: &mut String) {
    value.shrink_to_fit();
}

fn compact_string_vec(values: &mut Vec<String>) {
    for value in values.iter_mut() {
        compact_string(value);
    }
    values.shrink_to_fit();
}
