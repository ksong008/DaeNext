use super::*;

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
    pub(in crate::production_runtime_owner::resident_dataplane) default_alpn: Vec<String>,
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

    pub(super) fn compact_allocations(&mut self) {
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

    pub(super) fn compact_allocations(&mut self) {
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
    pub(super) fn compact_allocations(&mut self) {
        compact_string(&mut self.requested);
        compact_string(&mut self.name);
        compact_string(&mut self.canonical);
        compact_string(&mut self.family);
        compact_string(&mut self.client);
        compact_string(&mut self.alpn_policy);
        compact_string_vec(&mut self.default_alpn);
    }
}

impl ResidentRealityUnderlayPlan {
    pub(super) fn compact_allocations(&mut self) {
        self.short_id.shrink_to_fit();
        compact_string(&mut self.spider_x);
    }
}
