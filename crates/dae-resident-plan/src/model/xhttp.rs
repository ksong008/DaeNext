use super::*;

#[path = "xhttp/capacity.rs"]
mod capacity;
use self::capacity::selected_xhttp_physical_connection_limit;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidentUtlsFingerprintPlan {
    pub source: &'static str,
    pub requested: String,
    pub name: String,
    pub canonical: String,
    pub family: String,
    pub client: String,
    pub randomized: bool,
    pub alpn_policy: String,
    pub default_alpn: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResidentXhttpQuicTlsProvider {
    Boring,
    ChromeBoring,
}

impl ResidentXhttpQuicTlsProvider {
    pub fn for_endpoint(fingerprint: Option<&ResidentUtlsFingerprintPlan>) -> Result<Self, String> {
        let Some(fingerprint) = fingerprint else {
            return Ok(Self::Boring);
        };
        if fingerprint.family == dae_outbound::shared_transport::UTLS_FAMILY_CHROME
            && fingerprint.canonical == "chrome_auto"
            && matches!(fingerprint.name.as_str(), "chrome" | "chrome_auto")
            && !fingerprint.randomized
        {
            return Ok(Self::ChromeBoring);
        }
        Err(format!(
            "xHTTP HTTP/3 QUIC TLS supports only chrome/chrome_auto fingerprint; requested {}",
            fingerprint.name
        ))
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Boring => "quinn-boringssl",
            Self::ChromeBoring => "quinn-boringssl-chrome",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidentRealityUnderlayPlan {
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub spider_x: String,
    pub mldsa65_verify: Option<Mldsa65VerifyKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidentEchPlan {
    config_list: EchConfigList,
}

impl ResidentEchPlan {
    pub const fn new(config_list: EchConfigList) -> Self {
        Self { config_list }
    }

    pub fn config_list_bytes(&self) -> &[u8] {
        self.config_list.bytes()
    }

    pub const fn config_list_sha256(&self) -> &[u8; 32] {
        self.config_list.sha256()
    }

    pub fn config_list_sha256_hex(&self) -> String {
        self.config_list.sha256_hex()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidentXhttpEndpointPlan {
    pub server_host: String,
    pub server_port: u16,
    pub server_name: String,
    pub alpn: Vec<String>,
    pub stream_host: String,
    pub stream_path: String,
    pub mode: ResidentXhttpMode,
    pub settings: ResidentXhttpSettingsPlan,
    pub xmux: Option<ResidentXhttpXmuxPlan>,
    pub allow_insecure: bool,
    pub tls_fragment: Option<TlsFragmentOptions>,
    pub utls_fingerprint: Option<ResidentUtlsFingerprintPlan>,
    pub ech: Option<ResidentEchPlan>,
    pub reality: Option<ResidentRealityUnderlayPlan>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidentXhttpSettingsPlan {
    pub headers: BTreeMap<String, String>,
    pub x_padding_bytes: Option<(i32, i32)>,
    pub x_padding_obfs_mode: bool,
    pub x_padding_key: String,
    pub x_padding_header: String,
    pub x_padding_placement: ResidentXhttpPaddingPlacement,
    pub x_padding_method: ResidentXhttpPaddingMethod,
    pub uplink_http_method: String,
    pub session_id_placement: ResidentXhttpMetaPlacement,
    pub session_id_key: String,
    pub session_id_table: String,
    pub session_id_length: Option<(i32, i32)>,
    pub seq_placement: ResidentXhttpMetaPlacement,
    pub seq_key: String,
    pub uplink_data_placement: ResidentXhttpUplinkDataPlacement,
    pub uplink_data_key: String,
    pub uplink_chunk_size: Option<(i32, i32)>,
    pub no_grpc_header: bool,
    pub no_sse_header: bool,
    pub sc_max_each_post_bytes: Option<(i32, i32)>,
    pub sc_min_posts_interval_ms: Option<(i32, i32)>,
    pub sc_max_buffered_posts: i64,
    pub sc_stream_up_server_secs: Option<(i32, i32)>,
    pub server_max_header_bytes: i32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResidentXhttpPaddingPlacement {
    Cookie,
    Header,
    Query,
    QueryInHeader,
}

impl ResidentXhttpPaddingPlacement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cookie => "cookie",
            Self::Header => "header",
            Self::Query => "query",
            Self::QueryInHeader => "queryInHeader",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResidentXhttpPaddingMethod {
    RepeatX,
    Tokenish,
}

impl ResidentXhttpPaddingMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RepeatX => "repeat-x",
            Self::Tokenish => "tokenish",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResidentXhttpMetaPlacement {
    Path,
    Cookie,
    Header,
    Query,
}

impl ResidentXhttpMetaPlacement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Cookie => "cookie",
            Self::Header => "header",
            Self::Query => "query",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResidentXhttpUplinkDataPlacement {
    Auto,
    Body,
    Cookie,
    Header,
}

impl ResidentXhttpUplinkDataPlacement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Body => "body",
            Self::Cookie => "cookie",
            Self::Header => "header",
        }
    }
}

impl ResidentXhttpSettingsPlan {
    pub fn official_default() -> Self {
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

    pub fn normalized_x_padding_bytes(&self) -> (i32, i32) {
        match self.x_padding_bytes {
            Some((from, to)) if to > 0 => (from, to),
            _ => (100, 1000),
        }
    }

    pub fn normalized_sc_max_each_post_bytes(&self) -> (i32, i32) {
        match self.sc_max_each_post_bytes {
            Some((from, to)) if to > 0 => (from, to),
            _ => (1_000_000, 1_000_000),
        }
    }

    pub fn normalized_sc_min_posts_interval_ms(&self) -> (i32, i32) {
        match self.sc_min_posts_interval_ms {
            Some((from, to)) if to > 0 => (from, to),
            _ => (30, 30),
        }
    }

    pub fn normalized_sc_max_buffered_posts(&self) -> i64 {
        if self.sc_max_buffered_posts == 0 {
            30
        } else {
            self.sc_max_buffered_posts
        }
    }

    pub fn normalized_sc_stream_up_server_secs(&self) -> (i32, i32) {
        match self.sc_stream_up_server_secs {
            Some((from, to)) if to > 0 => (from, to),
            _ => (20, 80),
        }
    }

    pub fn normalized_server_max_header_bytes(&self) -> i32 {
        if self.server_max_header_bytes <= 0 {
            8192
        } else {
            self.server_max_header_bytes
        }
    }

    pub fn normalized_uplink_chunk_size(&self) -> (i32, i32) {
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

    pub fn normalized_session_key(&self) -> &str {
        if !self.session_id_key.is_empty() {
            return &self.session_id_key;
        }
        match self.session_id_placement {
            ResidentXhttpMetaPlacement::Header => "X-Session",
            ResidentXhttpMetaPlacement::Cookie | ResidentXhttpMetaPlacement::Query => "x_session",
            ResidentXhttpMetaPlacement::Path => "",
        }
    }

    pub fn normalized_seq_key(&self) -> &str {
        if !self.seq_key.is_empty() {
            return &self.seq_key;
        }
        match self.seq_placement {
            ResidentXhttpMetaPlacement::Header => "X-Seq",
            ResidentXhttpMetaPlacement::Cookie | ResidentXhttpMetaPlacement::Query => "x_seq",
            ResidentXhttpMetaPlacement::Path => "",
        }
    }

    pub fn normalized_uplink_data_key(&self) -> &str {
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

    pub fn sample_range(range: (i32, i32)) -> i32 {
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
pub enum ResidentXhttpMode {
    PacketUp,
    StreamUp,
    StreamOne,
}

impl ResidentXhttpMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PacketUp => "packet-up",
            Self::StreamUp => "stream-up",
            Self::StreamOne => "stream-one",
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ResidentXhttpXmuxPlan {
    pub runtime_generation: u64,
    pub physical_connection_limit: usize,
    pub max_concurrency: Option<(i32, i32)>,
    pub max_connections: Option<(i32, i32)>,
    pub c_max_reuse_times: Option<(i32, i32)>,
    pub h_max_request_times: Option<(i32, i32)>,
    pub h_max_reusable_secs: Option<(i32, i32)>,
    pub h_keep_alive_period: i64,
}

impl ResidentXhttpXmuxPlan {
    pub fn official_default() -> Self {
        Self {
            runtime_generation: 0,
            physical_connection_limit: selected_xhttp_physical_connection_limit(),
            max_concurrency: Some((0, 0)),
            max_connections: Some((3, 3)),
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

    pub fn official_normalized(self) -> Self {
        let runtime_generation = self.runtime_generation;
        let mut normalized = if self.is_official_zero_value() {
            Self::official_default()
        } else {
            self
        };
        normalized.runtime_generation = runtime_generation;
        if normalized.physical_connection_limit == 0 {
            normalized.physical_connection_limit = selected_xhttp_physical_connection_limit();
        }
        normalized
    }

    pub fn validate_official(&self, field: &str, node_tag: &str) -> Result<(), String> {
        if self.range_to(self.max_connections) > 0 && self.range_to(self.max_concurrency) > 0 {
            return Err(format!(
                "resident dataplane vless xHTTP {field} rejects maxConnections together with maxConcurrency for node {node_tag}"
            ));
        }
        Ok(())
    }

    pub fn sample_range(range: Option<(i32, i32)>) -> i32 {
        let Some((from, to)) = range else {
            return 0;
        };
        if from == to {
            return from;
        }
        fastrand::i32(from..=to)
    }

    pub fn sampled_connection_target(&self) -> usize {
        let sampled = Self::sample_range(self.max_connections);
        usize::try_from(sampled)
            .ok()
            .filter(|value| *value > 0)
            .map_or(0, |value| value.min(self.physical_connection_limit.max(1)))
    }

    pub fn physical_connection_limit(&self) -> usize {
        self.physical_connection_limit.max(1)
    }

    fn range_to(&self, range: Option<(i32, i32)>) -> i32 {
        range.map_or(0, |(_, to)| to)
    }

    fn range_is_zero_or_none(range: Option<(i32, i32)>) -> bool {
        matches!(range, None | Some((0, 0)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentXhttpHttpVersion {
    H1,
    H2,
    H3,
}

impl ResidentXhttpHttpVersion {
    pub fn from_tls_alpn(alpn: &[String]) -> Self {
        if alpn.len() == 1 && alpn[0].trim().eq_ignore_ascii_case("http/1.1") {
            Self::H1
        } else if alpn.len() == 1 && alpn[0].trim().eq_ignore_ascii_case("h3") {
            Self::H3
        } else {
            Self::H2
        }
    }

    pub fn alpn_label(self) -> &'static str {
        match self {
            Self::H1 => "http/1.1",
            Self::H2 => "h2",
            Self::H3 => "h3",
        }
    }

    pub fn provider_for_mode(self, mode: ResidentXhttpMode) -> &'static str {
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
    pub fn from_proxy(proxy: &ResidentProxyPlan) -> Self {
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
            utls_fingerprint: proxy.utls_fingerprint.clone(),
            ech: proxy.ech.clone(),
            reality: proxy.reality.clone(),
        }
    }

    pub fn http_version(&self) -> ResidentXhttpHttpVersion {
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
        if let Some(fingerprint) = &mut self.utls_fingerprint {
            fingerprint.compact_allocations();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_xmux_normalization_preserves_runtime_generation() {
        let xmux = ResidentXhttpXmuxPlan {
            runtime_generation: 42,
            physical_connection_limit: 0,
            max_concurrency: None,
            max_connections: None,
            c_max_reuse_times: None,
            h_max_request_times: None,
            h_max_reusable_secs: None,
            h_keep_alive_period: 0,
        };
        let normalized = xmux.official_normalized();
        assert_eq!(normalized.runtime_generation, 42);
        assert!(normalized.physical_connection_limit > 0);
        assert_eq!(normalized.max_concurrency, Some((0, 0)));
        assert_eq!(normalized.max_connections, Some((3, 3)));
    }

    #[test]
    fn official_packet_up_defaults_preserve_xray_scheduler_bounds() {
        let settings = ResidentXhttpSettingsPlan::official_default();
        assert_eq!(
            settings.normalized_sc_max_each_post_bytes(),
            (1_000_000, 1_000_000)
        );
        assert_eq!(settings.normalized_sc_min_posts_interval_ms(), (30, 30));
        assert_eq!(settings.normalized_sc_max_buffered_posts(), 30);
    }
}
