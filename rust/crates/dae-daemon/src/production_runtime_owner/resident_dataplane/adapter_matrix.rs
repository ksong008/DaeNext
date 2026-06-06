#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResidentLiveAdapterMatrixEntry {
    pub(crate) handler: &'static str,
    pub(crate) formal_matrix_handler: &'static str,
    pub(crate) planner_admitted: bool,
    pub(crate) tcp_live_adapter: bool,
    pub(crate) udp_live_adapter: bool,
    pub(crate) udp_semantics: &'static str,
    pub(crate) transport_underlay: bool,
    pub(crate) route_group_connectivity: bool,
    pub(crate) selected_node_fail_closed: bool,
    pub(crate) fingerprint_underlay: bool,
    pub(crate) remote_live_matrix: bool,
    pub(crate) go_outbound_fallback_retired: bool,
    pub(crate) fingerprint_behavior: &'static str,
    pub(crate) evidence: &'static [&'static str],
    pub(crate) missing: &'static [&'static str],
}

impl ResidentLiveAdapterMatrixEntry {
    pub(crate) fn udp_path_ready(self) -> bool {
        self.udp_live_adapter || self.udp_semantics == "protocol-closed"
    }

    pub(crate) fn wired_ready(self) -> bool {
        self.planner_admitted
            && self.tcp_live_adapter
            && self.udp_path_ready()
            && self.transport_underlay
            && self.route_group_connectivity
            && self.selected_node_fail_closed
            && self.fingerprint_underlay
            && self.go_outbound_fallback_retired
    }

    pub(crate) fn live_ready(self) -> bool {
        self.wired_ready() && self.remote_live_matrix && self.missing.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResidentLiveAdapterMatrixContract {
    pub(crate) schema: &'static str,
    pub(crate) entries: &'static [ResidentLiveAdapterMatrixEntry],
    pub(crate) planner_admission_ready: bool,
    pub(crate) tcp_live_adapter_ready: bool,
    pub(crate) udp_live_adapter_ready: bool,
    pub(crate) transport_underlay_ready: bool,
    pub(crate) route_group_connectivity_ready: bool,
    pub(crate) selected_node_fail_closed_ready: bool,
    pub(crate) fingerprint_underlay_ready: bool,
    pub(crate) go_outbound_fallback_retirement_ready: bool,
    pub(crate) wired_matrix_ready: bool,
    pub(crate) remote_live_matrix_ready: bool,
    pub(crate) matrix_ready: bool,
}

pub(crate) fn resident_live_adapter_matrix_contract() -> ResidentLiveAdapterMatrixContract {
    let entries = resident_live_adapter_matrix_entries();
    let planner_admission_ready = entries.iter().all(|entry| entry.planner_admitted);
    let tcp_live_adapter_ready = entries.iter().all(|entry| entry.tcp_live_adapter);
    let udp_live_adapter_ready = entries.iter().all(|entry| entry.udp_path_ready());
    let transport_underlay_ready = entries.iter().all(|entry| entry.transport_underlay);
    let route_group_connectivity_ready = entries.iter().all(|entry| entry.route_group_connectivity);
    let selected_node_fail_closed_ready =
        entries.iter().all(|entry| entry.selected_node_fail_closed);
    let fingerprint_underlay_ready = entries.iter().all(|entry| entry.fingerprint_underlay);
    let go_outbound_fallback_retirement_ready = entries
        .iter()
        .all(|entry| entry.go_outbound_fallback_retired);
    let wired_matrix_ready = !entries.is_empty() && entries.iter().all(|entry| entry.wired_ready());
    let remote_live_matrix_ready = !entries.is_empty()
        && entries
            .iter()
            .all(|entry| entry.remote_live_matrix && entry.missing.is_empty());
    let matrix_ready = wired_matrix_ready && remote_live_matrix_ready;

    ResidentLiveAdapterMatrixContract {
        schema: "resident-live-adapter-matrix",
        entries,
        planner_admission_ready,
        tcp_live_adapter_ready,
        udp_live_adapter_ready,
        transport_underlay_ready,
        route_group_connectivity_ready,
        selected_node_fail_closed_ready,
        fingerprint_underlay_ready,
        go_outbound_fallback_retirement_ready,
        wired_matrix_ready,
        remote_live_matrix_ready,
        matrix_ready,
    }
}

pub(crate) fn resident_live_adapter_matrix_entries() -> &'static [ResidentLiveAdapterMatrixEntry] {
    &RESIDENT_LIVE_ADAPTER_MATRIX_ENTRIES
}

const RESIDENT_LIVE_ADAPTER_MATRIX_ENTRIES: [ResidentLiveAdapterMatrixEntry; 10] = [
    ResidentLiveAdapterMatrixEntry {
        handler: "vless-vision-tcp-tls",
        formal_matrix_handler: "vless",
        planner_admitted: true,
        tcp_live_adapter: true,
        udp_live_adapter: true,
        udp_semantics: "relay",
        transport_underlay: true,
        route_group_connectivity: true,
        selected_node_fail_closed: true,
        fingerprint_underlay: true,
        remote_live_matrix: false,
        go_outbound_fallback_retired: true,
        fingerprint_behavior: "link fingerprint selects the fingerprint-aware underlay, global fingerprint is fallback, no fingerprint uses the standard TLS underlay",
        evidence: &[
            "resident_dataplane::plan admits only the live adapter shape",
            "resident_dataplane::tcp opens the fingerprint-aware VLESS/TLS client",
            "resident_dataplane::udp uses the same admitted proxy plan for XUDP",
            "resident dataplane event field tls_underlay records boring/rustls underlay choice",
            "live-evidence-ledger must record a remote UDP matrix echo before this row is live-ready",
            "live-evidence-ledger must record remote TCP/page-load evidence before this row is live-ready",
        ],
        missing: &["remote live matrix evidence not recorded by live-evidence-ledger"],
    },
    udp_remote_live_entry(
        "shadowsocks",
        "stage18 AEAD TCP candidate uses resident Shadowsocks AEAD stream/UDP relay; SIP003 and 2022 variants remain fail-closed",
        &[
            "resident_dataplane::plan admits stage18 AEAD TCP candidate shapes",
            "resident_dataplane::tcp dispatches through the Shadowsocks AEAD stream relay",
            "resident_dataplane::udp dispatches through the Shadowsocks AEAD UDP datagram relay",
            "live-evidence-ledger must record a remote UDP matrix echo before this row is live-ready",
            "live-evidence-ledger must record remote TCP/page-load evidence before this row is live-ready",
        ],
    ),
    udp_remote_live_entry(
        "trojan",
        "plain TLS/TCP endpoints use the resident TLS underlay and UDP-over-TCP packet stream; trojan-go transport combinations remain fail-closed",
        &[
            "resident_dataplane::plan admits plain TLS/TCP endpoint shapes",
            "resident_dataplane::tcp sends the request header then relays TLS plaintext",
            "resident_dataplane::udp dispatches through the Trojan UDP-over-TCP packet stream",
            "live-evidence-ledger must record a remote UDP matrix echo before this row is live-ready",
            "live-evidence-ledger must record remote TCP/page-load evidence before this row is live-ready",
        ],
    ),
    udp_remote_live_entry(
        "vmess",
        "AEAD plain TCP endpoints use the resident TCP relay and UDP-over-TCP exchange; TLS and transport combinations remain fail-closed",
        &[
            "resident_dataplane::plan admits VMess AEAD plain TCP endpoint shapes",
            "dae_outbound::vmess exposes reusable AEAD session/chunk codecs for resident relay",
            "resident_dataplane::tcp sends VMess header/chunks and relays response chunks",
            "resident_dataplane::udp dispatches through the VMess AEAD UDP-over-TCP exchange",
            "live-evidence-ledger must record a remote UDP matrix echo before this row is live-ready",
            "live-evidence-ledger must record remote TCP/page-load evidence before this row is live-ready",
        ],
    ),
    udp_remote_live_entry(
        "hysteria2",
        "pinned QUIC/H3 authenticated endpoints use the resident QUIC relay and UDP datagram path; port hopping remains fail-closed",
        &[
            "resident_dataplane::plan admits single-port pinned Hysteria2 endpoint shapes",
            "dae_outbound::hysteria2 exposes H3 auth and TCP stream request/response helpers",
            "resident_dataplane::tcp opens a marked quinn UDP endpoint and relays TCP over a Hysteria2 stream",
            "resident_dataplane::udp sends and parses Hysteria2 UDP datagrams over the marked QUIC endpoint",
            "live-evidence-ledger must record a remote UDP matrix echo before this row is live-ready",
            "live-evidence-ledger must record remote TCP/page-load evidence before this row is live-ready",
        ],
    ),
    udp_remote_live_entry(
        "tuic",
        "explicit-insecure QUIC authenticated endpoints use the resident QUIC relay and UDP packet frame path",
        &[
            "resident_dataplane::plan admits explicit-insecure TUIC endpoint shapes",
            "dae_outbound::tuic exposes auth stream and Connect frame runtime helpers",
            "resident_dataplane::tcp opens a marked quinn UDP endpoint and relays TCP over a TUIC stream",
            "resident_dataplane::udp sends and parses TUIC packet datagrams over the marked QUIC endpoint",
            "live-evidence-ledger must record a remote UDP matrix echo before this row is live-ready",
            "live-evidence-ledger must record remote TCP/page-load evidence before this row is live-ready",
        ],
    ),
    udp_remote_live_entry(
        "juicity",
        "pinned or explicit-insecure QUIC authenticated endpoints use the resident QUIC relay and stream packet UDP path",
        &[
            "resident_dataplane::plan admits Juicity endpoint shapes with pinned certchain or explicit insecure verification",
            "dae_outbound::juicity exposes EKM auth stream and TCP stream request helpers",
            "resident_dataplane::tcp opens a marked quinn UDP endpoint and relays TCP over a Juicity stream",
            "resident_dataplane::udp sends and parses Juicity stream packet frames over the marked QUIC endpoint",
            "live-evidence-ledger must record a remote UDP matrix echo before this row is live-ready",
            "live-evidence-ledger must record remote TCP/page-load evidence before this row is live-ready",
        ],
    ),
    udp_remote_live_entry(
        "anytls",
        "session-frame TLS/TCP endpoints use the resident TLS underlay and UDP packet stream",
        &[
            "resident_dataplane::plan admits AnyTLS session-frame endpoint shapes",
            "resident_dataplane::tcp sends auth/settings/SYN/PSH frames and relays PSH payload frames",
            "resident_dataplane::udp sends auth/settings/SYN/PSH frames and decodes UDP packet stream responses",
            "live-evidence-ledger must record a remote UDP matrix echo before this row is live-ready",
            "live-evidence-ledger must record remote TCP/page-load evidence before this row is live-ready",
        ],
    ),
    protocol_closed_remote_live_entry(
        "http-proxy",
        "plain HTTP CONNECT endpoints use the resident TCP relay; UDP has no HTTP CONNECT relay semantics and is fail-closed without Go fallback",
        &[
            "resident_dataplane::plan admits plain HTTP CONNECT endpoint shapes",
            "resident_dataplane::tcp dispatches through the HTTP CONNECT relay",
            "resident_dataplane::udp returns an explicit protocol-closed fail-closed result for HTTP CONNECT",
            "live-evidence-ledger must record remote TCP/page-load evidence before this row is live-ready",
        ],
    ),
    udp_remote_live_entry(
        "socks5",
        "SOCKS5 CONNECT endpoints use the resident TCP relay and UDP ASSOCIATE for datagrams",
        &[
            "resident_dataplane::plan admits SOCKS5 endpoint shapes",
            "resident_dataplane::tcp dispatches through the SOCKS5 CONNECT relay",
            "resident_dataplane::udp dispatches through SOCKS5 UDP ASSOCIATE",
            "live-evidence-ledger must record a remote UDP matrix echo before this row is live-ready",
            "live-evidence-ledger must record remote TCP/page-load evidence before this row is live-ready",
        ],
    ),
];

const fn udp_remote_live_entry(
    formal_matrix_handler: &'static str,
    fingerprint_behavior: &'static str,
    evidence: &'static [&'static str],
) -> ResidentLiveAdapterMatrixEntry {
    ResidentLiveAdapterMatrixEntry {
        handler: formal_matrix_handler,
        formal_matrix_handler,
        planner_admitted: true,
        tcp_live_adapter: true,
        udp_live_adapter: true,
        udp_semantics: "relay",
        transport_underlay: true,
        route_group_connectivity: true,
        selected_node_fail_closed: true,
        fingerprint_underlay: true,
        remote_live_matrix: false,
        go_outbound_fallback_retired: true,
        fingerprint_behavior,
        evidence,
        missing: &["remote live matrix evidence not recorded by live-evidence-ledger"],
    }
}

const fn protocol_closed_remote_live_entry(
    formal_matrix_handler: &'static str,
    fingerprint_behavior: &'static str,
    evidence: &'static [&'static str],
) -> ResidentLiveAdapterMatrixEntry {
    ResidentLiveAdapterMatrixEntry {
        handler: formal_matrix_handler,
        formal_matrix_handler,
        planner_admitted: true,
        tcp_live_adapter: true,
        udp_live_adapter: false,
        udp_semantics: "protocol-closed",
        transport_underlay: true,
        route_group_connectivity: true,
        selected_node_fail_closed: true,
        fingerprint_underlay: true,
        remote_live_matrix: false,
        go_outbound_fallback_retired: true,
        fingerprint_behavior,
        evidence,
        missing: &["remote live matrix evidence not recorded by live-evidence-ledger"],
    }
}
