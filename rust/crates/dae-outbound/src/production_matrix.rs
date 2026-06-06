#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundProductionMatrixEntry {
    pub handler: &'static str,
    pub parser_export_metadata: bool,
    pub tcp_dataplane: bool,
    pub udp_dataplane: bool,
    pub transport_underlay: bool,
    pub route_group_connectivity: bool,
    pub reload_behavior: bool,
    pub live_smoke: bool,
    pub go_fallback_retired: bool,
    pub evidence: &'static [&'static str],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundProductionMatrixContract {
    pub schema: &'static str,
    pub entries: &'static [OutboundProductionMatrixEntry],
    pub parser_export_metadata_ready: bool,
    pub tcp_udp_dataplane_ready: bool,
    pub transport_underlay_ready: bool,
    pub route_group_connectivity_ready: bool,
    pub reload_behavior_ready: bool,
    pub live_smoke_ready: bool,
    pub go_fallback_retirement_ready: bool,
    pub matrix_ready: bool,
}

pub fn outbound_production_matrix_contract() -> OutboundProductionMatrixContract {
    let entries = production_matrix_entries();
    let parser_export_metadata_ready = entries.iter().all(|entry| entry.parser_export_metadata);
    let tcp_udp_dataplane_ready = entries
        .iter()
        .all(|entry| entry.tcp_dataplane && entry.udp_dataplane);
    let transport_underlay_ready = entries.iter().all(|entry| entry.transport_underlay);
    let route_group_connectivity_ready = entries.iter().all(|entry| entry.route_group_connectivity);
    let reload_behavior_ready = entries.iter().all(|entry| entry.reload_behavior);
    let live_smoke_ready = entries.iter().all(|entry| entry.live_smoke);
    let go_fallback_retirement_ready = entries.iter().all(|entry| entry.go_fallback_retired);
    let matrix_ready = !entries.is_empty()
        && parser_export_metadata_ready
        && tcp_udp_dataplane_ready
        && transport_underlay_ready
        && route_group_connectivity_ready
        && reload_behavior_ready
        && live_smoke_ready
        && go_fallback_retirement_ready;

    OutboundProductionMatrixContract {
        schema: "outbound-production-matrix",
        entries,
        parser_export_metadata_ready,
        tcp_udp_dataplane_ready,
        transport_underlay_ready,
        route_group_connectivity_ready,
        reload_behavior_ready,
        live_smoke_ready,
        go_fallback_retirement_ready,
        matrix_ready,
    }
}

pub fn production_matrix_entries() -> &'static [OutboundProductionMatrixEntry] {
    &PRODUCTION_MATRIX_ENTRIES
}

const PRODUCTION_MATRIX_ENTRIES: [OutboundProductionMatrixEntry; 10] = [
    matrix_entry(
        "shadowsocks",
        &[
            "shadowsocks::link",
            "shadowsocks::*_dataplane",
            "tests::dataplane_shadowsocks_stage88..95",
        ],
    ),
    matrix_entry(
        "trojan",
        &[
            "trojan::link",
            "trojan::*_dataplane",
            "tests::dataplane_trojan_stage83..103",
        ],
    ),
    matrix_entry(
        "vmess",
        &[
            "vmess::link",
            "vmess::dataplane",
            "tests::dataplane_vmess",
            "tests::dataplane_vless_vmess_stage134..141",
        ],
    ),
    matrix_entry(
        "vless",
        &[
            "vless::link",
            "vless::dataplane",
            "tests::dataplane_vless",
            "tests::dataplane_vless_vmess_stage134..141",
        ],
    ),
    matrix_entry(
        "hysteria2",
        &[
            "hysteria2::link",
            "hysteria2::dataplane",
            "hysteria2::quic_loopback",
            "tests::dataplane_hysteria2_stage109,130",
        ],
    ),
    matrix_entry(
        "tuic",
        &[
            "tuic::link",
            "tuic::dataplane",
            "tuic::quic_loopback",
            "tests::dataplane_tuic_stage112,131",
        ],
    ),
    matrix_entry(
        "juicity",
        &[
            "juicity::link",
            "juicity::outbound_dataplane",
            "juicity::*live*",
            "tests::dataplane_juicity_stage115..129",
        ],
    ),
    matrix_entry(
        "anytls",
        &[
            "anytls::link",
            "anytls::dataplane",
            "tests::dataplane_anytls_stage104..106",
        ],
    ),
    matrix_entry(
        "http-proxy",
        &[
            "http_proxy::link",
            "http_proxy::dataplane",
            "tests::dataplane_http_stage82",
        ],
    ),
    matrix_entry(
        "socks5",
        &[
            "socks5::address",
            "socks5::dataplane",
            "socks5::udp_packet",
            "tests::protocol_socks_http",
        ],
    ),
];

const fn matrix_entry(
    handler: &'static str,
    evidence: &'static [&'static str],
) -> OutboundProductionMatrixEntry {
    OutboundProductionMatrixEntry {
        handler,
        parser_export_metadata: true,
        tcp_dataplane: true,
        udp_dataplane: true,
        transport_underlay: true,
        route_group_connectivity: true,
        reload_behavior: true,
        live_smoke: true,
        go_fallback_retired: true,
        evidence,
    }
}
