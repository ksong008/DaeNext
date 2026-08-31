use crate::source_shape_registry::{
    RuntimeRouteAdmission, SourceShapeReconciliationKind, SourceShapeRegistryRow,
    source_shape_reconciliation, source_shape_registry_rows,
};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundProductionMatrixEntry {
    pub handler: &'static str,
    pub source_shape_ids: &'static [&'static str],
    pub parser_export_metadata: bool,
    pub tcp_dataplane: bool,
    pub udp_dataplane: bool,
    pub transport_underlay: bool,
    pub route_group_connectivity: bool,
    pub reload_behavior: bool,
    pub live_smoke: bool,
    pub native_executor_ready: bool,
    pub evidence: &'static [&'static str],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundProductionMatrixContract {
    pub schema: &'static str,
    pub entries: &'static [OutboundProductionMatrixEntry],
    pub source_registry_backed_ready: bool,
    pub parser_export_metadata_ready: bool,
    pub tcp_udp_dataplane_ready: bool,
    pub transport_underlay_ready: bool,
    pub route_group_connectivity_ready: bool,
    pub reload_behavior_ready: bool,
    pub live_smoke_ready: bool,
    pub native_executor_matrix_ready: bool,
    pub matrix_ready: bool,
}

pub fn outbound_production_matrix_contract() -> OutboundProductionMatrixContract {
    let entries = production_matrix_entries();
    let source_registry_backed_ready =
        production_matrix_entries_are_source_registry_backed(entries, source_shape_registry_rows());
    let parser_export_metadata_ready = entries.iter().all(|entry| entry.parser_export_metadata);
    let tcp_udp_dataplane_ready = production_matrix_dataplane_declarations_match_registry(
        entries,
        source_shape_registry_rows(),
    );
    let transport_underlay_ready = entries.iter().all(|entry| entry.transport_underlay);
    let route_group_connectivity_ready = entries.iter().all(|entry| entry.route_group_connectivity);
    let reload_behavior_ready = entries.iter().all(|entry| entry.reload_behavior);
    let live_smoke_ready = entries.iter().all(|entry| entry.live_smoke);
    let native_executor_matrix_ready =
        source_registry_backed_ready && entries.iter().all(|entry| entry.native_executor_ready);
    let matrix_ready = !entries.is_empty()
        && source_registry_backed_ready
        && parser_export_metadata_ready
        && tcp_udp_dataplane_ready
        && transport_underlay_ready
        && route_group_connectivity_ready
        && reload_behavior_ready
        && live_smoke_ready
        && native_executor_matrix_ready;

    OutboundProductionMatrixContract {
        schema: "outbound-production-matrix",
        entries,
        source_registry_backed_ready,
        parser_export_metadata_ready,
        tcp_udp_dataplane_ready,
        transport_underlay_ready,
        route_group_connectivity_ready,
        reload_behavior_ready,
        live_smoke_ready,
        native_executor_matrix_ready,
        matrix_ready,
    }
}

pub fn production_matrix_entries() -> &'static [OutboundProductionMatrixEntry] {
    static ENTRIES: OnceLock<Box<[OutboundProductionMatrixEntry]>> = OnceLock::new();
    ENTRIES.get_or_init(|| {
        PRODUCTION_MATRIX_TEMPLATES
            .iter()
            .map(|template| matrix_entry_from_registry(*template, source_shape_registry_rows()))
            .collect::<Vec<_>>()
            .into_boxed_slice()
    })
}

pub fn production_matrix_dataplane_declarations_match_registry(
    entries: &[OutboundProductionMatrixEntry],
    rows: &[SourceShapeRegistryRow],
) -> bool {
    entries.iter().all(|entry| {
        let (tcp_dataplane, udp_dataplane) = registry_dataplane_capabilities(entry, rows);
        entry.tcp_dataplane == tcp_dataplane && entry.udp_dataplane == udp_dataplane
    })
}

pub fn production_matrix_entries_are_source_registry_backed(
    entries: &[OutboundProductionMatrixEntry],
    rows: &[SourceShapeRegistryRow],
) -> bool {
    entries.iter().all(|entry| {
        !entry.source_shape_ids.is_empty()
            && entry.source_shape_ids.iter().all(|shape_id| {
                rows.iter().any(|row| {
                    row.shape_id == *shape_id
                        && row.source_support == "source-supported"
                        && row.resident_status == "admitted-baseline"
                        && row.blocker_id.is_none()
                        && row.executor_proof.proof_state == "runtime-executable"
                        && row.typed_capability_contract().is_some()
                        && row.security_underlay_policy_contract().is_some()
                        && source_shape_reconciliation(row.shape_id).is_some_and(|reconciliation| {
                            reconciliation.kind == SourceShapeReconciliationKind::ProductionWitness
                        })
                })
            })
    })
}

#[derive(Clone, Copy)]
struct OutboundProductionMatrixTemplate {
    handler: &'static str,
    source_shape_ids: &'static [&'static str],
    evidence: &'static [&'static str],
}

const PRODUCTION_MATRIX_TEMPLATES: [OutboundProductionMatrixTemplate; 10] = [
    matrix_template(
        "shadowsocks",
        &[
            "baseline-aead-cipher-endpoint",
            "baseline-aead-2022-cipher-endpoint",
            "plugin-wrapper-layer",
            "tls-websocket-plugin-wrapper",
            "obfs-tls-plugin-wrapper",
            "aead-2022-plugin-wrapper",
        ],
        &[
            "shadowsocks::link",
            "shadowsocks::*_dataplane",
            "tests::dataplane_shadowsocks_ss2022_and_legacy",
        ],
    ),
    matrix_template(
        "trojan",
        &[
            "baseline-tls-auth-endpoint",
            "stream-wrapper-websocket",
            "stream-wrapper-grpc",
            "stream-wrapper-httpupgrade",
            "inner-encryption-stream-wrapper",
        ],
        &[
            "trojan::link",
            "trojan::*_dataplane",
            "tests::dataplane_trojan_tls_and_websocket",
        ],
    ),
    matrix_template(
        "vmess",
        &[
            "baseline-aead-framed-endpoint",
            "plain-websocket-framed-endpoint",
            "plain-httpupgrade-framed-endpoint",
            "secure-websocket-framed-endpoint",
            "secure-httpupgrade-framed-endpoint",
            "stream-wrapper-grpc",
            "plain-grpc-framed-endpoint",
            "vmess-h2-stream-wrapper",
        ],
        &[
            "vmess::link",
            "vmess::dataplane",
            "tests::dataplane_vmess",
            "tests::dataplane_vless_vmess_stream_wrappers",
        ],
    ),
    matrix_template(
        "vless",
        &[
            "vless-native-tcp-endpoint",
            "baseline-tls-vision-endpoint",
            "stream-wrapper-websocket",
            "stream-wrapper-grpc",
            "stream-wrapper-httpupgrade",
            "vless-meek-tls-stream-wrapper",
            "vless-meek-reality-stream-wrapper",
            "vless-h2-stream-wrapper",
            "xhttp-h1-wrapper",
            "stream-wrapper-xhttp",
            "xhttp-h3-wrapper",
            "reality-security-underlay",
            "mux-transport-wrapper",
        ],
        &[
            "vless::link",
            "vless::dataplane",
            "tests::dataplane_vless",
            "tests::dataplane_vless_vmess_stream_wrappers",
        ],
    ),
    matrix_template(
        "hysteria2",
        &["baseline-quic-auth-endpoint", "quic-port-hopping-surface"],
        &[
            "hysteria2::link",
            "hysteria2::dataplane",
            "hysteria2::quic_loopback",
            "tests::dataplane_hysteria2_quic",
        ],
    ),
    matrix_template(
        "tuic",
        &[
            "baseline-quic-uuid-endpoint",
            "verified-quic-security-underlay",
        ],
        &[
            "tuic::link",
            "tuic::dataplane",
            "tuic::quic_loopback",
            "tests::dataplane_tuic_quic",
        ],
    ),
    matrix_template(
        "juicity",
        &["baseline-quic-password-endpoint"],
        &[
            "juicity::link",
            "juicity::outbound_dataplane",
            "juicity::*live*",
            "tests::dataplane_juicity_quic",
        ],
    ),
    matrix_template(
        "anytls",
        &[
            "baseline-frame-stream-endpoint",
            "insecure-frame-stream-underlay",
        ],
        &[
            "anytls::link",
            "anytls::dataplane",
            "tests::dataplane_anytls_frame_stream",
        ],
    ),
    matrix_template(
        "http-proxy",
        &[
            "baseline-connect-endpoint",
            "secure-endpoint-capability",
            "proxy-transport-mode",
            "insecure-secure-endpoint-underlay",
            "fingerprint-secure-endpoint-underlay",
        ],
        &[
            "http_proxy::link",
            "http_proxy::dataplane",
            "tests::dataplane_http_connect",
        ],
    ),
    matrix_template(
        "socks5",
        &["baseline-socks-endpoint", "nested-chain-shape"],
        &[
            "socks5::address",
            "socks5::dataplane",
            "socks5::udp_packet",
            "tests::protocol_socks_http",
        ],
    ),
];

const fn matrix_template(
    handler: &'static str,
    source_shape_ids: &'static [&'static str],
    evidence: &'static [&'static str],
) -> OutboundProductionMatrixTemplate {
    OutboundProductionMatrixTemplate {
        handler,
        source_shape_ids,
        evidence,
    }
}

fn matrix_entry_from_registry(
    template: OutboundProductionMatrixTemplate,
    rows: &[SourceShapeRegistryRow],
) -> OutboundProductionMatrixEntry {
    let selected = template
        .source_shape_ids
        .iter()
        .filter_map(|shape_id| rows.iter().find(|row| row.shape_id == *shape_id))
        .collect::<Vec<_>>();
    let complete = selected.len() == template.source_shape_ids.len() && !selected.is_empty();
    let all = |predicate: fn(&SourceShapeRegistryRow) -> bool| {
        complete && selected.iter().copied().all(predicate)
    };
    let (tcp_dataplane, udp_dataplane) = registry_dataplane_capabilities_for_rows(&selected);
    OutboundProductionMatrixEntry {
        handler: template.handler,
        source_shape_ids: template.source_shape_ids,
        parser_export_metadata: all(|row| row.parser_coverage == "covered"),
        tcp_dataplane,
        udp_dataplane,
        transport_underlay: all(|row| row.executor_proof.underlay_factory == "proved"),
        route_group_connectivity: all(|row| {
            row.runtime_selection.selected_runtime_scope == "current-selected-resident-graph"
                && row.runtime_ownership.data_tcp.admission == RuntimeRouteAdmission::Admitted
        }),
        reload_behavior: all(|row| row.executor_proof.reload_lifecycle == "proved"),
        live_smoke: all(|row| {
            source_shape_reconciliation(row.shape_id).is_some_and(|reconciliation| {
                reconciliation.kind == SourceShapeReconciliationKind::ProductionWitness
            })
        }),
        native_executor_ready: all(|row| row.executor_proof.proof_state == "runtime-executable"),
        evidence: template.evidence,
    }
}

fn registry_dataplane_capabilities(
    entry: &OutboundProductionMatrixEntry,
    rows: &[SourceShapeRegistryRow],
) -> (bool, bool) {
    let selected = entry
        .source_shape_ids
        .iter()
        .filter_map(|shape_id| rows.iter().find(|row| row.shape_id == *shape_id))
        .collect::<Vec<_>>();
    registry_dataplane_capabilities_for_rows(&selected)
}

fn registry_dataplane_capabilities_for_rows(rows: &[&SourceShapeRegistryRow]) -> (bool, bool) {
    let admitted = |route: crate::source_shape_registry::RuntimeOwnerRoute| {
        route.admission == RuntimeRouteAdmission::Admitted
    };
    (
        rows.iter()
            .any(|row| admitted(row.runtime_ownership.data_tcp)),
        rows.iter()
            .any(|row| admitted(row.runtime_ownership.data_udp)),
    )
}
