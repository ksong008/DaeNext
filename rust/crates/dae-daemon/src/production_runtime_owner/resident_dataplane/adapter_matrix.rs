use std::collections::BTreeSet;
use std::fs;

use serde_json::Value;

pub(crate) const RESIDENT_LIVE_MATRIX_EVIDENCE_ENV: &str = "DAE_RESIDENT_LIVE_MATRIX_EVIDENCE";

const REMOTE_LIVE_MATRIX_MISSING: &str =
    "remote live matrix evidence not recorded by live-evidence-ledger";
const REMOTE_LIVE_MATRIX_INVALID: &str = "remote live matrix evidence is invalid or incomplete";

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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentLiveMatrixEvidence {
    pub(crate) env: &'static str,
    pub(crate) source: Option<String>,
    pub(crate) schema: Option<String>,
    pub(crate) schema_version: Option<i64>,
    pub(crate) candidate_sha256: Option<String>,
    pub(crate) row_count: usize,
    pub(crate) pass_count: usize,
    pub(crate) all_pass: bool,
    pub(crate) valid: bool,
    pub(crate) ready_handlers: BTreeSet<String>,
    pub(crate) error: Option<String>,
}

impl ResidentLiveMatrixEvidence {
    fn missing() -> Self {
        Self {
            env: RESIDENT_LIVE_MATRIX_EVIDENCE_ENV,
            source: None,
            schema: None,
            schema_version: None,
            candidate_sha256: None,
            row_count: 0,
            pass_count: 0,
            all_pass: false,
            valid: false,
            ready_handlers: BTreeSet::new(),
            error: Some(REMOTE_LIVE_MATRIX_MISSING.to_owned()),
        }
    }

    fn invalid(source: String, error: impl Into<String>) -> Self {
        Self {
            env: RESIDENT_LIVE_MATRIX_EVIDENCE_ENV,
            source: Some(source),
            schema: None,
            schema_version: None,
            candidate_sha256: None,
            row_count: 0,
            pass_count: 0,
            all_pass: false,
            valid: false,
            ready_handlers: BTreeSet::new(),
            error: Some(error.into()),
        }
    }

    pub(crate) fn handler_ready(&self, handler: &str) -> bool {
        self.valid && self.ready_handlers.contains(handler)
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
    let evidence = resident_live_matrix_evidence_from_env();
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
            .all(|entry| resident_live_adapter_entry_remote_live_matrix_ready(entry, &evidence));
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

pub(crate) fn resident_live_matrix_evidence_from_env() -> ResidentLiveMatrixEvidence {
    let Ok(source) = std::env::var(RESIDENT_LIVE_MATRIX_EVIDENCE_ENV) else {
        return ResidentLiveMatrixEvidence::missing();
    };
    let source = source.trim().to_owned();
    if source.is_empty() {
        return ResidentLiveMatrixEvidence::missing();
    }
    let text = match fs::read_to_string(&source) {
        Ok(text) => text,
        Err(err) => {
            return ResidentLiveMatrixEvidence::invalid(
                source,
                format!("read remote live matrix evidence: {err}"),
            );
        }
    };
    let root: Value = match serde_json::from_str(&text) {
        Ok(root) => root,
        Err(err) => {
            return ResidentLiveMatrixEvidence::invalid(
                source,
                format!("parse remote live matrix evidence: {err}"),
            );
        }
    };
    resident_live_matrix_evidence_from_value(Some(source), &root)
}

pub(crate) fn resident_live_matrix_evidence_from_value(
    source: Option<String>,
    root: &Value,
) -> ResidentLiveMatrixEvidence {
    let source_for_error = source.clone().unwrap_or_else(|| "<inline>".to_owned());
    let schema = root["schema"].as_str().map(str::to_owned);
    let schema_version = root["schemaVersion"].as_i64();
    let candidate_sha256 = root["candidateSha256"].as_str().map(str::to_owned);
    let row_count = root["rowCount"].as_u64().unwrap_or(0) as usize;
    let pass_count = root["passCount"].as_u64().unwrap_or(0) as usize;
    let all_pass = root["allPass"].as_bool().unwrap_or(false);
    let Some(rows) = root["rows"].as_array() else {
        return ResidentLiveMatrixEvidence {
            env: RESIDENT_LIVE_MATRIX_EVIDENCE_ENV,
            source,
            schema,
            schema_version,
            candidate_sha256,
            row_count,
            pass_count,
            all_pass,
            valid: false,
            ready_handlers: BTreeSet::new(),
            error: Some(format!(
                "{REMOTE_LIVE_MATRIX_INVALID}: rows array missing in {source_for_error}"
            )),
        };
    };
    let mut ready_handlers = BTreeSet::new();
    for row in rows {
        let Some(name) = row["row"].as_str() else {
            continue;
        };
        if resident_live_matrix_row_passes(name, row) {
            ready_handlers.insert(name.to_owned());
        }
    }
    let required_handlers = resident_live_adapter_matrix_entries()
        .iter()
        .map(|entry| entry.formal_matrix_handler)
        .collect::<BTreeSet<_>>();
    let all_handlers_ready = required_handlers
        .iter()
        .all(|handler| ready_handlers.contains(*handler));
    let valid = schema.as_deref() == Some("daex-current-live-resident-matrix")
        && schema_version == Some(1)
        && all_pass
        && row_count == required_handlers.len()
        && pass_count == required_handlers.len()
        && rows.len() == required_handlers.len()
        && all_handlers_ready;
    let error = if valid {
        None
    } else {
        Some(format!(
            "{REMOTE_LIVE_MATRIX_INVALID}: schema={schema:?} schemaVersion={schema_version:?} rowCount={row_count} passCount={pass_count} allPass={all_pass} readyHandlers={}",
            ready_handlers.len()
        ))
    };
    ResidentLiveMatrixEvidence {
        env: RESIDENT_LIVE_MATRIX_EVIDENCE_ENV,
        source,
        schema,
        schema_version,
        candidate_sha256,
        row_count,
        pass_count,
        all_pass,
        valid,
        ready_handlers,
        error,
    }
}

fn resident_live_matrix_row_passes(name: &str, row: &Value) -> bool {
    row["pass"].as_bool() == Some(true)
        && row["ready"].as_bool() == Some(true)
        && target_large_page_passes(row, "google", 10_000)
        && target_large_page_passes(row, "youtube", 100_000)
        && proxy_evidence_passes(row, "www.google.com")
        && proxy_evidence_passes(row, "www.youtube.com")
        && row["targetFailures"]
            .as_array()
            .is_none_or(|failures| failures.is_empty())
        && resident_live_adapter_matrix_entries()
            .iter()
            .any(|entry| entry.formal_matrix_handler == name)
}

fn target_large_page_passes(row: &Value, target: &str, min_size: u64) -> bool {
    let target = &row["targets"][target];
    target["http_code"].as_u64() == Some(200)
        && target["largePagePass"].as_bool() == Some(true)
        && target["size"].as_u64().is_some_and(|size| size >= min_size)
}

fn proxy_evidence_passes(row: &Value, domain: &str) -> bool {
    row["proxyEvidence"][domain].as_bool() == Some(true)
}

pub(crate) fn resident_live_adapter_entry_remote_live_matrix_ready(
    entry: &ResidentLiveAdapterMatrixEntry,
    evidence: &ResidentLiveMatrixEvidence,
) -> bool {
    entry.remote_live_matrix || evidence.handler_ready(entry.formal_matrix_handler)
}

pub(crate) fn resident_live_adapter_entry_missing(
    entry: &ResidentLiveAdapterMatrixEntry,
    evidence: &ResidentLiveMatrixEvidence,
) -> Vec<String> {
    if resident_live_adapter_entry_remote_live_matrix_ready(entry, evidence) {
        return Vec::new();
    }
    if evidence.source.is_some() {
        return vec![
            evidence
                .error
                .clone()
                .unwrap_or_else(|| REMOTE_LIVE_MATRIX_INVALID.to_owned()),
        ];
    }
    entry
        .missing
        .iter()
        .map(|missing| (*missing).to_owned())
        .collect()
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
        "plain TLS/TCP endpoints and trojan-go WebSocket endpoints use the resident TLS underlay; other trojan-go transport combinations remain fail-closed",
        &[
            "resident_dataplane::plan admits plain TLS/TCP and trojan-go WebSocket endpoint shapes",
            "resident_dataplane::tcp sends the request header then relays TLS plaintext or WebSocket binary frames",
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

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        resident_live_adapter_entry_missing, resident_live_adapter_entry_remote_live_matrix_ready,
        resident_live_adapter_matrix_entries, resident_live_matrix_evidence_from_value,
    };

    #[test]
    fn remote_live_matrix_evidence_admits_all_rows_only_when_large_pages_are_proxied() {
        let rows = resident_live_adapter_matrix_entries()
            .iter()
            .map(|entry| live_row(entry.formal_matrix_handler))
            .collect::<Vec<_>>();
        let evidence = resident_live_matrix_evidence_from_value(
            Some("/tmp/current-live-summary.json".to_owned()),
            &json!({
                "schema": "daex-current-live-resident-matrix",
                "schemaVersion": 1,
                "candidateSha256": "abc",
                "rowCount": rows.len(),
                "passCount": rows.len(),
                "allPass": true,
                "rows": rows,
                "directControlNotCounted": {
                    "google": {"http_code": 200, "size": 90000},
                    "youtube": {"http_code": 200, "size": 700000}
                }
            }),
        );

        assert!(evidence.valid);
        for entry in resident_live_adapter_matrix_entries() {
            assert!(resident_live_adapter_entry_remote_live_matrix_ready(
                entry, &evidence
            ));
            assert!(resident_live_adapter_entry_missing(entry, &evidence).is_empty());
        }
    }

    #[test]
    fn remote_live_matrix_evidence_rejects_missing_proxy_evidence() {
        let mut rows = resident_live_adapter_matrix_entries()
            .iter()
            .map(|entry| live_row(entry.formal_matrix_handler))
            .collect::<Vec<_>>();
        rows[0]["proxyEvidence"]["www.youtube.com"] = json!(false);
        let evidence = resident_live_matrix_evidence_from_value(
            Some("/tmp/current-live-summary.json".to_owned()),
            &json!({
                "schema": "daex-current-live-resident-matrix",
                "schemaVersion": 1,
                "rowCount": rows.len(),
                "passCount": rows.len(),
                "allPass": true,
                "rows": rows
            }),
        );

        assert!(!evidence.valid);
        let first = &resident_live_adapter_matrix_entries()[0];
        assert!(!resident_live_adapter_entry_remote_live_matrix_ready(
            first, &evidence
        ));
        assert!(!resident_live_adapter_entry_missing(first, &evidence).is_empty());
    }

    fn live_row(row: &str) -> Value {
        json!({
            "row": row,
            "pass": true,
            "ready": true,
            "targets": {
                "google": {
                    "http_code": 200,
                    "size": 82_000,
                    "largePagePass": true
                },
                "youtube": {
                    "http_code": 200,
                    "size": 712_000,
                    "largePagePass": true
                }
            },
            "proxyEvidence": {
                "www.google.com": true,
                "www.youtube.com": true
            },
            "targetFailures": []
        })
    }
}
