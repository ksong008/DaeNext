use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamWrapperCapabilityContract {
    pub schema: &'static str,
    pub schema_version: u64,
    pub rows: &'static [StreamWrapperCapabilityRow],
    pub websocket_wss_loopback_ready: bool,
    pub resident_source_admission_ready: bool,
    pub expanded_stream_wrapper_complete: bool,
}

impl StreamWrapperCapabilityContract {
    pub fn to_value(self) -> Value {
        json!({
            "schema": self.schema,
            "schemaVersion": self.schema_version,
            "websocketWssLoopbackReady": self.websocket_wss_loopback_ready,
            "residentSourceAdmissionReady": self.resident_source_admission_ready,
            "expandedStreamWrapperComplete": self.expanded_stream_wrapper_complete,
            "rowCount": self.rows.len(),
            "rows": self.rows.iter().map(|row| row.to_value()).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamWrapperCapabilityRow {
    pub wrapper_id: &'static str,
    pub wrapper: &'static str,
    pub status: &'static str,
    pub source_admission: &'static str,
    pub provider: &'static str,
    pub security_underlay: &'static str,
    pub packet_semantics: &'static str,
    pub cache_lifecycle: &'static str,
    pub cancellation: &'static str,
    pub reload_cleanup: &'static str,
    pub blocker_id: Option<&'static str>,
    pub evidence_requirements: &'static [&'static str],
}

impl StreamWrapperCapabilityRow {
    pub fn to_value(self) -> Value {
        json!({
            "wrapperId": self.wrapper_id,
            "wrapper": self.wrapper,
            "status": self.status,
            "sourceAdmission": self.source_admission,
            "provider": self.provider,
            "securityUnderlay": self.security_underlay,
            "packetSemantics": self.packet_semantics,
            "cacheLifecycle": self.cache_lifecycle,
            "cancellation": self.cancellation,
            "reloadCleanup": self.reload_cleanup,
            "blockerId": self.blocker_id,
            "evidenceRequirements": self.evidence_requirements,
        })
    }
}

pub fn stream_wrapper_capability_contract() -> StreamWrapperCapabilityContract {
    StreamWrapperCapabilityContract {
        schema: "stream-wrapper-capability",
        schema_version: 1,
        rows: stream_wrapper_capability_rows(),
        websocket_wss_loopback_ready: true,
        resident_source_admission_ready: true,
        expanded_stream_wrapper_complete: true,
    }
}

pub fn stream_wrapper_capability_rows() -> &'static [StreamWrapperCapabilityRow] {
    &STREAM_WRAPPER_CAPABILITY_ROWS
}

const STREAM_WRAPPER_CAPABILITY_ROWS: [StreamWrapperCapabilityRow; 6] = [
    StreamWrapperCapabilityRow {
        wrapper_id: "websocket-wss-first-row",
        wrapper: "websocket-or-wss",
        status: "resident-live-final",
        source_admission: "admitted",
        provider: "resident-websocket-binary-frame",
        security_underlay: "standard-or-fingerprint-aware-tls",
        packet_semantics: "tcp-stream-binary-frames",
        cache_lifecycle: "none",
        cancellation: "stream-close",
        reload_cleanup: "drop-on-graph-diff-or-runtime-stop",
        blocker_id: None,
        evidence_requirements: &["large-page-live", "benchmark", "rollback"],
    },
    StreamWrapperCapabilityRow {
        wrapper_id: "grpc-wrapper",
        wrapper: "grpc",
        status: "resident-live-final",
        source_admission: "admitted",
        provider: "resident-grpc-h2-stream",
        security_underlay: "standard-or-fingerprint-aware-tls",
        packet_semantics: "tcp-stream-h2-grpc-hunk",
        cache_lifecycle: "per-stream",
        cancellation: "stream-close",
        reload_cleanup: "drop-on-graph-diff-or-runtime-stop",
        blocker_id: None,
        evidence_requirements: &["large-page-live", "benchmark", "rollback"],
    },
    StreamWrapperCapabilityRow {
        wrapper_id: "httpupgrade-wrapper",
        wrapper: "httpupgrade",
        status: "resident-live-final",
        source_admission: "admitted",
        provider: "resident-http-upgrade-stream",
        security_underlay: "standard-or-fingerprint-aware-tls",
        packet_semantics: "tcp-stream-after-http-upgrade",
        cache_lifecycle: "none",
        cancellation: "stream-close",
        reload_cleanup: "drop-on-graph-diff-or-runtime-stop",
        blocker_id: None,
        evidence_requirements: &["large-page-live", "benchmark", "rollback"],
    },
    StreamWrapperCapabilityRow {
        wrapper_id: "meek-wrapper",
        wrapper: "meek",
        status: "resident-live-final",
        source_admission: "admitted",
        provider: "resident-meek-polling",
        security_underlay: "standard-or-fingerprint-aware-tls",
        packet_semantics: "tcp-stream-meek-polling",
        cache_lifecycle: "per-session",
        cancellation: "session-close",
        reload_cleanup: "drop-on-graph-diff-or-runtime-stop",
        blocker_id: None,
        evidence_requirements: &["large-page-live", "benchmark", "rollback"],
    },
    StreamWrapperCapabilityRow {
        wrapper_id: "mux-wrapper",
        wrapper: "mux",
        status: "resident-live-final",
        source_admission: "admitted",
        provider: "resident-shared-mux-stream",
        security_underlay: "plain-or-standard-tls",
        packet_semantics: "multiplexed-stream",
        cache_lifecycle: "per-session",
        cancellation: "mux-end-frame",
        reload_cleanup: "drop-on-graph-diff-or-runtime-stop",
        blocker_id: None,
        evidence_requirements: &["large-page-live", "benchmark", "rollback"],
    },
    StreamWrapperCapabilityRow {
        wrapper_id: "xhttp-wrapper",
        wrapper: "xhttp",
        status: "resident-live-final",
        source_admission: "admitted",
        provider: "resident-xhttp-h2-packet-up",
        security_underlay: "standard-or-fingerprint-aware-tls",
        packet_semantics: "tcp-stream-h2-packet-up",
        cache_lifecycle: "per-session",
        cancellation: "session-close",
        reload_cleanup: "drop-on-graph-diff-or-runtime-stop",
        blocker_id: None,
        evidence_requirements: &["large-page-live", "benchmark", "rollback"],
    },
];
