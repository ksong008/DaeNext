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
        resident_source_admission_ready: false,
        expanded_stream_wrapper_complete: false,
    }
}

pub fn stream_wrapper_capability_rows() -> &'static [StreamWrapperCapabilityRow] {
    &STREAM_WRAPPER_CAPABILITY_ROWS
}

const STREAM_WRAPPER_CAPABILITY_ROWS: [StreamWrapperCapabilityRow; 5] = [
    StreamWrapperCapabilityRow {
        wrapper_id: "websocket-wss-first-row",
        wrapper: "websocket-or-wss",
        status: "loopback-admitted",
        source_admission: "blocked-until-resident-materialization",
        provider: "shared-websocket-frame-executor",
        security_underlay: "standard-or-fingerprint-aware-tls",
        packet_semantics: "tcp-stream-binary-frames",
        cache_lifecycle: "none",
        cancellation: "stream-close",
        reload_cleanup: "drop-on-graph-diff-or-runtime-stop",
        blocker_id: Some("missing-live-evidence"),
        evidence_requirements: &[
            "resident-graph-materialization",
            "large-page-live",
            "benchmark",
            "rollback",
        ],
    },
    blocked_row("grpc-wrapper", "grpc", "missing-stream-wrapper"),
    blocked_row(
        "httpupgrade-wrapper",
        "httpupgrade",
        "missing-stream-wrapper",
    ),
    blocked_row("meek-wrapper", "meek", "missing-stream-wrapper"),
    blocked_row("xhttp-wrapper", "xhttp", "missing-stream-wrapper"),
];

const fn blocked_row(
    wrapper_id: &'static str,
    wrapper: &'static str,
    blocker_id: &'static str,
) -> StreamWrapperCapabilityRow {
    StreamWrapperCapabilityRow {
        wrapper_id,
        wrapper,
        status: "blocked",
        source_admission: "blocked",
        provider: "pending",
        security_underlay: "pending",
        packet_semantics: "pending",
        cache_lifecycle: "pending",
        cancellation: "pending",
        reload_cleanup: "pending",
        blocker_id: Some(blocker_id),
        evidence_requirements: &[
            "loopback",
            "cancellation",
            "reload-cleanup",
            "large-page-live",
            "benchmark",
            "rollback",
        ],
    }
}
