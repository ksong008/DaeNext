use super::*;
use serde_json::json;

pub(crate) const RESIDENT_LIVE_MATRIX_EVIDENCE_ENV: &str = "RESIDENT_LIVE_MATRIX_EVIDENCE";
pub(crate) const RESIDENT_LIVE_MATRIX_EVIDENCE_LEGACY_ENV: &str =
    "DAE_RESIDENT_LIVE_MATRIX_EVIDENCE";

pub(crate) const REMOTE_LIVE_MATRIX_MISSING: &str =
    "remote live matrix evidence not recorded by live-evidence-ledger";
pub(crate) const REMOTE_LIVE_MATRIX_INVALID: &str =
    "remote live matrix evidence is invalid or incomplete";
pub(crate) const REDACTED_REMOTE_LIVE_MATRIX_ERROR: &str =
    "remote live matrix evidence is invalid; source detail redacted";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidentLiveAdapterMatrixEntry {
    pub handler: &'static str,
    pub formal_matrix_handler: &'static str,
    pub planner_admitted: bool,
    pub tcp_live_adapter: bool,
    pub tcp_semantics: &'static str,
    pub udp_live_adapter: bool,
    pub udp_semantics: &'static str,
    pub transport_underlay: bool,
    pub route_group_connectivity: bool,
    pub selected_node_fail_closed: bool,
    pub fingerprint_underlay: bool,
    pub remote_live_matrix: bool,
    pub native_executor_ready: bool,
    pub fingerprint_behavior: &'static str,
    pub evidence: &'static [&'static str],
    pub missing: &'static [&'static str],
}

impl ResidentLiveAdapterMatrixEntry {
    pub fn tcp_path_ready(self) -> bool {
        self.tcp_live_adapter || self.tcp_semantics == "protocol-closed"
    }

    pub fn udp_path_ready(self) -> bool {
        self.udp_live_adapter || self.udp_semantics == "protocol-closed"
    }

    pub fn wired_ready(self) -> bool {
        self.planner_admitted
            && self.tcp_path_ready()
            && self.udp_path_ready()
            && self.transport_underlay
            && self.route_group_connectivity
            && self.selected_node_fail_closed
            && self.fingerprint_underlay
            && self.native_executor_ready
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidentLiveMatrixEvidence {
    pub env: &'static str,
    pub source: Option<String>,
    pub schema: Option<String>,
    pub schema_version: Option<i64>,
    pub candidate_sha256: Option<String>,
    pub row_count: usize,
    pub pass_count: usize,
    pub all_pass: bool,
    pub valid: bool,
    pub ready_handlers: BTreeSet<String>,
    pub error: Option<String>,
}

impl ResidentLiveMatrixEvidence {
    pub(super) fn missing() -> Self {
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

    pub(super) fn invalid(env: &'static str, source: String, error: impl Into<String>) -> Self {
        Self {
            env,
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

    pub fn handler_ready(&self, handler: &str) -> bool {
        self.valid && self.ready_handlers.contains(handler)
    }

    pub fn redacted_error(&self) -> Option<&'static str> {
        self.error
            .as_ref()
            .map(|_| REDACTED_REMOTE_LIVE_MATRIX_ERROR)
    }

    pub fn redacted_report(&self) -> Value {
        json!({
            "env": self.env,
            "source": self
                .source
                .as_deref()
                .map(super::super::link_hash),
            "sourceRedacted": self.source.is_some(),
            "schema": self.schema.as_deref(),
            "schemaVersion": self.schema_version,
            "candidateSha256": self.candidate_sha256.as_deref(),
            "rowCount": self.row_count,
            "passCount": self.pass_count,
            "allPass": self.all_pass,
            "valid": self.valid,
            "readyHandlers": self.ready_handlers.iter().cloned().collect::<Vec<_>>(),
            "error": self.redacted_error(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidentLiveAdapterMatrixContract {
    pub schema: &'static str,
    pub entries: &'static [ResidentLiveAdapterMatrixEntry],
    pub planner_admission_ready: bool,
    pub tcp_live_adapter_ready: bool,
    pub udp_live_adapter_ready: bool,
    pub transport_underlay_ready: bool,
    pub route_group_connectivity_ready: bool,
    pub selected_node_fail_closed_ready: bool,
    pub fingerprint_underlay_ready: bool,
    pub native_executor_matrix_ready: bool,
    pub wired_matrix_ready: bool,
    pub remote_live_matrix_ready: bool,
    pub matrix_ready: bool,
}
