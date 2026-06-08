use super::*;
pub(crate) const RESIDENT_LIVE_MATRIX_EVIDENCE_ENV: &str = "DAE_RESIDENT_LIVE_MATRIX_EVIDENCE";

pub(crate) const REMOTE_LIVE_MATRIX_MISSING: &str =
    "remote live matrix evidence not recorded by live-evidence-ledger";
pub(crate) const REMOTE_LIVE_MATRIX_INVALID: &str =
    "remote live matrix evidence is invalid or incomplete";

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

    pub(super) fn invalid(source: String, error: impl Into<String>) -> Self {
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
