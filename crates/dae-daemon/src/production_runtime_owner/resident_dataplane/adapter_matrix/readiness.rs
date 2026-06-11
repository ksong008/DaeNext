use super::*;
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
