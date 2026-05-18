pub mod complex_dataplane;
pub mod daemon_default;
pub mod daemon_gray_switch;
pub mod daemon_live_evidence;
pub mod integration;
pub mod outbound_contract;
pub mod product_chain_admission;
pub mod protocol_dataplane;
pub mod release;
pub mod stage23_completion;
pub mod stage24_product_gate;
pub mod stage25_execution_queue;
pub mod stage26_candidate_contract;
pub mod stage27_candidate_smoke;
pub mod stage28_live_admission_gate;
pub mod stage29_host_preflight_gate;
pub mod stage30_attach_cleanup_gate;
pub mod stage31_34_admission_gates;
pub mod systemd;
pub mod true_daemon_admission;

#[cfg(test)]
mod tests;

pub use complex_dataplane::{
    ComplexDataplaneGateContract, ComplexDataplaneGateRow, complex_dataplane_gate_contract,
};
pub use daemon_default::{DaemonDefaultReadinessContract, daemon_default_readiness_contract};
pub use daemon_gray_switch::{
    DaemonGraySwitchGateContract, DaemonGraySwitchReadinessRow, daemon_gray_switch_gate_contract,
};
pub use daemon_live_evidence::{
    DaemonLiveEvidenceQueueContract, DaemonLiveEvidenceQueueRow,
    daemon_live_evidence_queue_contract,
};
pub use integration::{DaedDaewingContract, daed_daewing_contract};
pub use outbound_contract::{OutboundNativeMigrationContract, outbound_native_migration_contract};
pub use product_chain_admission::{
    ProductChainAdmissionContract, ProductChainAdmissionRow, product_chain_admission_contract,
};
pub use protocol_dataplane::{
    ProtocolDataplaneAdmissionContract, ProtocolDataplaneAdmissionRow,
    protocol_dataplane_admission_contract,
};
pub use release::{ReleaseWorkflowContract, release_workflow_contract};
pub use stage23_completion::{
    Stage23CompletionContract, Stage23CompletionRow, stage23_completion_contract,
};
pub use stage24_product_gate::{
    Stage24ProductGateContract, Stage24ProductGateRow, stage24_product_gate_contract,
};
pub use stage25_execution_queue::{
    Stage25TrueDaemonExecutionQueueContract, Stage25TrueDaemonExecutionQueueRow,
    stage25_true_daemon_execution_queue_contract,
};
pub use stage26_candidate_contract::{
    Stage26DaemonCandidateContract, Stage26DaemonCandidateInventoryRow,
    stage26_daemon_candidate_contract,
};
pub use stage27_candidate_smoke::{
    Stage27CandidateSmokeContract, Stage27CandidateSmokeRow, stage27_candidate_smoke_contract,
};
pub use stage28_live_admission_gate::{
    Stage28LiveAdmissionGateContract, Stage28LiveAdmissionGateRow,
    stage28_live_admission_gate_contract,
};
pub use stage29_host_preflight_gate::{
    Stage29HostPreflightGateContract, Stage29HostPreflightGateRow,
    stage29_host_preflight_gate_contract,
};
pub use stage30_attach_cleanup_gate::{
    Stage30AttachCleanupGateContract, Stage30AttachCleanupGateRow,
    stage30_attach_cleanup_gate_contract,
};
pub use stage31_34_admission_gates::{
    Stage31To34AdmissionContract, Stage31To34AdmissionRow, stage31_34_admission_contract,
};
pub use systemd::{SystemdContract, systemd_contract};
pub use true_daemon_admission::{
    TrueDefaultDaemonAdmissionContract, TrueDefaultDaemonAdmissionRow,
    true_default_daemon_admission_contract,
};
