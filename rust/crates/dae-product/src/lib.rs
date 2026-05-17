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
pub use systemd::{SystemdContract, systemd_contract};
pub use true_daemon_admission::{
    TrueDefaultDaemonAdmissionContract, TrueDefaultDaemonAdmissionRow,
    true_default_daemon_admission_contract,
};
