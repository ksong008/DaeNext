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
pub mod stage35_36_admission_gates;
pub mod stage37_loaded_listen_socket_map_gate;
pub mod stage38_production_dae_attach_gate;
pub mod stage39_transparent_listener_gate;
pub mod stage40_param_aware_object_gate;
pub mod stage41_48_admission_gates;
pub mod stage49_production_param_listener_gate;
pub mod stage50_active_tcp_ingress_gate;
pub mod stage51_active_tcp_relay_gate;
pub mod stage52_active_tcp_route_table_group_gate;
pub mod stage53_active_udp_tproxy_endpoint_gate;
pub mod stage54_active_dns_tproxy_cache_gate;
pub mod stage55_socks5_outbound_gate;
pub mod stage56_socks5_udp_associate_gate;
pub mod stage57_http_connect_gate;
pub mod stage58_shadowsocks_aead_tcp_gate;
pub mod stage59_shadowsocks_aead_udp_gate;
pub mod stage60_trojan_tcp_gate;
pub mod stage61_trojan_udp_over_tcp_gate;
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
pub use stage35_36_admission_gates::{
    Stage35To36AdmissionContract, Stage35To36AdmissionRow, stage35_36_admission_contract,
};
pub use stage37_loaded_listen_socket_map_gate::{
    Stage37LoadedListenSocketMapGateContract, Stage37LoadedListenSocketMapGateRow,
    stage37_loaded_listen_socket_map_gate_contract,
};
pub use stage38_production_dae_attach_gate::{
    Stage38ProductionDaeAttachGateContract, Stage38ProductionDaeAttachGateRow,
    stage38_production_dae_attach_gate_contract,
};
pub use stage39_transparent_listener_gate::{
    Stage39TransparentListenerGateContract, Stage39TransparentListenerGateRow,
    stage39_transparent_listener_gate_contract,
};
pub use stage40_param_aware_object_gate::{
    Stage40ParamAwareObjectGateContract, Stage40ParamAwareObjectGateRow,
    stage40_param_aware_object_gate_contract,
};
pub use stage41_48_admission_gates::{
    Stage41To48AdmissionContract, Stage41To48AdmissionRow, stage41_48_admission_contract,
};
pub use stage49_production_param_listener_gate::{
    Stage49ProductionParamListenerGateContract, Stage49ProductionParamListenerGateRow,
    stage49_production_param_listener_gate_contract,
};
pub use stage50_active_tcp_ingress_gate::{
    Stage50ActiveTcpIngressGateContract, Stage50ActiveTcpIngressGateRow,
    stage50_active_tcp_ingress_gate_contract,
};
pub use stage51_active_tcp_relay_gate::{
    Stage51ActiveTcpRelayGateContract, Stage51ActiveTcpRelayGateRow,
    stage51_active_tcp_relay_gate_contract,
};
pub use stage52_active_tcp_route_table_group_gate::{
    Stage52ActiveTcpRouteTableGroupGateContract, Stage52ActiveTcpRouteTableGroupGateRow,
    stage52_active_tcp_route_table_group_gate_contract,
};
pub use stage53_active_udp_tproxy_endpoint_gate::{
    Stage53ActiveUdpTproxyEndpointGateContract, Stage53ActiveUdpTproxyEndpointGateRow,
    stage53_active_udp_tproxy_endpoint_gate_contract,
};
pub use stage54_active_dns_tproxy_cache_gate::{
    Stage54ActiveDnsTproxyCacheGateContract, Stage54ActiveDnsTproxyCacheGateRow,
    stage54_active_dns_tproxy_cache_gate_contract,
};
pub use stage55_socks5_outbound_gate::{
    Stage55Socks5OutboundTrueDataplaneGateContract, Stage55Socks5OutboundTrueDataplaneGateRow,
    stage55_socks5_outbound_true_dataplane_gate_contract,
};
pub use stage56_socks5_udp_associate_gate::{
    Stage56Socks5UdpAssociateGateContract, Stage56Socks5UdpAssociateGateRow,
    stage56_socks5_udp_associate_gate_contract,
};
pub use stage57_http_connect_gate::{
    Stage57HttpConnectGateContract, Stage57HttpConnectGateRow, stage57_http_connect_gate_contract,
};
pub use stage58_shadowsocks_aead_tcp_gate::{
    Stage58ShadowsocksAeadTcpGateContract, Stage58ShadowsocksAeadTcpGateRow,
    stage58_shadowsocks_aead_tcp_gate_contract,
};
pub use stage59_shadowsocks_aead_udp_gate::{
    Stage59ShadowsocksAeadUdpGateContract, Stage59ShadowsocksAeadUdpGateRow,
    stage59_shadowsocks_aead_udp_gate_contract,
};
pub use stage60_trojan_tcp_gate::{
    Stage60TrojanTcpGateContract, Stage60TrojanTcpGateRow, stage60_trojan_tcp_gate_contract,
};
pub use stage61_trojan_udp_over_tcp_gate::{
    Stage61TrojanUdpOverTcpGateContract, Stage61TrojanUdpOverTcpGateRow,
    stage61_trojan_udp_over_tcp_gate_contract,
};
pub use systemd::{SystemdContract, systemd_contract};
pub use true_daemon_admission::{
    TrueDefaultDaemonAdmissionContract, TrueDefaultDaemonAdmissionRow,
    true_default_daemon_admission_contract,
};
