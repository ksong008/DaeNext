#![recursion_limit = "256"]

mod active_generation_slot;
mod display;
mod dns_ports;
pub mod events;
mod execution;
mod execution_types;
mod generation_coordinator;
mod generation_fence;
mod generation_identity;
mod generation_lifecycle;
mod metrics;
mod network_defaults;
mod payload_admission;
mod relay_deadline;
mod resource_profile;
mod session_admission;
mod socket;
mod stop_signal;
mod task_set;

use std::time::Duration;

use serde_json::{Value, json};

pub use active_generation_slot::ActiveGenerationSlot;
pub use display::{
    resident_normalized_socket_addr, resident_socket_addr_display, resident_tcp_network_name,
    resident_udp_network_name,
};
pub use dns_ports::{ResidentDnsUdpFuture, ResidentDnsUdpResolver};
pub use execution::{
    RuntimeExecutionDescriptor, append_runtime_execution_descriptor, tcp_execution_descriptor,
    udp_execution_descriptor,
};
pub use generation_coordinator::GenerationCoordinator;
pub use generation_fence::{GenerationFence, GenerationGate, GenerationWritePermit};
pub use generation_identity::{
    GenerationToken, LogicalGenerationId, PhysicalRuntimeId, PublicationEpoch,
};
pub use generation_lifecycle::{ResidentGenerationLifecycle, ResidentGenerationState};
pub use metrics::{
    ProxiedDoh3CleanupMetricObservation, ResidentDataplaneMetrics, ResidentTcpConnectionGuard,
    ResidentTrafficCounters, ResidentUdpActivityGuard, UdpIngressMetricObservation,
};
pub use network_defaults::{
    ANYTLS_LOCAL_CLOSE_DRAIN_TIMEOUT, RESIDENT_ANYTLS_RELAY_BUFFER_SIZE, RESIDENT_CONNECT_TIMEOUT,
    RESIDENT_DNS_DEFAULT_PORT, RESIDENT_IDLE_SLEEP, RESIDENT_RUNTIME_FORCED_TASK_JOIN_GRACE,
    RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE, RESIDENT_RUNTIME_TASK_JOIN_GRACE,
    RESIDENT_TCP_CANDIDATE_ATTEMPT_DELAY, RESIDENT_TCP_CANDIDATE_MAX_IN_FLIGHT,
    RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT, RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT,
    RESIDENT_TCP_IDLE_TIMEOUT, RESIDENT_UDP_DNS_SESSION_IDLE_TIMEOUT,
    RESIDENT_UDP_RESPONSE_TIMEOUT, RESIDENT_UDP_SOCKET_BUFFER_BYTES_DEFAULT,
    RESIDENT_UDP_SOCKET_BUFFER_BYTES_ENV, RESIDENT_UDP_SOCKET_BUFFER_BYTES_MAX,
    RESIDENT_UDP_SOCKET_BUFFER_BYTES_MIN, TLS_RECORD_HEADER_LEN, TLS_RECORD_MAX_PAYLOAD_LEN,
    VISION_COMMAND_CONTINUE, VISION_COMMAND_DIRECT, VISION_COMMAND_END, VLESS_RESPONSE_VERSION,
    XUDP_COMMAND_KEEP, XUDP_COMMAND_NEW, XUDP_MUX_TARGET, XUDP_NETWORK_UDP, XUDP_OPTION_DATA,
    resident_udp_runtime_topology,
};
pub use payload_admission::{
    ResidentUdpPayloadAdmission, ResidentUdpPayloadAdmissionError, ResidentUdpPayloadPermit,
};
pub use relay_deadline::{reset_resident_relay_idle_deadline, resident_relay_idle_deadline};
pub use resource_profile::*;
pub use session_admission::{
    ResidentUdpSessionAdmission, ResidentUdpSessionAdmissionError, ResidentUdpSessionPermit,
};
pub use socket::{apply_udp_socket_buffer_tuning, set_socket_mark};
pub use stop_signal::{
    ResidentStopListener, ResidentStopSignal, SharedResidentStopSignal, run_until_resident_stop,
};
pub use task_set::{
    ResidentTaskSetShutdown, record_resident_task_completion, shutdown_resident_task_set,
};

pub trait ResidentHealthResuscitation: std::fmt::Debug + Send + Sync {
    fn trigger(&self, outbound: u8, network_type: dae_core_types::NetworkTypeId);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentOwnedTaskShutdownCompletion {
    Joined,
    Aborted,
}
