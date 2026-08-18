#![recursion_limit = "256"]

mod active_generation_slot;
mod generation_identity;
mod generation_lifecycle;
mod metrics;
mod network_defaults;
mod payload_admission;
mod relay_deadline;
mod resource_profile;
mod socket;
mod stop_signal;

use std::time::Duration;

use serde_json::{Value, json};

pub use active_generation_slot::ActiveGenerationSlot;
pub use generation_identity::{
    GenerationToken, LogicalGenerationId, PhysicalRuntimeId, PublicationEpoch,
};
pub use generation_lifecycle::{ResidentGenerationLifecycle, ResidentGenerationState};
pub use metrics::{
    ProxiedDoh3CleanupMetricObservation, ResidentDataplaneMetrics, ResidentTcpConnectionGuard,
    ResidentTrafficCounters, ResidentUdpActivityGuard, UdpIngressMetricObservation,
};
pub use network_defaults::{
    RESIDENT_CONNECT_TIMEOUT, RESIDENT_TCP_CANDIDATE_ATTEMPT_DELAY,
    RESIDENT_TCP_CANDIDATE_MAX_IN_FLIGHT, RESIDENT_UDP_RESPONSE_TIMEOUT,
};
pub use payload_admission::{
    ResidentUdpPayloadAdmission, ResidentUdpPayloadAdmissionError, ResidentUdpPayloadPermit,
    admit_udp_payload,
};
pub use relay_deadline::{reset_resident_relay_idle_deadline, resident_relay_idle_deadline};
pub use resource_profile::*;
pub use socket::set_socket_mark;
pub use stop_signal::{
    ResidentStopListener, ResidentStopSignal, SharedResidentStopSignal, run_until_resident_stop,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentOwnedTaskShutdownCompletion {
    Joined,
    Aborted,
}
