mod payload_admission;
mod resource_profile;
mod socket;

use std::time::Duration;

use serde_json::{Value, json};

pub use payload_admission::{
    ResidentUdpPayloadAdmission, ResidentUdpPayloadAdmissionError, ResidentUdpPayloadPermit,
    admit_udp_payload,
};
pub use resource_profile::*;
pub use socket::set_socket_mark;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentOwnedTaskShutdownCompletion {
    Joined,
    Aborted,
}
