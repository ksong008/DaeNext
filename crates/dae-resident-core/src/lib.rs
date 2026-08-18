mod payload_admission;
mod socket;

pub use payload_admission::{
    ResidentUdpPayloadAdmission, ResidentUdpPayloadAdmissionError, ResidentUdpPayloadPermit,
    admit_udp_payload,
};
pub use socket::set_socket_mark;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentOwnedTaskShutdownCompletion {
    Joined,
    Aborted,
}
