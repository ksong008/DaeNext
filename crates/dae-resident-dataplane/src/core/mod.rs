mod payload_admission;
mod socket;

pub(crate) use payload_admission::{
    ResidentUdpPayloadAdmission, ResidentUdpPayloadAdmissionError, ResidentUdpPayloadPermit,
    admit_udp_payload,
};
pub(crate) use socket::set_socket_mark;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidentOwnedTaskShutdownCompletion {
    Joined,
    Aborted,
}
