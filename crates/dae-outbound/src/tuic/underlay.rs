use super::link::{TuicUnderlayContract, underlay_contract};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TuicUnderlayAdmissionContract {
    pub tcp_request: TuicUnderlayContract,
    pub udp_request: TuicUnderlayContract,
    pub tcp_underlay_uses_udp: bool,
    pub tcp_underlay_preserves_mark: bool,
    pub tcp_underlay_drops_mptcp: bool,
    pub udp_underlay_uses_original: bool,
    pub socket_so_mark_observation_required: bool,
    pub true_quic_dataplane_deferred: bool,
}

pub fn admission_contract(mark: u32, mptcp: bool) -> TuicUnderlayAdmissionContract {
    let tcp_request = underlay_contract("tcp", mark, mptcp)
        .expect("fixed TUIC TCP network fits MagicNetwork framing");
    let udp_request = underlay_contract("udp", mark, mptcp)
        .expect("fixed TUIC UDP network fits MagicNetwork framing");
    TuicUnderlayAdmissionContract {
        tcp_underlay_uses_udp: tcp_request.underlay_network == "udp",
        tcp_underlay_preserves_mark: tcp_request.underlay_mark == mark,
        tcp_underlay_drops_mptcp: !tcp_request.underlay_mptcp,
        udp_underlay_uses_original: udp_request.underlay_network == udp_request.input_network,
        socket_so_mark_observation_required: true,
        true_quic_dataplane_deferred: true,
        tcp_request,
        udp_request,
    }
}
