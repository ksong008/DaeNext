use super::*;

#[test]
fn stage112_tuic_underlay_admission_contract_preserves_mark_and_drops_tcp_mptcp() {
    let contract = tuic::underlay::admission_contract(1234, true);

    assert_eq!(contract.tcp_request.input_network, "tcp");
    assert_eq!(contract.tcp_request.underlay_network, "udp");
    assert_eq!(contract.tcp_request.input_mark, 1234);
    assert_eq!(contract.tcp_request.underlay_mark, 1234);
    assert!(contract.tcp_request.input_mptcp);
    assert!(!contract.tcp_request.underlay_mptcp);
    assert!(contract.tcp_underlay_uses_udp);
    assert!(contract.tcp_underlay_preserves_mark);
    assert!(contract.tcp_underlay_drops_mptcp);

    assert_eq!(contract.udp_request.input_network, "udp");
    assert_eq!(contract.udp_request.underlay_network, "udp");
    assert_eq!(contract.udp_request.input_mark, 1234);
    assert_eq!(contract.udp_request.underlay_mark, 1234);
    assert!(contract.udp_request.input_mptcp);
    assert!(contract.udp_request.underlay_mptcp);
    assert!(contract.udp_underlay_uses_original);
    assert!(contract.socket_so_mark_observation_required);
    assert!(contract.true_quic_dataplane_deferred);
}
