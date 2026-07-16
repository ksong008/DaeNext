use super::*;

#[test]
fn nested_chain_selectors_require_the_effective_udp_disposition() {
    let socks_policy_closed = MaterializedSourceShape {
        chain: MaterializedChain::ParentConnect,
        chain_udp: MaterializedChainUdp::PolicyClosed,
        ..standalone(
            MaterializedProtocol::Socks5,
            TEST_NO_SECURITY_VARIANT,
            MaterializedWrapper::None,
            MaterializedUdp::Socks5Associate,
        )
    };
    assert!(matches("nested-chain-shape", socks_policy_closed));
    assert!(!matches(
        "nested-chain-shape",
        MaterializedSourceShape {
            chain_udp: MaterializedChainUdp::ParentStream,
            ..socks_policy_closed
        }
    ));

    let vmess_parent_stream = MaterializedSourceShape {
        chain: MaterializedChain::ParentConnect,
        chain_udp: MaterializedChainUdp::ParentStream,
        ..standalone(
            MaterializedProtocol::VmessAead,
            TEST_NO_SECURITY_VARIANT,
            MaterializedWrapper::None,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::PlainTcp),
        )
    };
    assert!(matches("nested-chain-shape", vmess_parent_stream));
    assert!(!matches(
        "nested-chain-shape",
        MaterializedSourceShape {
            chain_udp: MaterializedChainUdp::PolicyClosed,
            ..vmess_parent_stream
        }
    ));
}
