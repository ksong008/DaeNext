use std::net::SocketAddr;

use dae_datapath::OUTBOUND_CONTROL_PLANE_ROUTING;
use dae_dns::{DNS_DEFAULT_PORT, DnsPacketView};
use dae_ebpf_support::BpfRoutingResult;

pub(super) fn resident_udp_dns_fast_path_applies(original_dst: SocketAddr) -> bool {
    original_dst.port() == DNS_DEFAULT_PORT
}

pub(super) fn resident_udp_dns_fast_path_can_bypass_missing_tuple(
    original_dst: SocketAddr,
    payload: &[u8],
) -> bool {
    resident_udp_dns_fast_path_applies(original_dst) && resident_udp_payload_is_dns_request(payload)
}

pub(super) fn minimal_resident_dns_routing_result() -> BpfRoutingResult {
    BpfRoutingResult {
        outbound: OUTBOUND_CONTROL_PLANE_ROUTING,
        ..BpfRoutingResult::default()
    }
}

fn resident_udp_payload_is_dns_request(payload: &[u8]) -> bool {
    let Ok(request) = DnsPacketView::parse(payload) else {
        return false;
    };
    !request.response() && request.question_count() > 0
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use dae_datapath::OUTBOUND_CONTROL_PLANE_ROUTING;
    use dae_dns::DNS_DEFAULT_PORT;

    use super::*;

    const QUERY: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    #[test]
    fn missing_tuple_bypass_requires_dns_destination_and_request_payload() {
        let dns_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), DNS_DEFAULT_PORT);
        let non_dns_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), 853);
        let mut response = QUERY.to_vec();
        response[2] |= 0x80;

        assert!(resident_udp_dns_fast_path_can_bypass_missing_tuple(
            dns_dst, QUERY
        ));
        assert!(!resident_udp_dns_fast_path_can_bypass_missing_tuple(
            non_dns_dst,
            QUERY
        ));
        assert!(!resident_udp_dns_fast_path_can_bypass_missing_tuple(
            dns_dst, b"not-dns"
        ));
        assert!(!resident_udp_dns_fast_path_can_bypass_missing_tuple(
            dns_dst, &response
        ));
    }

    #[test]
    fn minimal_dns_routing_result_targets_control_plane_dns() {
        let result = minimal_resident_dns_routing_result();

        assert_eq!(result.outbound, OUTBOUND_CONTROL_PLANE_ROUTING);
        assert_eq!(result.must, 0);
        assert_eq!(result.mark, 0);
    }
}
