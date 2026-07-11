use crate::kernel_program_packet::IPPROTO_FRAGMENT;
use crate::*;

#[test]
fn packet_level_golden_cases_cover_required_admission_queue() {
    let cases = packet_level_golden_cases();
    let case_names = cases.iter().map(|case| case.name).collect::<Vec<_>>();
    let queue_names = packet_level_golden_evidence_queue()
        .iter()
        .map(|line| line.item)
        .collect::<Vec<_>>();
    assert_eq!(case_names, queue_names);
    assert!(
        cases
            .iter()
            .any(|case| case.name == "truncated_packet_no_drop"
                && case.expected_disposition == KernelPacketParseDisposition::FaultNoDrop)
    );
}

#[test]
fn packet_level_golden_parses_l2_and_l3_ipv4_tcp_udp() {
    let tcp = tcp_header(12_345, 443, 0x02);
    let udp = udp_header(53_000, 53);

    let report = parse_kernel_program_packet(ETH_HLEN, 0, &ethernet(ipv4(IPPROTO_TCP, &tcp, 0xa0)));
    assert_ipv4_transport(&report, IPPROTO_TCP, 12_345, 443);
    assert_eq!(report.parsed.tcp_flags, 0x02);
    assert_eq!(report.parsed.dscp, 40);

    let report = parse_kernel_program_packet(ETH_HLEN, 0, &ethernet(ipv4(IPPROTO_UDP, &udp, 0x2c)));
    assert_ipv4_transport(&report, IPPROTO_UDP, 53_000, 53);
    assert_eq!(report.parsed.dscp, 11);

    let report = parse_kernel_program_packet(0, ETH_P_IP_NETWORK, &ipv4(IPPROTO_TCP, &tcp, 0));
    assert_ipv4_transport(&report, IPPROTO_TCP, 12_345, 443);

    let report = parse_kernel_program_packet(0, ETH_P_IP_NETWORK, &ipv4(IPPROTO_UDP, &udp, 0));
    assert_ipv4_transport(&report, IPPROTO_UDP, 53_000, 53);
}

#[test]
fn packet_level_golden_parses_dscp_four_with_ecn_bits_ignored() {
    let tcp = tcp_header(12_345, 443, 0x02);
    let udp = udp_header(53_000, 53);

    let report = parse_kernel_program_packet(
        ETH_HLEN,
        0,
        &ethernet(ipv4(IPPROTO_TCP, &tcp, (0x04 << 2) | 0x03)),
    );
    assert_ipv4_transport(&report, IPPROTO_TCP, 12_345, 443);
    assert_eq!(report.parsed.dscp, 0x04);

    let report = parse_kernel_program_packet(
        ETH_HLEN,
        0,
        &ethernet_ipv6(ipv6(IPPROTO_UDP, &udp, (0x04 << 2) | 0x02)),
    );
    assert_ipv6_transport(&report, IPPROTO_UDP, 53_000, 53);
    assert_eq!(report.parsed.dscp, 0x04);
}

#[test]
fn packet_level_golden_parses_ipv6_tcp_udp_extensions_and_ndp_redirect() {
    let tcp = tcp_header(12_345, 443, 0x10);
    let udp = udp_header(53_000, 53);

    let report =
        parse_kernel_program_packet(ETH_HLEN, 0, &ethernet_ipv6(ipv6(IPPROTO_TCP, &tcp, 0xbc)));
    assert_ipv6_transport(&report, IPPROTO_TCP, 12_345, 443);
    assert_eq!(report.parsed.tcp_flags, 0x10);
    assert_eq!(report.parsed.dscp, 47);

    let report =
        parse_kernel_program_packet(ETH_HLEN, 0, &ethernet_ipv6(ipv6(IPPROTO_UDP, &udp, 0x14)));
    assert_ipv6_transport(&report, IPPROTO_UDP, 53_000, 53);
    assert_eq!(report.parsed.dscp, 5);

    let mut hop_by_hop = vec![IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 0];
    hop_by_hop.extend_from_slice(&udp);
    let report = parse_kernel_program_packet(ETH_HLEN, 0, &ethernet_ipv6(ipv6(0, &hop_by_hop, 0)));
    assert_ipv6_transport(&report, IPPROTO_UDP, 53_000, 53);

    let mut icmp = [0u8; 8];
    icmp[0] = NDP_REDIRECT;
    let report =
        parse_kernel_program_packet(ETH_HLEN, 0, &ethernet_ipv6(ipv6(IPPROTO_ICMPV6, &icmp, 0)));
    assert_eq!(
        report.disposition,
        KernelPacketParseDisposition::Parsed,
        "{}",
        report.disposition.as_str()
    );
    assert_eq!(report.parsed.l4proto, IPPROTO_ICMPV6);
    assert_eq!(report.parsed.icmp6_type, NDP_REDIRECT);
}

#[test]
fn packet_level_golden_only_parses_transport_headers_from_initial_fragments() {
    let udp = udp_header(12_345, 53);

    let initial_ipv4 = ipv4_fragment(IPPROTO_UDP, &udp, 0, true);
    let report = parse_kernel_program_packet(ETH_HLEN, 0, &ethernet(initial_ipv4));
    assert_ipv4_transport(&report, IPPROTO_UDP, 12_345, 53);

    let non_initial_ipv4 = ipv4_fragment(IPPROTO_UDP, &udp, 1, false);
    let report = parse_kernel_program_packet(ETH_HLEN, 0, &ethernet(non_initial_ipv4));
    assert_eq!(
        report.disposition,
        KernelPacketParseDisposition::ChainNextNoDrop
    );
    assert_eq!((report.parsed.sport, report.parsed.dport), (0, 0));

    let initial_ipv6 = ipv6_fragment(IPPROTO_UDP, &udp, 0, true);
    let report = parse_kernel_program_packet(ETH_HLEN, 0, &ethernet_ipv6(initial_ipv6));
    assert_ipv6_transport(&report, IPPROTO_UDP, 12_345, 53);

    let non_initial_ipv6 = ipv6_fragment(IPPROTO_UDP, &udp, 1, false);
    let report = parse_kernel_program_packet(ETH_HLEN, 0, &ethernet_ipv6(non_initial_ipv6));
    assert_eq!(
        report.disposition,
        KernelPacketParseDisposition::ChainNextNoDrop
    );
    assert_eq!((report.parsed.sport, report.parsed.dport), (0, 0));
}

#[test]
fn packet_level_golden_faults_truncated_ipv6_fragment_header_without_drop() {
    let report = parse_kernel_program_packet(
        ETH_HLEN,
        0,
        &ethernet_ipv6(ipv6(IPPROTO_FRAGMENT, &[IPPROTO_UDP, 0, 0], 0)),
    );
    assert_eq!(
        report.disposition,
        KernelPacketParseDisposition::FaultNoDrop
    );
    assert_eq!((report.parsed.sport, report.parsed.dport), (0, 0));
}

#[test]
fn packet_level_golden_passes_unsupported_and_faults_truncated_without_drop() {
    let report = parse_kernel_program_packet(ETH_HLEN, 0, &ethernet_with_proto(0x0806, &[]));
    assert_eq!(
        report.disposition,
        KernelPacketParseDisposition::ChainNextNoDrop
    );

    let report = parse_kernel_program_packet(ETH_HLEN, 0, &ethernet(ipv4(1, &[0; 8], 0)));
    assert_eq!(
        report.disposition,
        KernelPacketParseDisposition::ChainNextNoDrop
    );

    let short_udp_ports_only = [0x00, 0x35, 0xd9, 0x08];
    let report = parse_kernel_program_packet(
        ETH_HLEN,
        0,
        &ethernet(ipv4(IPPROTO_UDP, &short_udp_ports_only, 0)),
    );
    assert_eq!(
        report.disposition,
        KernelPacketParseDisposition::FaultNoDrop
    );
}

fn assert_ipv4_transport(report: &KernelPacketParseReport, proto: u8, sport: u16, dport: u16) {
    assert_eq!(report.disposition, KernelPacketParseDisposition::Parsed);
    assert!(report.parsed.is_ipv4);
    assert_eq!(report.parsed.h_proto, ETH_P_IP_NETWORK);
    assert_eq!(report.parsed.l4proto, proto);
    assert_eq!(report.parsed.sport, sport.to_be());
    assert_eq!(report.parsed.dport, dport.to_be());
    assert_eq!(&report.parsed.sip[10..16], &[0xff, 0xff, 192, 0, 2, 1]);
    assert_eq!(&report.parsed.dip[10..16], &[0xff, 0xff, 198, 51, 100, 2]);
}

fn assert_ipv6_transport(report: &KernelPacketParseReport, proto: u8, sport: u16, dport: u16) {
    assert_eq!(report.disposition, KernelPacketParseDisposition::Parsed);
    assert!(!report.parsed.is_ipv4);
    assert_eq!(report.parsed.h_proto, ETH_P_IPV6_NETWORK);
    assert_eq!(report.parsed.l4proto, proto);
    assert_eq!(report.parsed.sport, sport.to_be());
    assert_eq!(report.parsed.dport, dport.to_be());
    assert_eq!(&report.parsed.sip[0..4], &[0x20, 0x01, 0x0d, 0xb8]);
    assert_eq!(&report.parsed.dip[0..4], &[0x20, 0x01, 0x0d, 0xb8]);
}

fn ethernet(payload: Vec<u8>) -> Vec<u8> {
    ethernet_with_proto(0x0800, &payload)
}

fn ethernet_ipv6(payload: Vec<u8>) -> Vec<u8> {
    ethernet_with_proto(0x86dd, &payload)
}

fn ethernet_with_proto(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn ipv4(proto: u8, payload: &[u8], tos: u8) -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[1] = tos;
    packet[2..4].copy_from_slice(&(20u16 + payload.len() as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = proto;
    packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
    packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
    packet.extend_from_slice(payload);
    packet
}

fn ipv4_fragment(proto: u8, payload: &[u8], fragment_offset: u16, more_fragments: bool) -> Vec<u8> {
    let mut packet = ipv4(proto, payload, 0);
    let fragment_field = (fragment_offset & 0x1fff) | if more_fragments { 0x2000 } else { 0 };
    packet[6..8].copy_from_slice(&fragment_field.to_be_bytes());
    packet
}

fn ipv6(nexthdr: u8, payload: &[u8], traffic_class: u8) -> Vec<u8> {
    let mut packet = vec![0u8; 40];
    packet[0] = 0x60 | (traffic_class >> 4);
    packet[1] = (traffic_class & 0x0f) << 4;
    packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    packet[6] = nexthdr;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    packet[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    packet.extend_from_slice(payload);
    packet
}

fn ipv6_fragment(
    transport_protocol: u8,
    payload: &[u8],
    fragment_offset: u16,
    more_fragments: bool,
) -> Vec<u8> {
    let mut fragment = [0u8; 8];
    fragment[0] = transport_protocol;
    let fragment_field = ((fragment_offset & 0x1fff) << 3) | u16::from(more_fragments);
    fragment[2..4].copy_from_slice(&fragment_field.to_be_bytes());
    fragment[4..8].copy_from_slice(&0x1234_5678_u32.to_be_bytes());
    let mut body = fragment.to_vec();
    body.extend_from_slice(payload);
    ipv6(IPPROTO_FRAGMENT, &body, 0)
}

fn tcp_header(sport: u16, dport: u16, flags: u8) -> [u8; 20] {
    let mut tcp = [0u8; 20];
    tcp[0..2].copy_from_slice(&sport.to_be_bytes());
    tcp[2..4].copy_from_slice(&dport.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = flags;
    tcp
}

fn udp_header(sport: u16, dport: u16) -> [u8; 8] {
    let mut udp = [0u8; 8];
    udp[0..2].copy_from_slice(&sport.to_be_bytes());
    udp[2..4].copy_from_slice(&dport.to_be_bytes());
    udp[4..6].copy_from_slice(&8u16.to_be_bytes());
    udp
}
