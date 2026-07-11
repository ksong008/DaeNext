pub const ETH_HLEN: u32 = 14;
pub const ETH_P_IP_NETWORK: u16 = u16::to_be(0x0800);
pub const ETH_P_IPV6_NETWORK: u16 = u16::to_be(0x86dd);
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const NDP_REDIRECT: u8 = 137;

const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_ROUTING: u8 = 43;
pub const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_NONE: u8 = 59;
const IPPROTO_DSTOPTS: u8 = 60;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const IPV6_MAX_EXTENSIONS: u8 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelPacketParseDisposition {
    Parsed,
    ChainNextNoDrop,
    FaultNoDrop,
}

impl KernelPacketParseDisposition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parsed => "parsed",
            Self::ChainNextNoDrop => "chain_next_no_drop",
            Self::FaultNoDrop => "fault_no_drop",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelPacketParsed {
    pub eth_src: [u8; 6],
    pub eth_dst: [u8; 6],
    pub h_proto: u16,
    pub sip: [u8; 16],
    pub dip: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub l4proto: u8,
    pub dscp: u8,
    pub tcp_flags: u8,
    pub icmp6_type: u8,
    pub is_ipv4: bool,
}

impl KernelPacketParsed {
    pub const fn zeroed(h_proto: u16) -> Self {
        Self {
            eth_src: [0; 6],
            eth_dst: [0; 6],
            h_proto,
            sip: [0; 16],
            dip: [0; 16],
            sport: 0,
            dport: 0,
            l4proto: 0,
            dscp: 0,
            tcp_flags: 0,
            icmp6_type: 0,
            is_ipv4: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelPacketParseReport {
    pub disposition: KernelPacketParseDisposition,
    pub parsed: KernelPacketParsed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelPacketGoldenCase {
    pub name: &'static str,
    pub expected_disposition: KernelPacketParseDisposition,
}

pub fn packet_level_golden_cases() -> Vec<KernelPacketGoldenCase> {
    [
        ("l2_ipv4_tcp", KernelPacketParseDisposition::Parsed),
        ("l2_ipv4_udp", KernelPacketParseDisposition::Parsed),
        ("l3_ipv4_tcp", KernelPacketParseDisposition::Parsed),
        ("l3_ipv4_udp", KernelPacketParseDisposition::Parsed),
        ("l2_ipv6_tcp", KernelPacketParseDisposition::Parsed),
        ("l2_ipv6_udp", KernelPacketParseDisposition::Parsed),
        (
            "ipv6_extension_headers",
            KernelPacketParseDisposition::Parsed,
        ),
        (
            "ipv4_non_initial_fragment_pass",
            KernelPacketParseDisposition::ChainNextNoDrop,
        ),
        (
            "ipv6_non_initial_fragment_pass",
            KernelPacketParseDisposition::ChainNextNoDrop,
        ),
        (
            "ipv6_icmpv6_ndp_redirect",
            KernelPacketParseDisposition::Parsed,
        ),
        (
            "unsupported_l3_protocol_pass",
            KernelPacketParseDisposition::ChainNextNoDrop,
        ),
        (
            "unsupported_l4_protocol_pass",
            KernelPacketParseDisposition::ChainNextNoDrop,
        ),
        (
            "truncated_packet_no_drop",
            KernelPacketParseDisposition::FaultNoDrop,
        ),
    ]
    .into_iter()
    .map(|(name, expected_disposition)| KernelPacketGoldenCase {
        name,
        expected_disposition,
    })
    .collect()
}

pub fn parse_kernel_program_packet(
    link_h_len: u32,
    skb_protocol: u16,
    packet: &[u8],
) -> KernelPacketParseReport {
    let mut parsed = KernelPacketParsed::zeroed(skb_protocol);
    let mut network_offset = 0usize;
    if link_h_len == ETH_HLEN {
        let Some(eth) = packet.get(0..ETH_HLEN as usize) else {
            return fault(parsed);
        };
        parsed.eth_dst.copy_from_slice(&eth[0..6]);
        parsed.eth_src.copy_from_slice(&eth[6..12]);
        parsed.h_proto = read_ne_u16(eth, 12);
        network_offset = ETH_HLEN as usize;
    }

    match parsed.h_proto {
        ETH_P_IP_NETWORK => parse_ipv4(packet, network_offset, parsed),
        ETH_P_IPV6_NETWORK => parse_ipv6(packet, network_offset, parsed),
        _ => chain_next(parsed),
    }
}

fn parse_ipv4(
    packet: &[u8],
    network_offset: usize,
    mut parsed: KernelPacketParsed,
) -> KernelPacketParseReport {
    let Some(ip) = packet.get(network_offset..network_offset + IPV4_MIN_HEADER_LEN) else {
        return fault(parsed);
    };
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < IPV4_MIN_HEADER_LEN {
        return fault(parsed);
    }
    parsed.is_ipv4 = true;
    parsed.l4proto = ip[9];
    parsed.dscp = (ip[1] & 0xfc) >> 2;
    parsed.sip[10] = 0xff;
    parsed.sip[11] = 0xff;
    parsed.sip[12..16].copy_from_slice(&ip[12..16]);
    parsed.dip[10] = 0xff;
    parsed.dip[11] = 0xff;
    parsed.dip[12..16].copy_from_slice(&ip[16..20]);
    if read_be_u16(ip, 6) & 0x1fff != 0 {
        return chain_next(parsed);
    }
    parse_l4(packet, network_offset + ihl, parsed)
}

fn parse_ipv6(
    packet: &[u8],
    network_offset: usize,
    mut parsed: KernelPacketParsed,
) -> KernelPacketParseReport {
    let Some(ip) = packet.get(network_offset..network_offset + IPV6_HEADER_LEN) else {
        return fault(parsed);
    };
    parsed.is_ipv4 = false;
    parsed.dscp = ((ip[0] & 0x0f) << 2) | (ip[1] >> 6);
    parsed.sip.copy_from_slice(&ip[8..24]);
    parsed.dip.copy_from_slice(&ip[24..40]);

    let mut offset = network_offset + IPV6_HEADER_LEN;
    let mut nexthdr = ip[6];
    let mut i = 0_u8;
    while i < IPV6_MAX_EXTENSIONS {
        if nexthdr == IPPROTO_NONE || !is_ipv6_extension_header(nexthdr) {
            break;
        }
        if nexthdr == IPPROTO_FRAGMENT {
            let Some(fragment) = packet.get(offset..offset + 8) else {
                return fault(parsed);
            };
            nexthdr = fragment[0];
            offset += fragment.len();
            if read_be_u16(fragment, 2) & 0xfff8 != 0 {
                return chain_next(parsed);
            }
        } else {
            let Some(ext) = packet.get(offset..offset + 2) else {
                return fault(parsed);
            };
            nexthdr = ext[0];
            offset += ipv6_optlen(ext[1]) as usize;
        }
        i += 1;
    }
    if is_ipv6_extension_header(nexthdr) {
        return chain_next(parsed);
    }
    parsed.l4proto = nexthdr;
    parse_l4(packet, offset, parsed)
}

fn parse_l4(
    packet: &[u8],
    transport_offset: usize,
    mut parsed: KernelPacketParsed,
) -> KernelPacketParseReport {
    match parsed.l4proto {
        IPPROTO_TCP => {
            let Some(tcp) = packet.get(transport_offset..transport_offset + 20) else {
                return fault(parsed);
            };
            parsed.sport = read_ne_u16(tcp, 0);
            parsed.dport = read_ne_u16(tcp, 2);
            parsed.tcp_flags = tcp[13];
            parsed_report(parsed)
        }
        IPPROTO_UDP => {
            let Some(udp) = packet.get(transport_offset..transport_offset + 8) else {
                return fault(parsed);
            };
            parsed.sport = read_ne_u16(udp, 0);
            parsed.dport = read_ne_u16(udp, 2);
            parsed_report(parsed)
        }
        IPPROTO_ICMPV6 => {
            let Some(icmp) = packet.get(transport_offset..transport_offset + 8) else {
                return fault(parsed);
            };
            parsed.icmp6_type = icmp[0];
            parsed_report(parsed)
        }
        _ => chain_next(parsed),
    }
}

fn read_ne_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_ne_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_be_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn is_ipv6_extension_header(nexthdr: u8) -> bool {
    matches!(
        nexthdr,
        IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_FRAGMENT | IPPROTO_DSTOPTS
    )
}

fn ipv6_optlen(hdr_ext_len: u8) -> u32 {
    ((hdr_ext_len as u32) + 1) << 3
}

fn parsed_report(parsed: KernelPacketParsed) -> KernelPacketParseReport {
    KernelPacketParseReport {
        disposition: KernelPacketParseDisposition::Parsed,
        parsed,
    }
}

fn chain_next(parsed: KernelPacketParsed) -> KernelPacketParseReport {
    KernelPacketParseReport {
        disposition: KernelPacketParseDisposition::ChainNextNoDrop,
        parsed,
    }
}

fn fault(parsed: KernelPacketParsed) -> KernelPacketParseReport {
    KernelPacketParseReport {
        disposition: KernelPacketParseDisposition::FaultNoDrop,
        parsed,
    }
}
