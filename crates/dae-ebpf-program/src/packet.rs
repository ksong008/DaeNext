use core::{ffi::c_void, mem, ptr};

use aya_ebpf::bindings::__sk_buff;

use crate::abi::{BpfIpBytes, BpfRedirectTuple, BpfTuplesKey};
use crate::helpers;

pub const ETH_HLEN: u32 = 14;
pub const ETH_DST_OFFSET: u32 = 0;
pub const ETH_SRC_OFFSET: u32 = 6;
pub const ETH_PROTO_OFFSET: u32 = 12;
pub const ETH_P_IP_NETWORK: u32 = u16::to_be(0x0800) as u32;
pub const ETH_P_IPV6_NETWORK: u32 = u16::to_be(0x86dd) as u32;
pub const ETH_P_8021Q_NETWORK: u32 = u16::to_be(0x8100) as u32;
pub const ETH_P_8021AD_NETWORK: u32 = u16::to_be(0x88a8) as u32;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const NDP_REDIRECT: u8 = 137;

const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_NONE: u8 = 59;
const IPPROTO_DSTOPTS: u8 = 60;
const IPV4_MIN_HEADER_LEN: u32 = 20;
const IPV4_SADDR_OFFSET: usize = 12;
const IPV4_DADDR_OFFSET: usize = 16;
const IPV6_HEADER_LEN: u32 = 40;
const IPV6_SADDR_OFFSET: usize = 8;
const IPV6_DADDR_OFFSET: usize = 24;
const IPV6_MAX_EXTENSIONS: u8 = 8;
const VLAN_HLEN: u32 = 4;
const VLAN_MAX_DEPTH: u8 = 2;

#[repr(C)]
pub struct ParsedPacket {
    pub eth_src: [u8; 6],
    pub eth_dst: [u8; 6],
    pub h_proto: u32,
    pub sip: BpfIpBytes,
    pub dip: BpfIpBytes,
    pub sport: u16,
    pub dport: u16,
    pub l4proto: u8,
    pub dscp: u8,
    pub tcp_flags: u8,
    pub icmp6_type: u8,
    pub is_ipv4: u8,
}

impl ParsedPacket {
    pub const fn zeroed() -> Self {
        Self {
            eth_src: [0; 6],
            eth_dst: [0; 6],
            h_proto: 0,
            sip: BpfIpBytes::zeroed(),
            dip: BpfIpBytes::zeroed(),
            sport: 0,
            dport: 0,
            l4proto: 0,
            dscp: 0,
            tcp_flags: 0,
            icmp6_type: 0,
            is_ipv4: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfSockTupleIpv4 {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfSockTupleIpv6 {
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub sport: u16,
    pub dport: u16,
}

#[repr(C)]
pub union BpfSockTuple {
    pub ipv4: BpfSockTupleIpv4,
    pub ipv6: BpfSockTupleIpv6,
}

#[inline(always)]
fn read_ne_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_ne_bytes([bytes[offset], bytes[offset + 1]])
}

#[inline(always)]
fn read_be_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

#[inline(always)]
fn read_ne_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[inline(always)]
pub fn read_le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

#[inline(always)]
pub fn read_le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[inline(always)]
unsafe fn copy4(dst: *mut u8, src: *const u8) {
    unsafe {
        dst.add(0).write_volatile(src.add(0).read_volatile());
        dst.add(1).write_volatile(src.add(1).read_volatile());
        dst.add(2).write_volatile(src.add(2).read_volatile());
        dst.add(3).write_volatile(src.add(3).read_volatile());
    }
}

#[inline(always)]
pub unsafe fn copy16(dst: *mut u8, src: *const u8) {
    unsafe {
        copy4(dst, src);
        copy4(dst.add(4), src.add(4));
        copy4(dst.add(8), src.add(8));
        copy4(dst.add(12), src.add(12));
    }
}

#[inline(always)]
pub unsafe fn copy_ip(dst: *mut BpfIpBytes, src: *const BpfIpBytes) {
    unsafe {
        copy16(
            ptr::addr_of_mut!((*dst).u6_addr8).cast::<u8>(),
            ptr::addr_of!((*src).u6_addr8).cast::<u8>(),
        );
    }
}

#[inline(always)]
pub unsafe fn copy_mac(dst: *mut u8, src: *const u8) {
    unsafe {
        dst.add(0).write_volatile(src.add(0).read_volatile());
        dst.add(1).write_volatile(src.add(1).read_volatile());
        dst.add(2).write_volatile(src.add(2).read_volatile());
        dst.add(3).write_volatile(src.add(3).read_volatile());
        dst.add(4).write_volatile(src.add(4).read_volatile());
        dst.add(5).write_volatile(src.add(5).read_volatile());
    }
}

#[inline(always)]
unsafe fn load_bytes(skb: *mut __sk_buff, offset: u32, dst: *mut c_void, len: u32) -> bool {
    unsafe { helpers::bpf_skb_load_bytes(skb.cast::<c_void>(), offset, dst, len) == 0 }
}

#[inline(always)]
fn is_ipv6_extension_header(nexthdr: u8) -> bool {
    matches!(
        nexthdr,
        IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_FRAGMENT | IPPROTO_DSTOPTS
    )
}

#[inline(always)]
fn ipv6_optlen(hdr_ext_len: u8) -> u32 {
    ((hdr_ext_len as u32) + 1) << 3
}

#[inline(always)]
fn is_vlan_protocol(proto: u32) -> bool {
    proto == ETH_P_8021Q_NETWORK || proto == ETH_P_8021AD_NETWORK
}

#[inline(always)]
pub unsafe fn parse_transport(skb: *mut __sk_buff, link_h_len: u32, out: *mut ParsedPacket) -> i32 {
    unsafe {
        ptr::write(out, ParsedPacket::zeroed());
        (*out).h_proto = (*skb).protocol;
    }

    let mut network_offset = 0_u32;
    let mut vlan_depth = if unsafe { (*skb).vlan_present } != 0 {
        if !is_vlan_protocol(unsafe { (*skb).vlan_proto } & 0xffff) {
            return 1;
        }
        1
    } else {
        0
    };
    if link_h_len == ETH_HLEN {
        let mut eth = [0u8; ETH_HLEN as usize];
        if !unsafe { load_bytes(skb, 0, eth.as_mut_ptr().cast::<c_void>(), ETH_HLEN) } {
            return -1;
        }
        unsafe {
            copy_mac((*out).eth_dst.as_mut_ptr(), eth.as_ptr());
            copy_mac((*out).eth_src.as_mut_ptr(), eth.as_ptr().add(6));
            (*out).h_proto = read_ne_u16(&eth, 12) as u32;
        }
        network_offset += ETH_HLEN;
    }

    let mut proto = unsafe { (*out).h_proto };
    while is_vlan_protocol(proto) {
        if vlan_depth >= VLAN_MAX_DEPTH {
            return 1;
        }
        if !unsafe {
            load_bytes(
                skb,
                network_offset,
                ptr::addr_of_mut!((*out).sport).cast::<c_void>(),
                VLAN_HLEN,
            )
        } {
            return -1;
        }
        proto = unsafe { (*out).dport as u32 };
        unsafe {
            (*out).sport = 0;
            (*out).dport = 0;
        }
        network_offset += VLAN_HLEN;
        vlan_depth += 1;
    }
    unsafe {
        (*out).h_proto = proto;
    }
    if proto == ETH_P_IP_NETWORK {
        unsafe { parse_ipv4(skb, network_offset, out) }
    } else if proto == ETH_P_IPV6_NETWORK {
        unsafe { parse_ipv6(skb, network_offset, out) }
    } else {
        1
    }
}

#[inline(always)]
unsafe fn parse_ipv4(skb: *mut __sk_buff, network_offset: u32, out: *mut ParsedPacket) -> i32 {
    let mut ip = [0u8; IPV4_MIN_HEADER_LEN as usize];
    if !unsafe {
        load_bytes(
            skb,
            network_offset,
            ip.as_mut_ptr().cast::<c_void>(),
            IPV4_MIN_HEADER_LEN,
        )
    } {
        return -1;
    }
    let ihl = ((ip[0] & 0x0f) as u32) * 4;
    if ihl < IPV4_MIN_HEADER_LEN {
        return -3;
    }
    unsafe {
        (*out).is_ipv4 = 1;
        (*out).l4proto = ip[9];
        (*out).dscp = (ip[1] & 0xfc) >> 2;
        (*out).sip.u6_addr8[10] = 0xff;
        (*out).sip.u6_addr8[11] = 0xff;
        (*out).dip.u6_addr8[10] = 0xff;
        (*out).dip.u6_addr8[11] = 0xff;
        copy4(
            ptr::addr_of_mut!((*out).sip.u6_addr8[12]),
            ip.as_ptr().add(IPV4_SADDR_OFFSET),
        );
        copy4(
            ptr::addr_of_mut!((*out).dip.u6_addr8[12]),
            ip.as_ptr().add(IPV4_DADDR_OFFSET),
        );
    }
    if read_be_u16(&ip, 6) & 0x1fff != 0 {
        return 1;
    }
    unsafe { parse_l4(skb, network_offset + ihl, out) }
}

#[inline(always)]
unsafe fn parse_ipv6(skb: *mut __sk_buff, network_offset: u32, out: *mut ParsedPacket) -> i32 {
    let mut ip = [0u8; IPV6_HEADER_LEN as usize];
    if !unsafe {
        load_bytes(
            skb,
            network_offset,
            ip.as_mut_ptr().cast::<c_void>(),
            IPV6_HEADER_LEN,
        )
    } {
        return -1;
    }
    unsafe {
        (*out).is_ipv4 = 0;
        (*out).dscp = ((ip[0] & 0x0f) << 2) | (ip[1] >> 6);
        copy16(
            ptr::addr_of_mut!((*out).sip.u6_addr8).cast::<u8>(),
            ip.as_ptr().add(IPV6_SADDR_OFFSET),
        );
        copy16(
            ptr::addr_of_mut!((*out).dip.u6_addr8).cast::<u8>(),
            ip.as_ptr().add(IPV6_DADDR_OFFSET),
        );
    }

    let mut offset = network_offset + IPV6_HEADER_LEN;
    let mut nexthdr = ip[6];
    let mut i = 0_u8;
    while i < IPV6_MAX_EXTENSIONS {
        if nexthdr == IPPROTO_NONE || !is_ipv6_extension_header(nexthdr) {
            break;
        }
        if nexthdr == IPPROTO_FRAGMENT {
            let mut fragment = [0u8; 8];
            if !unsafe {
                load_bytes(
                    skb,
                    offset,
                    fragment.as_mut_ptr().cast::<c_void>(),
                    fragment.len() as u32,
                )
            } {
                return -1;
            }
            nexthdr = fragment[0];
            offset += fragment.len() as u32;
            if read_be_u16(&fragment, 2) & 0xfff8 != 0 {
                return 1;
            }
        } else {
            let mut ext = [0u8; 2];
            if !unsafe { load_bytes(skb, offset, ext.as_mut_ptr().cast::<c_void>(), 2) } {
                return -1;
            }
            nexthdr = ext[0];
            offset += ipv6_optlen(ext[1]);
        }
        i += 1;
    }
    if is_ipv6_extension_header(nexthdr) {
        return 1;
    }
    unsafe {
        (*out).l4proto = nexthdr;
    }
    unsafe { parse_l4(skb, offset, out) }
}

#[inline(always)]
unsafe fn parse_l4(skb: *mut __sk_buff, transport_offset: u32, out: *mut ParsedPacket) -> i32 {
    let proto = unsafe { (*out).l4proto };
    if proto == IPPROTO_TCP {
        let mut tcp = [0u8; 20];
        if !unsafe {
            load_bytes(
                skb,
                transport_offset,
                tcp.as_mut_ptr().cast::<c_void>(),
                tcp.len() as u32,
            )
        } {
            return -1;
        }
        unsafe {
            (*out).sport = read_ne_u16(&tcp, 0);
            (*out).dport = read_ne_u16(&tcp, 2);
            (*out).tcp_flags = tcp[13];
        }
    } else if proto == IPPROTO_UDP {
        let mut udp = [0u8; 8];
        if !unsafe {
            load_bytes(
                skb,
                transport_offset,
                udp.as_mut_ptr().cast::<c_void>(),
                udp.len() as u32,
            )
        } {
            return -1;
        }
        unsafe {
            (*out).sport = read_ne_u16(&udp, 0);
            (*out).dport = read_ne_u16(&udp, 2);
        }
    } else if proto == IPPROTO_ICMPV6 {
        let mut icmp = [0u8; 8];
        if !unsafe {
            load_bytes(
                skb,
                transport_offset,
                icmp.as_mut_ptr().cast::<c_void>(),
                icmp.len() as u32,
            )
        } {
            return -1;
        }
        unsafe {
            (*out).icmp6_type = icmp[0];
        }
    } else {
        return 1;
    }
    0
}

#[inline(always)]
pub fn tcp_syn(flags: u8) -> bool {
    (flags & 0x02) != 0
}

#[inline(always)]
pub fn tcp_ack(flags: u8) -> bool {
    (flags & 0x10) != 0
}

#[inline(always)]
pub unsafe fn build_tuples(info: *const ParsedPacket, key: *mut BpfTuplesKey) {
    unsafe {
        ptr::write(key, BpfTuplesKey::zeroed());
        copy_ip(ptr::addr_of_mut!((*key).sip), ptr::addr_of!((*info).sip));
        copy_ip(ptr::addr_of_mut!((*key).dip), ptr::addr_of!((*info).dip));
        (*key).sport = (*info).sport;
        (*key).dport = (*info).dport;
        (*key).l4proto = (*info).l4proto;
    }
}

#[inline(always)]
pub unsafe fn reverse_tuples(src: *const BpfTuplesKey, dst: *mut BpfTuplesKey) {
    unsafe {
        ptr::write(dst, BpfTuplesKey::zeroed());
        copy_ip(ptr::addr_of_mut!((*dst).sip), ptr::addr_of!((*src).dip));
        copy_ip(ptr::addr_of_mut!((*dst).dip), ptr::addr_of!((*src).sip));
        (*dst).sport = (*src).dport;
        (*dst).dport = (*src).sport;
        (*dst).l4proto = (*src).l4proto;
    }
}

#[inline(always)]
pub unsafe fn build_sock_tuple(info: *const ParsedPacket, tuple: *mut BpfSockTuple) -> u32 {
    unsafe {
        if (*info).is_ipv4 != 0 {
            ptr::addr_of_mut!((*tuple).ipv4).write(BpfSockTupleIpv4 {
                saddr: read_ne_u32(&(*info).sip.u6_addr8, 12),
                daddr: read_ne_u32(&(*info).dip.u6_addr8, 12),
                sport: (*info).sport,
                dport: (*info).dport,
            });
            mem::size_of::<BpfSockTupleIpv4>() as u32
        } else {
            copy16(
                ptr::addr_of_mut!((*tuple).ipv6.saddr).cast::<u8>(),
                ptr::addr_of!((*info).sip.u6_addr8).cast::<u8>(),
            );
            copy16(
                ptr::addr_of_mut!((*tuple).ipv6.daddr).cast::<u8>(),
                ptr::addr_of!((*info).dip.u6_addr8).cast::<u8>(),
            );
            (*tuple).ipv6.sport = (*info).sport;
            (*tuple).ipv6.dport = (*info).dport;
            mem::size_of::<BpfSockTupleIpv6>() as u32
        }
    }
}

#[inline(always)]
pub unsafe fn redirect_tuple_from_forward_packet(
    info: *const ParsedPacket,
    tuple: *mut BpfRedirectTuple,
) {
    unsafe {
        ptr::write(
            tuple,
            BpfRedirectTuple {
                sip: BpfIpBytes::zeroed(),
                dip: BpfIpBytes::zeroed(),
            },
        );
        if (*info).is_ipv4 != 0 {
            copy4(
                ptr::addr_of_mut!((*tuple).sip.u6_addr8[12]),
                ptr::addr_of!((*info).sip.u6_addr8[12]),
            );
            copy4(
                ptr::addr_of_mut!((*tuple).dip.u6_addr8[12]),
                ptr::addr_of!((*info).dip.u6_addr8[12]),
            );
        } else {
            copy_ip(ptr::addr_of_mut!((*tuple).sip), ptr::addr_of!((*info).sip));
            copy_ip(ptr::addr_of_mut!((*tuple).dip), ptr::addr_of!((*info).dip));
        }
    }
}

#[inline(always)]
pub unsafe fn redirect_tuple_from_return_packet(
    skb: *mut __sk_buff,
    tuple: *mut BpfRedirectTuple,
) -> bool {
    unsafe {
        ptr::write(
            tuple,
            BpfRedirectTuple {
                sip: BpfIpBytes::zeroed(),
                dip: BpfIpBytes::zeroed(),
            },
        );
    }
    let network_offset = ETH_HLEN;
    let proto = unsafe { (*skb).protocol };
    if proto == ETH_P_IP_NETWORK {
        unsafe {
            load_bytes(
                skb,
                network_offset + IPV4_DADDR_OFFSET as u32,
                ptr::addr_of_mut!((*tuple).sip.u6_addr8[12]).cast::<c_void>(),
                4,
            ) && load_bytes(
                skb,
                network_offset + IPV4_SADDR_OFFSET as u32,
                ptr::addr_of_mut!((*tuple).dip.u6_addr8[12]).cast::<c_void>(),
                4,
            )
        }
    } else if proto == ETH_P_IPV6_NETWORK {
        unsafe {
            load_bytes(
                skb,
                network_offset + IPV6_DADDR_OFFSET as u32,
                ptr::addr_of_mut!((*tuple).sip.u6_addr8).cast::<c_void>(),
                16,
            ) && load_bytes(
                skb,
                network_offset + IPV6_SADDR_OFFSET as u32,
                ptr::addr_of_mut!((*tuple).dip.u6_addr8).cast::<c_void>(),
                16,
            )
        }
    } else {
        false
    }
}
