use core::{ffi::c_void, ptr};

use aya_ebpf::bindings::{__sk_buff, bpf_sock};

use crate::abi::{BpfRedirectEntry, BpfRedirectTuple, BpfTuplesKey, BpfUdpConnState, TPROXY_MARK};
use crate::packet::{
    self, BpfSockTuple, ETH_HLEN, ETH_PROTO_OFFSET, ETH_SRC_OFFSET, IPPROTO_ICMPV6, IPPROTO_TCP,
    IPPROTO_UDP, NDP_REDIRECT, ParsedPacket,
};
use crate::{helpers, maps, routing, udp_state};

const TCX_NEXT: i32 = -1;
const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;
const BPF_ANY: u64 = 0;
const BPF_F_INGRESS: u64 = 1;
const BPF_ADJ_ROOM_MAC: u32 = 1;
const PACKET_HOST: u32 = 0;
const PACKET_OTHERHOST: u32 = 3;
const BPF_TCP_LISTEN: u32 = 10;
const NOWHERE_IFINDEX: u32 = 0;
const LISTEN_SOCKET_KEY_TCP4: u32 = 0;
const LISTEN_SOCKET_KEY_TCP6: u32 = 1;
const LISTEN_SOCKET_KEY_UDP4: u32 = 2;
const LISTEN_SOCKET_KEY_UDP6: u32 = 3;
const SKB_CB_TPROXY_MARK: usize = 0;
const SKB_CB_TPROXY_L4PROTO: usize = 1;
const SKB_CB_TPROXY_IS_IPV4: usize = 2;
const REDIRECT_LINK_LAYER_L2: u8 = 2;
const REDIRECT_LINK_LAYER_L3: u8 = 3;

#[inline(always)]
fn redirect_link_layer_for_header_len(link_h_len: u32) -> u8 {
    if link_h_len == 0 {
        REDIRECT_LINK_LAYER_L3
    } else {
        REDIRECT_LINK_LAYER_L2
    }
}

#[inline(always)]
fn redirect_entry_requires_l3_strip(entry: *const BpfRedirectEntry) -> bool {
    unsafe { (*entry).link_layer == REDIRECT_LINK_LAYER_L3 }
}

#[inline(always)]
fn redirect_entry_l3_strip_delta() -> i32 {
    -(ETH_HLEN as i32)
}

#[inline(always)]
fn redirect_entry_l3_strip_mode() -> u32 {
    BPF_ADJ_ROOM_MAC
}

pub fn chain_next() -> i32 {
    TCX_NEXT
}

#[inline(always)]
fn is_new_tcp(info: *const ParsedPacket) -> bool {
    unsafe {
        (*info).l4proto == IPPROTO_TCP
            && packet::tcp_syn((*info).tcp_flags)
            && !packet::tcp_ack((*info).tcp_flags)
    }
}

#[inline(always)]
fn is_dns_udp(info: *const ParsedPacket) -> bool {
    unsafe { (*info).l4proto == IPPROTO_UDP && (*info).dport == u16::to_be(53) }
}

#[inline(always)]
unsafe fn assign_listener(skb: *mut __sk_buff, l4proto: u32, is_ipv4: u32) {
    let key = if l4proto == IPPROTO_TCP as u32 {
        if is_ipv4 != 0 {
            LISTEN_SOCKET_KEY_TCP4
        } else {
            LISTEN_SOCKET_KEY_TCP6
        }
    } else if l4proto == IPPROTO_UDP as u32 {
        if is_ipv4 != 0 {
            LISTEN_SOCKET_KEY_UDP4
        } else {
            LISTEN_SOCKET_KEY_UDP6
        }
    } else {
        return;
    };
    let sock = unsafe {
        helpers::bpf_map_lookup_elem(
            maps::listen_socket_map_ptr(),
            ptr::addr_of!(key).cast::<c_void>(),
        )
    };
    if sock.is_null() {
        return;
    }
    unsafe {
        let _ = helpers::bpf_sk_assign(skb.cast::<c_void>(), sock, 0);
        let _ = helpers::bpf_sk_release(sock);
    }
}

#[inline(always)]
unsafe fn current_dae_netns_tcp_state(
    skb: *mut __sk_buff,
    info: *const ParsedPacket,
    tuple: *mut BpfSockTuple,
) -> Option<u32> {
    let tuple_size = unsafe { packet::build_sock_tuple(info, tuple) };
    let sk = unsafe {
        helpers::bpf_skc_lookup_tcp(
            skb.cast::<c_void>(),
            tuple.cast::<c_void>(),
            tuple_size,
            crate::abi::param_dae_netns_id() as u64,
            0,
        )
    };
    if sk.is_null() {
        return None;
    }
    let state = unsafe { (*sk.cast::<bpf_sock>()).state };
    unsafe {
        helpers::bpf_sk_release(sk);
    }
    Some(state)
}

#[inline(always)]
unsafe fn prep_redirect_to_control_plane(
    skb: *mut __sk_buff,
    link_h_len: u32,
    info: *const ParsedPacket,
    key: *const BpfTuplesKey,
    from_wan: bool,
    redirect_tuple: *mut BpfRedirectTuple,
    redirect_entry: *mut BpfRedirectEntry,
) -> bool {
    let skb_void = skb.cast::<c_void>();
    if link_h_len == 0 {
        let l3proto = unsafe { (*info).h_proto as u16 };
        if unsafe { helpers::bpf_skb_change_head(skb_void, ETH_HLEN, 0) } != 0 {
            return false;
        }
        let _ = unsafe {
            helpers::bpf_skb_store_bytes(
                skb_void,
                ETH_PROTO_OFFSET,
                ptr::addr_of!(l3proto).cast::<c_void>(),
                2,
                0,
            )
        };
    }

    let dae0peer_mac = crate::abi::param_dae0peer_mac();
    let _ = unsafe {
        helpers::bpf_skb_store_bytes(
            skb_void,
            packet::ETH_DST_OFFSET,
            dae0peer_mac.as_ptr().cast::<c_void>(),
            6,
            0,
        )
    };

    unsafe {
        packet::redirect_tuple_from_forward_packet(info, redirect_tuple);
        ptr::addr_of_mut!((*redirect_entry).ifindex).write((*skb).ifindex);
        packet::copy_mac(
            (*redirect_entry).smac.as_mut_ptr(),
            (*info).eth_src.as_ptr(),
        );
        packet::copy_mac(
            (*redirect_entry).dmac.as_mut_ptr(),
            (*info).eth_dst.as_ptr(),
        );
        ptr::addr_of_mut!((*redirect_entry).from_wan).write(from_wan as u8);
        ptr::addr_of_mut!((*redirect_entry).link_layer)
            .write(redirect_link_layer_for_header_len(link_h_len));
        ptr::addr_of_mut!((*redirect_entry).padding).write([0; 2]);
        if helpers::bpf_map_update_elem(
            maps::redirect_track_map_ptr(),
            redirect_tuple.cast::<c_void>(),
            redirect_entry.cast::<c_void>(),
            BPF_ANY,
        ) != 0
        {
            return false;
        }
        (*skb).cb[SKB_CB_TPROXY_MARK] = TPROXY_MARK;
        let assign_l4proto = if ((*info).l4proto == IPPROTO_TCP
            && packet::tcp_syn((*info).tcp_flags))
            || (*info).l4proto == IPPROTO_UDP
        {
            (*info).l4proto as u32
        } else {
            0
        };
        (*skb).cb[SKB_CB_TPROXY_L4PROTO] = assign_l4proto;
        (*skb).cb[SKB_CB_TPROXY_IS_IPV4] = if assign_l4proto != 0 {
            (*info).is_ipv4 as u32
        } else {
            0
        };
    }
    let _ = key;
    true
}

#[inline(always)]
unsafe fn redirect_to_control_plane(
    skb: *mut __sk_buff,
    link_h_len: u32,
    info: *const ParsedPacket,
    key: *const BpfTuplesKey,
    from_wan: bool,
    redirect_tuple: *mut BpfRedirectTuple,
    redirect_entry: *mut BpfRedirectEntry,
) -> i32 {
    if !unsafe {
        prep_redirect_to_control_plane(
            skb,
            link_h_len,
            info,
            key,
            from_wan,
            redirect_tuple,
            redirect_entry,
        )
    } {
        return TC_ACT_SHOT;
    }
    unsafe { helpers::bpf_redirect(crate::abi::param_dae0_ifindex(), 0) as i32 }
}

#[inline(always)]
pub fn dae0peer_ingress(skb: *mut __sk_buff) -> i32 {
    if unsafe { (*skb).cb[SKB_CB_TPROXY_MARK] } != TPROXY_MARK {
        return TC_ACT_SHOT;
    }

    unsafe {
        (*skb).mark = TPROXY_MARK;
        let _ = helpers::bpf_skb_change_type(skb.cast::<c_void>(), PACKET_HOST);
        let mut info = ParsedPacket::zeroed();
        if packet::parse_transport(skb, ETH_HLEN, ptr::addr_of_mut!(info)) == 0 {
            let info_ptr = ptr::addr_of!(info);
            if is_new_tcp(info_ptr) || (*info_ptr).l4proto == IPPROTO_UDP {
                assign_listener(skb, (*info_ptr).l4proto as u32, (*info_ptr).is_ipv4 as u32);
            }
        } else {
            let l4proto = (*skb).cb[SKB_CB_TPROXY_L4PROTO];
            if l4proto != 0 {
                assign_listener(skb, l4proto, (*skb).cb[SKB_CB_TPROXY_IS_IPV4]);
            }
        }
    }
    TC_ACT_OK
}

#[inline(always)]
pub fn dae0_ingress(skb: *mut __sk_buff) -> i32 {
    let mut tuple = BpfRedirectTuple {
        sip: crate::abi::BpfIpBytes::zeroed(),
        dip: crate::abi::BpfIpBytes::zeroed(),
    };
    if !unsafe { packet::redirect_tuple_from_return_packet(skb, ptr::addr_of_mut!(tuple)) } {
        return TC_ACT_OK;
    }

    let entry = unsafe {
        helpers::bpf_map_lookup_elem(
            maps::redirect_track_map_ptr(),
            ptr::addr_of!(tuple).cast::<c_void>(),
        )
    }
    .cast::<BpfRedirectEntry>();
    if entry.is_null() {
        return TC_ACT_OK;
    }

    unsafe {
        if redirect_entry_requires_l3_strip(entry) {
            if helpers::bpf_skb_adjust_room(
                skb.cast::<c_void>(),
                redirect_entry_l3_strip_delta(),
                redirect_entry_l3_strip_mode(),
                0,
            ) != 0
            {
                return TC_ACT_SHOT;
            }
        } else {
            let _ = helpers::bpf_skb_store_bytes(
                skb.cast::<c_void>(),
                ETH_SRC_OFFSET,
                ptr::addr_of!((*entry).dmac).cast::<c_void>(),
                6,
                0,
            );
            let _ = helpers::bpf_skb_store_bytes(
                skb.cast::<c_void>(),
                packet::ETH_DST_OFFSET,
                ptr::addr_of!((*entry).smac).cast::<c_void>(),
                6,
                0,
            );
        }
        let packet_type = if (*entry).from_wan != 0 {
            PACKET_HOST
        } else {
            PACKET_OTHERHOST
        };
        let _ = helpers::bpf_skb_change_type(skb.cast::<c_void>(), packet_type);
        let flags = if (*entry).from_wan != 0 {
            BPF_F_INGRESS
        } else {
            0
        };
        helpers::bpf_redirect((*entry).ifindex, flags) as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redirect_entry(link_layer: u8) -> BpfRedirectEntry {
        BpfRedirectEntry {
            ifindex: 0,
            smac: [0; 6],
            dmac: [0; 6],
            from_wan: 0,
            link_layer,
            padding: [0; 2],
        }
    }

    #[test]
    fn redirect_entry_records_original_link_layer_without_changing_layout() {
        assert_eq!(
            redirect_link_layer_for_header_len(ETH_HLEN),
            REDIRECT_LINK_LAYER_L2
        );
        assert_eq!(
            redirect_link_layer_for_header_len(0),
            REDIRECT_LINK_LAYER_L3
        );
    }

    #[test]
    fn l3_wan_egress_return_path_records_and_strips_temporary_mac_header() {
        let l2 = redirect_entry(REDIRECT_LINK_LAYER_L2);
        let l3 = redirect_entry(REDIRECT_LINK_LAYER_L3);

        assert_eq!(
            redirect_link_layer_for_header_len(ETH_HLEN),
            REDIRECT_LINK_LAYER_L2
        );
        assert_eq!(
            redirect_link_layer_for_header_len(0),
            REDIRECT_LINK_LAYER_L3
        );
        assert!(!redirect_entry_requires_l3_strip(&l2));
        assert!(redirect_entry_requires_l3_strip(&l3));
        assert_eq!(redirect_entry_l3_strip_delta(), -(ETH_HLEN as i32));
        assert_eq!(redirect_entry_l3_strip_mode(), BPF_ADJ_ROOM_MAC);
    }
}

#[inline(always)]
pub fn lan_egress(skb: *mut __sk_buff, link_h_len: u32) -> i32 {
    let mut info = ParsedPacket::zeroed();
    let ret = unsafe { packet::parse_transport(skb, link_h_len, ptr::addr_of_mut!(info)) };
    if ret != 0 {
        return chain_next();
    }
    if unsafe { (*skb).ingress_ifindex } == NOWHERE_IFINDEX
        && info.l4proto == IPPROTO_ICMPV6
        && info.icmp6_type == NDP_REDIRECT
    {
        return TC_ACT_SHOT;
    }
    if info.l4proto == IPPROTO_UDP
        && !udp_state::refresh_reversed_udp_state(ptr::addr_of!(info), true)
    {
        return TC_ACT_SHOT;
    }
    chain_next()
}

#[inline(always)]
pub fn wan_ingress(skb: *mut __sk_buff, link_h_len: u32) -> i32 {
    let mut info = ParsedPacket::zeroed();
    let ret = unsafe { packet::parse_transport(skb, link_h_len, ptr::addr_of_mut!(info)) };
    if ret != 0 {
        return TC_ACT_OK;
    }
    if info.l4proto == IPPROTO_UDP
        && !udp_state::refresh_reversed_udp_state(ptr::addr_of!(info), true)
    {
        return TC_ACT_SHOT;
    }
    chain_next()
}

#[inline(always)]
pub fn lan_ingress(skb: *mut __sk_buff, link_h_len: u32) -> i32 {
    let mut info = ParsedPacket::zeroed();
    let ret = unsafe { packet::parse_transport(skb, link_h_len, ptr::addr_of_mut!(info)) };
    if ret != 0 {
        return chain_next();
    }
    if info.l4proto == IPPROTO_ICMPV6 {
        return TC_ACT_OK;
    }

    let mut key = BpfTuplesKey::zeroed();
    unsafe {
        packet::build_tuples(ptr::addr_of!(info), ptr::addr_of_mut!(key));
    }

    let mut sock_tuple = core::mem::MaybeUninit::<BpfSockTuple>::uninit();
    if info.l4proto == IPPROTO_TCP && !is_new_tcp(ptr::addr_of!(info)) {
        if let Some(state) = unsafe {
            current_dae_netns_tcp_state(skb, ptr::addr_of!(info), sock_tuple.as_mut_ptr())
        } && state != BPF_TCP_LISTEN
        {
            let mut redirect_tuple = BpfRedirectTuple {
                sip: crate::abi::BpfIpBytes::zeroed(),
                dip: crate::abi::BpfIpBytes::zeroed(),
            };
            let mut redirect_entry = BpfRedirectEntry {
                ifindex: 0,
                smac: [0; 6],
                dmac: [0; 6],
                from_wan: 0,
                link_layer: 0,
                padding: [0; 2],
            };
            return unsafe {
                redirect_to_control_plane(
                    skb,
                    link_h_len,
                    ptr::addr_of!(info),
                    ptr::addr_of!(key),
                    false,
                    ptr::addr_of_mut!(redirect_tuple),
                    ptr::addr_of_mut!(redirect_entry),
                )
            };
        }
        let routing_result = routing::lookup_routing_result(ptr::addr_of!(key));
        if !routing_result.is_null() {
            unsafe {
                (*skb).mark = (*routing_result).mark;
            }
        }
        return TC_ACT_OK;
    }

    let mut new_udp_state = BpfUdpConnState::new(false);
    if info.l4proto == IPPROTO_UDP {
        let state = unsafe {
            udp_state::refresh_udp_conn_state(
                ptr::addr_of_mut!(key),
                false,
                ptr::addr_of_mut!(new_udp_state),
            )
        };
        if state.is_null() {
            return TC_ACT_SHOT;
        }
        if unsafe { (*state).is_wan_ingress_direction } != 0 {
            return TC_ACT_OK;
        }
    }

    let mut params = routing::RouteParams::zeroed();
    routing::route_params_from_packet(
        ptr::addr_of_mut!(params),
        ptr::addr_of!(info),
        false,
        ptr::null(),
    );
    let route_result = routing::route(ptr::addr_of!(params));
    if route_result < 0 {
        return TC_ACT_SHOT;
    }
    let outbound = (route_result & 0xff) as u8;
    let mark = (route_result >> 8) as u32;
    let must = ((route_result >> 40) & 1) != 0;
    if !routing::save_routing_result(
        ptr::addr_of!(key),
        ptr::addr_of!(info),
        outbound,
        mark,
        must,
        ptr::null(),
    ) {
        return TC_ACT_SHOT;
    }

    if outbound == routing::ROUTE_OUTBOUND_DIRECT {
        unsafe {
            (*skb).mark = mark;
        }
        return TC_ACT_OK;
    }
    if outbound == routing::ROUTE_OUTBOUND_BLOCK {
        return TC_ACT_SHOT;
    }
    if !routing::outbound_alive(ptr::addr_of!(info), outbound) && !is_dns_udp(ptr::addr_of!(info)) {
        return TC_ACT_SHOT;
    }

    let mut redirect_tuple = BpfRedirectTuple {
        sip: crate::abi::BpfIpBytes::zeroed(),
        dip: crate::abi::BpfIpBytes::zeroed(),
    };
    let mut redirect_entry = BpfRedirectEntry {
        ifindex: 0,
        smac: [0; 6],
        dmac: [0; 6],
        from_wan: 0,
        link_layer: 0,
        padding: [0; 2],
    };
    unsafe {
        redirect_to_control_plane(
            skb,
            link_h_len,
            ptr::addr_of!(info),
            ptr::addr_of!(key),
            false,
            ptr::addr_of_mut!(redirect_tuple),
            ptr::addr_of_mut!(redirect_entry),
        )
    }
}

#[inline(always)]
pub fn wan_egress(skb: *mut __sk_buff, link_h_len: u32) -> i32 {
    if unsafe { (*skb).ingress_ifindex } != NOWHERE_IFINDEX {
        return TC_ACT_OK;
    }
    let mut info = ParsedPacket::zeroed();
    let ret = unsafe { packet::parse_transport(skb, link_h_len, ptr::addr_of_mut!(info)) };
    if ret != 0 {
        return TC_ACT_OK;
    }
    if info.l4proto == IPPROTO_ICMPV6 {
        return TC_ACT_OK;
    }

    let mut key = BpfTuplesKey::zeroed();
    unsafe {
        packet::build_tuples(ptr::addr_of!(info), ptr::addr_of_mut!(key));
    }

    let pid_pname = routing::pid_pname_for_packet(skb);
    if routing::pid_is_control_plane(skb, pid_pname) {
        return TC_ACT_OK;
    }

    let outbound: u8;
    let mark: u32;
    if info.l4proto == IPPROTO_TCP && !is_new_tcp(ptr::addr_of!(info)) {
        let routing_result = routing::lookup_routing_result(ptr::addr_of!(key));
        if routing_result.is_null() {
            return TC_ACT_OK;
        }
        unsafe {
            outbound = (*routing_result).outbound;
            mark = (*routing_result).mark;
        }
    } else {
        let mut new_udp_state = BpfUdpConnState::new(false);
        if info.l4proto == IPPROTO_UDP {
            let state = unsafe {
                udp_state::refresh_udp_conn_state(
                    ptr::addr_of_mut!(key),
                    false,
                    ptr::addr_of_mut!(new_udp_state),
                )
            };
            if state.is_null() {
                return TC_ACT_SHOT;
            }
            if unsafe { (*state).is_wan_ingress_direction } != 0 {
                return TC_ACT_OK;
            }
        }

        let mut params = routing::RouteParams::zeroed();
        routing::route_params_from_packet(
            ptr::addr_of_mut!(params),
            ptr::addr_of!(info),
            true,
            pid_pname,
        );
        let route_result = routing::route(ptr::addr_of!(params));
        if route_result < 0 {
            return TC_ACT_SHOT;
        }
        outbound = (route_result & 0xff) as u8;
        mark = (route_result >> 8) as u32;
        let must = ((route_result >> 40) & 1) != 0;
        if (outbound != routing::ROUTE_OUTBOUND_DIRECT || mark != 0 || must)
            && !routing::save_routing_result(
                ptr::addr_of!(key),
                ptr::addr_of!(info),
                outbound,
                mark,
                must,
                pid_pname,
            )
        {
            return TC_ACT_SHOT;
        }
    }

    if outbound == routing::ROUTE_OUTBOUND_DIRECT && mark == 0 {
        unsafe {
            (*skb).mark = mark;
        }
        return TC_ACT_OK;
    }
    if outbound == routing::ROUTE_OUTBOUND_BLOCK {
        return TC_ACT_SHOT;
    }
    if !routing::outbound_alive(ptr::addr_of!(info), outbound) && !is_dns_udp(ptr::addr_of!(info)) {
        return TC_ACT_SHOT;
    }

    let mut redirect_tuple = BpfRedirectTuple {
        sip: crate::abi::BpfIpBytes::zeroed(),
        dip: crate::abi::BpfIpBytes::zeroed(),
    };
    let mut redirect_entry = BpfRedirectEntry {
        ifindex: 0,
        smac: [0; 6],
        dmac: [0; 6],
        from_wan: 0,
        link_layer: 0,
        padding: [0; 2],
    };
    unsafe {
        redirect_to_control_plane(
            skb,
            link_h_len,
            ptr::addr_of!(info),
            ptr::addr_of!(key),
            true,
            ptr::addr_of_mut!(redirect_tuple),
            ptr::addr_of_mut!(redirect_entry),
        )
    }
}
