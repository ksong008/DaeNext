use core::{ffi::c_void, ptr};

use aya_ebpf::bindings::{__sk_buff, bpf_sock};

use crate::abi::{
    BpfRedirectEntry, BpfRedirectKey, BpfTproxyMetrics, BpfTuplesKey, BpfUdpConnState,
    REDIRECT_TRACK_ABI_VERSION, TPROXY_MARK,
};
use crate::packet::{
    self, BpfSockTuple, ETH_HLEN, ETH_PROTO_OFFSET, ETH_SRC_OFFSET, IPPROTO_ICMPV6, IPPROTO_TCP,
    IPPROTO_UDP, NDP_REDIRECT, ParsedPacket,
};
use crate::{helpers, maps, redirect_key, redirect_vlan, routing, udp_state};

const TC_ACT_UNSPEC: i32 = -1;
const TCX_NEXT: i32 = TC_ACT_UNSPEC;
const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;
const BPF_ANY: u64 = 0;
const BPF_F_INGRESS: u64 = 1;
const PACKET_HOST: u32 = 0;
const PACKET_OTHERHOST: u32 = 3;
const BPF_TCP_LISTEN: u32 = 10;
const NOWHERE_IFINDEX: u32 = 0;
const LISTEN_SOCKET_KEY_TCP4: u32 = 0;
const LISTEN_SOCKET_KEY_TCP6: u32 = 1;
const LISTEN_SOCKET_KEY_UDP4: u32 = 2;
const LISTEN_SOCKET_KEY_UDP6: u32 = 3;
const REDIRECT_LINK_LAYER_L2: u8 = 2;
const REDIRECT_LINK_LAYER_L3: u8 = 3;
const TPROXY_METRICS_KEY: u32 = 0;
const METRIC_SK_ASSIGN_FAILURE: u32 = 0;
const METRIC_REDIRECT_PREP_STORE_FAILURE: u32 = 1;
const METRIC_REDIRECT_RESTORE_STORE_FAILURE: u32 = 2;

// tproxy failure counters live in the per-CPU `tproxy_metrics` map.  They make
// helper failures observable (sk_assign / skb_store_bytes). Store failures
// are counted and dropped fail-closed; sk_assign retains its prior packet
// disposition and is counted. Userspace reads the map through the same
// PerCpuArray-by-id machinery as udp_state_metrics.
#[inline(never)]
fn increment_tproxy_metric(metric: u32) {
    let key = TPROXY_METRICS_KEY;
    let metrics = unsafe {
        helpers::bpf_map_lookup_elem(
            maps::tproxy_metrics_map_ptr(),
            ptr::addr_of!(key).cast::<c_void>(),
        )
    }
    .cast::<BpfTproxyMetrics>();
    if metrics.is_null() {
        return;
    }
    let counter = unsafe {
        match metric {
            METRIC_SK_ASSIGN_FAILURE => ptr::addr_of_mut!((*metrics).sk_assign_failure_total),
            METRIC_REDIRECT_PREP_STORE_FAILURE => {
                ptr::addr_of_mut!((*metrics).redirect_prep_store_failure_total)
            }
            METRIC_REDIRECT_RESTORE_STORE_FAILURE => {
                ptr::addr_of_mut!((*metrics).redirect_restore_store_failure_total)
            }
            _ => return,
        }
    };
    unsafe {
        counter.write_volatile(counter.read_volatile().wrapping_add(1));
    }
}

#[inline(always)]
fn redirect_link_layer_for_header_len(link_h_len: u32) -> u8 {
    if link_h_len == 0 {
        REDIRECT_LINK_LAYER_L3
    } else {
        REDIRECT_LINK_LAYER_L2
    }
}

#[inline(always)]
fn redirect_entry_requires_l2_restore(entry: *const BpfRedirectEntry) -> bool {
    unsafe { (*entry).link_layer == REDIRECT_LINK_LAYER_L2 }
}

#[inline(always)]
fn redirect_entry_uses_l3_no_mac_redirect(entry: *const BpfRedirectEntry) -> bool {
    unsafe { (*entry).link_layer == REDIRECT_LINK_LAYER_L3 }
}

pub fn chain_next() -> i32 {
    // TC clsact and TCX both use -1 as the explicit "continue" action
    // (TC_ACT_UNSPEC / TCX_NEXT). Keep pass-through physical-interface paths
    // on this action so co-hosted TC/TCX programs, such as NAT helpers, still
    // see the packet.
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
fn protected_wan_destination(l4proto: u8, dport: u16, protect: bool, tproxy_port: u16) -> bool {
    protect && (l4proto == IPPROTO_TCP || l4proto == IPPROTO_UDP) && dport == tproxy_port
}

#[inline(always)]
fn udp_state_unavailable_action() -> i32 {
    udp_state_unavailable_action_for_policy(crate::abi::param_udp_state_saturation_policy())
}

#[inline(always)]
fn physical_wan_control_plane_passthrough_action() -> i32 {
    chain_next()
}

#[inline(always)]
const fn udp_state_unavailable_action_for_policy(policy: u32) -> i32 {
    match policy {
        crate::abi::UDP_STATE_SATURATION_POLICY_FAIL_CLOSED => TC_ACT_SHOT,
        _ => TC_ACT_SHOT,
    }
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
        // A failed bpf_sk_assign leaves the packet with the tproxy mark but
        // without a listener socket: the connection is not redirected into
        // the dae listener (a redirect hole).  Count the failure instead of
        // discarding it; bpf_sk_release must still run either way.
        if helpers::bpf_sk_assign(skb.cast::<c_void>(), sock, 0) != 0 {
            increment_tproxy_metric(METRIC_SK_ASSIGN_FAILURE);
        }
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
    redirect_track_key: *mut BpfRedirectKey,
    redirect_entry: *mut BpfRedirectEntry,
) -> bool {
    let skb_void = skb.cast::<c_void>();
    if link_h_len == 0 {
        let l3proto = unsafe { (*info).h_proto as u16 };
        if unsafe { helpers::bpf_skb_change_head(skb_void, ETH_HLEN, 0) } != 0 {
            return false;
        }
        if unsafe {
            helpers::bpf_skb_store_bytes(
                skb_void,
                ETH_PROTO_OFFSET,
                ptr::addr_of!(l3proto).cast::<c_void>(),
                2,
                0,
            )
        } != 0
        {
            increment_tproxy_metric(METRIC_REDIRECT_PREP_STORE_FAILURE);
            return false;
        }
    }
    if !unsafe { redirect_vlan::strip(skb, info) } {
        return false;
    }

    let dae0peer_mac = crate::abi::param_dae0peer_mac();
    if unsafe {
        helpers::bpf_skb_store_bytes(
            skb_void,
            packet::ETH_DST_OFFSET,
            dae0peer_mac.as_ptr().cast::<c_void>(),
            6,
            0,
        )
    } != 0
    {
        increment_tproxy_metric(METRIC_REDIRECT_PREP_STORE_FAILURE);
        return false;
    }

    unsafe {
        redirect_key::from_forward_tuple(key, redirect_track_key);
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
        ptr::addr_of_mut!((*redirect_entry).abi_version).write(REDIRECT_TRACK_ABI_VERSION);
        if !redirect_vlan::capture(info, redirect_entry) {
            return false;
        }
        if helpers::bpf_map_update_elem(
            maps::redirect_track_map_ptr(),
            redirect_track_key.cast::<c_void>(),
            redirect_entry.cast::<c_void>(),
            BPF_ANY,
        ) != 0
        {
            return false;
        }
    }
    true
}

#[inline(always)]
unsafe fn redirect_to_control_plane(
    skb: *mut __sk_buff,
    link_h_len: u32,
    info: *const ParsedPacket,
    key: *const BpfTuplesKey,
    from_wan: bool,
    redirect_track_key: *mut BpfRedirectKey,
    redirect_entry: *mut BpfRedirectEntry,
) -> i32 {
    if !unsafe {
        prep_redirect_to_control_plane(
            skb,
            link_h_len,
            info,
            key,
            from_wan,
            redirect_track_key,
            redirect_entry,
        )
    } {
        return TC_ACT_SHOT;
    }
    unsafe { helpers::bpf_redirect(crate::abi::param_dae0_ifindex(), 0) as i32 }
}

#[inline(always)]
pub fn dae0peer_ingress(skb: *mut __sk_buff) -> i32 {
    let mut info = ParsedPacket::zeroed();
    if unsafe { packet::parse_transport(skb, ETH_HLEN, ptr::addr_of_mut!(info)) } != 0 {
        return TC_ACT_SHOT;
    }
    let mut tuple = BpfTuplesKey::zeroed();
    let mut redirect_track_key = BpfRedirectKey::zeroed();
    unsafe {
        packet::build_tuples(ptr::addr_of!(info), ptr::addr_of_mut!(tuple));
        redirect_key::from_forward_tuple(
            ptr::addr_of!(tuple),
            ptr::addr_of_mut!(redirect_track_key),
        );
    }
    let entry = unsafe {
        helpers::bpf_map_lookup_elem(
            maps::redirect_track_map_ptr(),
            ptr::addr_of!(redirect_track_key).cast::<c_void>(),
        )
    }
    .cast::<BpfRedirectEntry>();
    if entry.is_null() || unsafe { (*entry).abi_version } != REDIRECT_TRACK_ABI_VERSION {
        return TC_ACT_SHOT;
    }

    unsafe {
        (*skb).mark = TPROXY_MARK;
        let _ = helpers::bpf_skb_change_type(skb.cast::<c_void>(), PACKET_HOST);
        let info_ptr = ptr::addr_of!(info);
        if is_new_tcp(info_ptr) || (*info_ptr).l4proto == IPPROTO_UDP {
            assign_listener(skb, (*info_ptr).l4proto as u32, (*info_ptr).is_ipv4 as u32);
        }
    }
    TC_ACT_OK
}

#[inline(always)]
pub fn dae0_ingress(skb: *mut __sk_buff) -> i32 {
    let mut info = ParsedPacket::zeroed();
    if unsafe { packet::parse_transport(skb, ETH_HLEN, ptr::addr_of_mut!(info)) } != 0 {
        return TC_ACT_OK;
    }
    let mut tuple = BpfTuplesKey::zeroed();
    let mut redirect_track_key = BpfRedirectKey::zeroed();
    unsafe {
        packet::build_tuples(ptr::addr_of!(info), ptr::addr_of_mut!(tuple));
        redirect_key::from_return_tuple(
            ptr::addr_of!(tuple),
            ptr::addr_of_mut!(redirect_track_key),
        );
    }

    let entry = unsafe {
        helpers::bpf_map_lookup_elem(
            maps::redirect_track_map_ptr(),
            ptr::addr_of!(redirect_track_key).cast::<c_void>(),
        )
    }
    .cast::<BpfRedirectEntry>();
    if entry.is_null() || unsafe { (*entry).abi_version } != REDIRECT_TRACK_ABI_VERSION {
        return TC_ACT_OK;
    }

    unsafe {
        if redirect_entry_requires_l2_restore(entry) {
            if !redirect_vlan::restore(skb, entry, info.h_proto as u16) {
                return TC_ACT_SHOT;
            }
            if helpers::bpf_skb_store_bytes(
                skb.cast::<c_void>(),
                ETH_SRC_OFFSET,
                ptr::addr_of!((*entry).dmac).cast::<c_void>(),
                6,
                0,
            ) != 0
            {
                increment_tproxy_metric(METRIC_REDIRECT_RESTORE_STORE_FAILURE);
                return TC_ACT_SHOT;
            }
            if helpers::bpf_skb_store_bytes(
                skb.cast::<c_void>(),
                packet::ETH_DST_OFFSET,
                ptr::addr_of!((*entry).smac).cast::<c_void>(),
                6,
                0,
            ) != 0
            {
                increment_tproxy_metric(METRIC_REDIRECT_RESTORE_STORE_FAILURE);
                return TC_ACT_SHOT;
            }
        } else if !redirect_entry_uses_l3_no_mac_redirect(entry) {
            return TC_ACT_SHOT;
        }
        // L3 devices such as PPP are handled by bpf_redirect() through the
        // kernel's no-MAC redirect path. BPF_ADJ_ROOM_MAC changes the room
        // between L2 and L3; using it here would remove bytes from the L3
        // header instead of removing the temporary Ethernet header.
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
        return udp_state_unavailable_action();
    }
    chain_next()
}

#[inline(always)]
pub fn wan_ingress(skb: *mut __sk_buff, link_h_len: u32) -> i32 {
    let mut info = ParsedPacket::zeroed();
    let ret = unsafe { packet::parse_transport(skb, link_h_len, ptr::addr_of_mut!(info)) };
    if ret != 0 {
        return chain_next();
    }
    // `tproxy_port_protect` is a WAN-ingress guard.  Traffic arriving from
    // the physical WAN and addressed directly to the transparent-proxy
    // listener is unsolicited; do not let it reach the dae listener.  LAN
    // ingress and dae-owned outbound traffic use different hooks and remain
    // unaffected.  The flag lives in the historical PARAM padding byte so
    // older object/layout checks continue to pass.
    if protected_wan_destination(
        info.l4proto,
        info.dport,
        crate::abi::param_tproxy_port_protect(),
        crate::abi::param_tproxy_port(),
    ) {
        return TC_ACT_SHOT;
    }
    if info.l4proto == IPPROTO_UDP
        && !udp_state::refresh_reversed_udp_state(ptr::addr_of!(info), true)
    {
        return udp_state_unavailable_action();
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
        return chain_next();
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
            let mut redirect_track_key = BpfRedirectKey::zeroed();
            let mut redirect_entry = BpfRedirectEntry::zeroed();
            return unsafe {
                redirect_to_control_plane(
                    skb,
                    link_h_len,
                    ptr::addr_of!(info),
                    ptr::addr_of!(key),
                    false,
                    ptr::addr_of_mut!(redirect_track_key),
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
        return chain_next();
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
            return udp_state_unavailable_action();
        }
        if unsafe { (*state).is_wan_ingress_direction } != 0 {
            return chain_next();
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
        return chain_next();
    }
    if outbound == routing::ROUTE_OUTBOUND_BLOCK {
        return TC_ACT_SHOT;
    }
    if !routing::outbound_alive(ptr::addr_of!(info), outbound) && !is_dns_udp(ptr::addr_of!(info)) {
        return TC_ACT_SHOT;
    }

    let mut redirect_track_key = BpfRedirectKey::zeroed();
    let mut redirect_entry = BpfRedirectEntry::zeroed();
    unsafe {
        redirect_to_control_plane(
            skb,
            link_h_len,
            ptr::addr_of!(info),
            ptr::addr_of!(key),
            false,
            ptr::addr_of_mut!(redirect_track_key),
            ptr::addr_of_mut!(redirect_entry),
        )
    }
}

#[inline(always)]
pub fn wan_egress(skb: *mut __sk_buff, link_h_len: u32) -> i32 {
    if unsafe { (*skb).ingress_ifindex } != NOWHERE_IFINDEX {
        return chain_next();
    }
    let mut info = ParsedPacket::zeroed();
    let ret = unsafe { packet::parse_transport(skb, link_h_len, ptr::addr_of_mut!(info)) };
    if ret != 0 {
        return chain_next();
    }
    if info.l4proto == IPPROTO_ICMPV6 {
        return chain_next();
    }

    let mut key = BpfTuplesKey::zeroed();
    unsafe {
        packet::build_tuples(ptr::addr_of!(info), ptr::addr_of_mut!(key));
    }

    let pid_pname = routing::pid_pname_for_packet(skb);
    if routing::pid_is_control_plane(skb, pid_pname) {
        return physical_wan_control_plane_passthrough_action();
    }

    let outbound: u8;
    let mark: u32;
    if info.l4proto == IPPROTO_TCP && !is_new_tcp(ptr::addr_of!(info)) {
        let routing_result = routing::lookup_routing_result(ptr::addr_of!(key));
        if routing_result.is_null() {
            return chain_next();
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
                return udp_state_unavailable_action();
            }
            if unsafe { (*state).is_wan_ingress_direction } != 0 {
                return chain_next();
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
        return chain_next();
    }
    if outbound == routing::ROUTE_OUTBOUND_BLOCK {
        return TC_ACT_SHOT;
    }
    if !routing::outbound_alive(ptr::addr_of!(info), outbound) && !is_dns_udp(ptr::addr_of!(info)) {
        return TC_ACT_SHOT;
    }

    let mut redirect_track_key = BpfRedirectKey::zeroed();
    let mut redirect_entry = BpfRedirectEntry::zeroed();
    unsafe {
        redirect_to_control_plane(
            skb,
            link_h_len,
            ptr::addr_of!(info),
            ptr::addr_of!(key),
            true,
            ptr::addr_of_mut!(redirect_track_key),
            ptr::addr_of_mut!(redirect_entry),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redirect_entry(link_layer: u8) -> BpfRedirectEntry {
        let mut entry = BpfRedirectEntry::zeroed();
        entry.link_layer = link_layer;
        entry
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
    fn chain_next_is_non_terminal_pass_through_action() {
        assert_eq!(TCX_NEXT, TC_ACT_UNSPEC);
        assert_eq!(chain_next(), TCX_NEXT);
        assert_ne!(chain_next(), TC_ACT_OK);
        assert_ne!(chain_next(), TC_ACT_SHOT);
    }

    #[test]
    fn unavailable_udp_state_is_terminal_fail_closed() {
        assert_eq!(udp_state_unavailable_action(), TC_ACT_SHOT);
        assert_ne!(udp_state_unavailable_action(), chain_next());
        assert_ne!(udp_state_unavailable_action(), TC_ACT_OK);
        assert_eq!(
            udp_state_unavailable_action_for_policy(
                crate::abi::UDP_STATE_SATURATION_POLICY_FAIL_CLOSED
            ),
            TC_ACT_SHOT
        );
        assert_eq!(
            udp_state_unavailable_action_for_policy(u32::MAX),
            TC_ACT_SHOT
        );
    }

    #[test]
    fn tproxy_port_protection_only_drops_protected_tcp_and_udp_wan_destinations() {
        let port = u16::to_be(12345);
        assert!(protected_wan_destination(IPPROTO_TCP, port, true, port));
        assert!(protected_wan_destination(IPPROTO_UDP, port, true, port));
        assert!(!protected_wan_destination(IPPROTO_TCP, port, false, port));
        assert!(!protected_wan_destination(
            IPPROTO_TCP,
            u16::to_be(443),
            true,
            port
        ));
        assert!(!protected_wan_destination(IPPROTO_ICMPV6, port, true, port));
    }

    #[test]
    fn physical_wan_control_plane_passthrough_continues_the_chain() {
        assert_eq!(
            physical_wan_control_plane_passthrough_action(),
            chain_next()
        );
        assert_ne!(physical_wan_control_plane_passthrough_action(), TC_ACT_OK);
        assert_ne!(physical_wan_control_plane_passthrough_action(), TC_ACT_SHOT);
    }

    #[test]
    fn l3_wan_egress_return_path_defers_temporary_mac_removal_to_kernel_redirect() {
        let l2 = redirect_entry(REDIRECT_LINK_LAYER_L2);
        let l3 = redirect_entry(REDIRECT_LINK_LAYER_L3);
        let unsupported = redirect_entry(0);

        assert_eq!(
            redirect_link_layer_for_header_len(ETH_HLEN),
            REDIRECT_LINK_LAYER_L2
        );
        assert_eq!(
            redirect_link_layer_for_header_len(0),
            REDIRECT_LINK_LAYER_L3
        );
        assert!(redirect_entry_requires_l2_restore(&l2));
        assert!(!redirect_entry_uses_l3_no_mac_redirect(&l2));
        assert!(!redirect_entry_requires_l2_restore(&l3));
        assert!(redirect_entry_uses_l3_no_mac_redirect(&l3));
        assert!(!redirect_entry_requires_l2_restore(&unsupported));
        assert!(!redirect_entry_uses_l3_no_mac_redirect(&unsupported));
    }
}
