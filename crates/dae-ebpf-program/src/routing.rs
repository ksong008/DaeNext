use core::{ffi::c_void, ptr};

use aya_ebpf::bindings::__sk_buff;

use crate::abi::{
    BPF_LPM_FULL_PREFIX_BITS, BpfDomainRouting, BpfIpBytes, BpfLpmKey, BpfMatchSet,
    BpfOutboundConnectivityQuery, BpfPidPname, BpfRoutingResult, BpfTuplesKey,
    MATCH_TYPE_DOMAIN_SET, MATCH_TYPE_DSCP, MATCH_TYPE_FALLBACK, MATCH_TYPE_IP_SET,
    MATCH_TYPE_IP_VERSION, MATCH_TYPE_L4_PROTO, MATCH_TYPE_MAC, MATCH_TYPE_PORT,
    MATCH_TYPE_PROCESS_NAME, MATCH_TYPE_SOURCE_IP_SET, MATCH_TYPE_SOURCE_PORT, MAX_MATCH_SET_LEN,
    TASK_COMM_LEN,
};
use crate::packet::{self, IPPROTO_TCP, ParsedPacket};
use crate::{helpers, maps};

const BPF_ANY: u64 = 0;
const CONTROL_PLANE_SO_MARK: u32 = 0x100;
const LATENCY_PROBE_HELPER_COMM: [u8; TASK_COMM_LEN] = *b"daed-latency\0\0\0\0";
const GEODATA_PREPARE_HELPER_COMM: [u8; TASK_COMM_LEN] = *b"daed-geodata\0\0\0\0";
const SUBSCRIPTION_PREPARE_HELPER_COMM: [u8; TASK_COMM_LEN] = *b"daed-subscript\0\0";
const OUTBOUND_DIRECT: u8 = 0;
const OUTBOUND_BLOCK: u8 = 1;
const OUTBOUND_MUST_RULES: u8 = 0xfc;
const OUTBOUND_CONTROL_PLANE_ROUTING: u8 = 0xfd;
const OUTBOUND_LOGICAL_OR: u8 = 0xfe;
const OUTBOUND_LOGICAL_MASK: u8 = 0xfe;

const L4_PROTO_TCP_MATCH: u32 = 1;
const L4_PROTO_UDP_MATCH: u32 = 2;
const IP_VERSION_4_MATCH: u32 = 1;
const IP_VERSION_6_MATCH: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfPortRange {
    port_start: u16,
    port_end: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
union BpfMatchValue {
    bytes: [u8; 16],
    index: u32,
    port_range: BpfPortRange,
    l4proto_type: u32,
    ip_version: u32,
    dscp: u8,
}

const ROUTE_BAD_RULE: u8 = 0b0001;
const ROUTE_GOOD_SUBRULE: u8 = 0b0010;
const ROUTE_MUST: u8 = 0b0100;
const ROUTE_IS_DNS: u8 = 0b1000;
const DNS_DEFAULT_PORT: u16 = 53;

const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENOEXEC: i64 = 8;
const EPERM: i64 = 1;

pub const ROUTE_OUTBOUND_DIRECT: u8 = OUTBOUND_DIRECT;
pub const ROUTE_OUTBOUND_BLOCK: u8 = OUTBOUND_BLOCK;

#[repr(C)]
pub struct RouteParams {
    l4proto_type: u32,
    ipversion_type: u32,
    is_wan: u32,
    pname: [u8; TASK_COMM_LEN],
    dscp: u32,
    h_sport: u16,
    h_dport: u16,
    saddr: BpfIpBytes,
    daddr: BpfIpBytes,
    mac: BpfIpBytes,
}

impl RouteParams {
    pub const fn zeroed() -> Self {
        Self {
            l4proto_type: 0,
            ipversion_type: 0,
            is_wan: 0,
            pname: [0; TASK_COMM_LEN],
            dscp: 0,
            h_sport: 0,
            h_dport: 0,
            saddr: BpfIpBytes::zeroed(),
            daddr: BpfIpBytes::zeroed(),
            mac: BpfIpBytes::zeroed(),
        }
    }
}

#[repr(C)]
struct RouteCtx {
    params: *const RouteParams,
    h_dport: u16,
    h_sport: u16,
    result: i64,
    lpm_key_saddr: BpfLpmKey,
    lpm_key_daddr: BpfLpmKey,
    lpm_key_mac: BpfLpmKey,
    state: u8,
}

impl RouteCtx {
    const fn zeroed() -> Self {
        Self {
            params: ptr::null(),
            h_dport: 0,
            h_sport: 0,
            result: -ENOEXEC,
            lpm_key_saddr: BpfLpmKey::zeroed(),
            lpm_key_daddr: BpfLpmKey::zeroed(),
            lpm_key_mac: BpfLpmKey::zeroed(),
            state: 0,
        }
    }
}

#[inline(always)]
fn lookup_match_set(index: *const u32) -> *mut BpfMatchSet {
    unsafe { helpers::bpf_map_lookup_elem(maps::routing_map_ptr(), index.cast::<c_void>()) }
        .cast::<BpfMatchSet>()
}

#[inline(always)]
fn lookup_lpm_map(index: *const u32) -> *mut c_void {
    unsafe { helpers::bpf_map_lookup_elem(maps::lpm_array_map_ptr(), index.cast::<c_void>()) }
}

#[inline(always)]
fn lookup_domain_route(ip: *const BpfIpBytes) -> *mut BpfDomainRouting {
    unsafe { helpers::bpf_map_lookup_elem(maps::domain_routing_map_ptr(), ip.cast::<c_void>()) }
        .cast::<BpfDomainRouting>()
}

#[inline(always)]
pub fn lookup_routing_result(key: *const BpfTuplesKey) -> *mut BpfRoutingResult {
    unsafe { helpers::bpf_map_lookup_elem(maps::routing_tuples_map_ptr(), key.cast::<c_void>()) }
        .cast::<BpfRoutingResult>()
}

#[inline(always)]
pub fn pid_pname_for_packet(skb: *mut __sk_buff) -> *mut BpfPidPname {
    let cookie = unsafe { helpers::bpf_get_socket_cookie(skb.cast::<c_void>()) };
    unsafe {
        helpers::bpf_map_lookup_elem(
            maps::cookie_pid_map_ptr(),
            ptr::addr_of!(cookie).cast::<c_void>(),
        )
    }
    .cast::<BpfPidPname>()
}

#[inline(always)]
pub fn pid_is_control_plane(skb: *mut __sk_buff, pid_pname: *mut BpfPidPname) -> bool {
    if !pid_pname.is_null() {
        let pid_tproxy = crate::abi::param_control_plane_pid();
        if pid_tproxy != 0 && unsafe { (*pid_pname).pid } == pid_tproxy {
            return true;
        }
        if (unsafe { (*skb).mark } & CONTROL_PLANE_SO_MARK) == CONTROL_PLANE_SO_MARK {
            return unsafe { pid_pname_is_control_helper(pid_pname) };
        }
        return false;
    }
    (unsafe { (*skb).mark } & CONTROL_PLANE_SO_MARK) == CONTROL_PLANE_SO_MARK
}

#[inline(always)]
unsafe fn pid_pname_is_control_helper(pid_pname: *const BpfPidPname) -> bool {
    unsafe {
        names_equal(
            ptr::addr_of!((*pid_pname).comm).cast::<u8>(),
            LATENCY_PROBE_HELPER_COMM.as_ptr(),
        ) || names_equal(
            ptr::addr_of!((*pid_pname).comm).cast::<u8>(),
            GEODATA_PREPARE_HELPER_COMM.as_ptr(),
        ) || names_equal(
            ptr::addr_of!((*pid_pname).comm).cast::<u8>(),
            SUBSCRIPTION_PREPARE_HELPER_COMM.as_ptr(),
        )
    }
}

#[inline(always)]
unsafe fn copy16_to_lpm_words(dst: *mut u32, src: *const u8) {
    unsafe {
        let dst = dst.cast::<u8>();
        packet::copy16(dst, src);
    }
}

#[inline(always)]
unsafe fn set_lpm_key(key: *mut BpfLpmKey, ip: *const BpfIpBytes) {
    unsafe {
        (*key).prefix_len = BPF_LPM_FULL_PREFIX_BITS;
        copy16_to_lpm_words(
            ptr::addr_of_mut!((*key).data).cast::<u32>(),
            ptr::addr_of!((*ip).u6_addr8).cast::<u8>(),
        );
    }
}

#[inline(always)]
unsafe fn domain_bitmap_hit(domain: *const BpfDomainRouting, index: u32) -> bool {
    unsafe {
        let word_index = ((index >> 5) & 31) as usize;
        let bit_index = index & 31;
        (((*domain).bitmap[word_index] >> bit_index) & 1) != 0
    }
}

#[inline(always)]
unsafe fn init_route_ctx(ctx: *mut RouteCtx, params: *const RouteParams) {
    unsafe {
        ptr::write(ctx, RouteCtx::zeroed());
        (*ctx).params = params;
        (*ctx).result = -ENOEXEC;
        (*ctx).h_dport = (*params).h_dport;
        (*ctx).h_sport = (*params).h_sport;
        write_route_state(
            ctx,
            if (*ctx).h_dport == DNS_DEFAULT_PORT
                && ((*params).l4proto_type == L4_PROTO_UDP_MATCH
                    || (*params).l4proto_type == L4_PROTO_TCP_MATCH)
            {
                ROUTE_IS_DNS
            } else {
                0
            },
        );
        set_lpm_key(
            ptr::addr_of_mut!((*ctx).lpm_key_saddr),
            ptr::addr_of!((*params).saddr),
        );
        set_lpm_key(
            ptr::addr_of_mut!((*ctx).lpm_key_daddr),
            ptr::addr_of!((*params).daddr),
        );
        set_lpm_key(
            ptr::addr_of_mut!((*ctx).lpm_key_mac),
            ptr::addr_of!((*params).mac),
        );
    }
}

#[inline(always)]
unsafe fn route_state(ctx: *const RouteCtx) -> u8 {
    unsafe { ptr::addr_of!((*ctx).state).read_volatile() }
}

#[inline(always)]
unsafe fn write_route_state(ctx: *mut RouteCtx, state: u8) {
    unsafe {
        ptr::addr_of_mut!((*ctx).state).write_volatile(state);
    }
}

#[inline(always)]
unsafe fn route_state_or(ctx: *mut RouteCtx, bits: u8) {
    unsafe {
        write_route_state(ctx, route_state(ctx) | bits);
    }
}

#[inline(always)]
unsafe fn route_state_and(ctx: *mut RouteCtx, bits: u8) {
    unsafe {
        write_route_state(ctx, route_state(ctx) & bits);
    }
}

#[inline(always)]
unsafe fn names_equal(a: *const u8, b: *const u8) -> bool {
    unsafe {
        a.add(0).read_volatile() == b.add(0).read_volatile()
            && a.add(1).read_volatile() == b.add(1).read_volatile()
            && a.add(2).read_volatile() == b.add(2).read_volatile()
            && a.add(3).read_volatile() == b.add(3).read_volatile()
            && a.add(4).read_volatile() == b.add(4).read_volatile()
            && a.add(5).read_volatile() == b.add(5).read_volatile()
            && a.add(6).read_volatile() == b.add(6).read_volatile()
            && a.add(7).read_volatile() == b.add(7).read_volatile()
            && a.add(8).read_volatile() == b.add(8).read_volatile()
            && a.add(9).read_volatile() == b.add(9).read_volatile()
            && a.add(10).read_volatile() == b.add(10).read_volatile()
            && a.add(11).read_volatile() == b.add(11).read_volatile()
            && a.add(12).read_volatile() == b.add(12).read_volatile()
            && a.add(13).read_volatile() == b.add(13).read_volatile()
            && a.add(14).read_volatile() == b.add(14).read_volatile()
            && a.add(15).read_volatile() == b.add(15).read_volatile()
    }
}

#[inline(always)]
unsafe fn match_value_ptr(match_set: *const BpfMatchSet) -> *const u8 {
    unsafe { ptr::addr_of!((*match_set).value).cast::<u8>() }
}

#[inline(always)]
unsafe fn match_value(match_set: *const BpfMatchSet) -> *const BpfMatchValue {
    unsafe { ptr::addr_of!((*match_set).value).cast::<BpfMatchValue>() }
}

#[inline(never)]
extern "C" fn route_loop_cb(index: u32, data: *mut c_void) -> i64 {
    let ctx = data.cast::<RouteCtx>();
    if index >= MAX_MATCH_SET_LEN {
        unsafe {
            (*ctx).result = -EFAULT;
        }
        return 1;
    }

    let match_set = lookup_match_set(ptr::addr_of!(index));
    if match_set.is_null() {
        unsafe {
            (*ctx).result = -EFAULT;
        }
        return 1;
    }

    unsafe {
        if (route_state(ctx) & (ROUTE_GOOD_SUBRULE | ROUTE_BAD_RULE)) == 0 {
            let params = (*ctx).params;
            let kind = (*match_set).kind;
            if kind == MATCH_TYPE_MAC
                || kind == MATCH_TYPE_IP_SET
                || kind == MATCH_TYPE_SOURCE_IP_SET
            {
                let lpm_index = (*match_value(match_set)).index;
                let lpm = lookup_lpm_map(ptr::addr_of!(lpm_index));
                if lpm.is_null() {
                    (*ctx).result = -EFAULT;
                    return 1;
                }
                let lpm_key = if kind == MATCH_TYPE_MAC {
                    ptr::addr_of_mut!((*ctx).lpm_key_mac)
                } else if kind == MATCH_TYPE_IP_SET {
                    ptr::addr_of_mut!((*ctx).lpm_key_daddr)
                } else {
                    ptr::addr_of_mut!((*ctx).lpm_key_saddr)
                };
                if !helpers::bpf_map_lookup_elem(lpm, lpm_key.cast::<c_void>()).is_null() {
                    route_state_or(ctx, ROUTE_GOOD_SUBRULE);
                }
            } else if kind == MATCH_TYPE_PORT {
                let range = (*match_value(match_set)).port_range;
                if range.port_start <= (*ctx).h_dport && (*ctx).h_dport <= range.port_end {
                    route_state_or(ctx, ROUTE_GOOD_SUBRULE);
                }
            } else if kind == MATCH_TYPE_SOURCE_PORT {
                let range = (*match_value(match_set)).port_range;
                if range.port_start <= (*ctx).h_sport && (*ctx).h_sport <= range.port_end {
                    route_state_or(ctx, ROUTE_GOOD_SUBRULE);
                }
            } else if kind == MATCH_TYPE_L4_PROTO {
                if ((*params).l4proto_type & (*match_value(match_set)).l4proto_type) != 0 {
                    route_state_or(ctx, ROUTE_GOOD_SUBRULE);
                }
            } else if kind == MATCH_TYPE_IP_VERSION {
                if ((*params).ipversion_type & (*match_value(match_set)).ip_version) != 0 {
                    route_state_or(ctx, ROUTE_GOOD_SUBRULE);
                }
            } else if kind == MATCH_TYPE_DOMAIN_SET {
                let domain = lookup_domain_route(ptr::addr_of!((*params).daddr));
                if !domain.is_null() && domain_bitmap_hit(domain, index) {
                    route_state_or(ctx, ROUTE_GOOD_SUBRULE);
                }
            } else if kind == MATCH_TYPE_PROCESS_NAME {
                if (*params).is_wan != 0
                    && names_equal(match_value_ptr(match_set), (*params).pname.as_ptr())
                {
                    route_state_or(ctx, ROUTE_GOOD_SUBRULE);
                }
            } else if kind == MATCH_TYPE_DSCP {
                if (*params).dscp == (*match_value(match_set)).dscp as u32 {
                    route_state_or(ctx, ROUTE_GOOD_SUBRULE);
                }
            } else if kind == MATCH_TYPE_FALLBACK {
                route_state_or(ctx, ROUTE_GOOD_SUBRULE);
            } else {
                (*ctx).result = -EINVAL;
                return 1;
            }
        }

        if (*match_set).outbound != OUTBOUND_LOGICAL_OR {
            let state = route_state(ctx);
            let subrule_hit = (state & ROUTE_GOOD_SUBRULE) != 0;
            let negated = (*match_set).not != 0;
            if subrule_hit == negated {
                route_state_or(ctx, ROUTE_BAD_RULE);
            }
            route_state_and(ctx, !ROUTE_GOOD_SUBRULE);
        }

        if ((*match_set).outbound & OUTBOUND_LOGICAL_MASK) != OUTBOUND_LOGICAL_MASK {
            let state = route_state(ctx);
            if (state & ROUTE_BAD_RULE) == 0 {
                if (*match_set).outbound == OUTBOUND_MUST_RULES {
                    route_state_or(ctx, ROUTE_MUST);
                } else {
                    let must = (state & ROUTE_MUST) != 0 || (*match_set).must != 0;
                    let outbound = if !must && (state & ROUTE_IS_DNS) != 0 {
                        OUTBOUND_CONTROL_PLANE_ROUTING
                    } else {
                        (*match_set).outbound
                    };
                    (*ctx).result = (outbound as i64)
                        | (((*match_set).mark as i64) << 8)
                        | ((must as i64) << 40);
                    return 1;
                }
            }
            route_state_and(ctx, !ROUTE_BAD_RULE);
        }
    }

    0
}

#[inline(always)]
pub fn route(params: *const RouteParams) -> i64 {
    let mut ctx = RouteCtx::zeroed();
    unsafe {
        init_route_ctx(ptr::addr_of_mut!(ctx), params);
        let ret = helpers::bpf_loop(
            MAX_MATCH_SET_LEN,
            route_loop_cb as *const c_void,
            ptr::addr_of_mut!(ctx).cast::<c_void>(),
            0,
        );
        if ret < 0 {
            return ret;
        }
        if ctx.result >= 0 { ctx.result } else { -EPERM }
    }
}

#[inline(always)]
unsafe fn copy_process_name(dst: *mut u8, src: *const i8) {
    unsafe {
        let src = src.cast::<u8>();
        dst.add(0).write_volatile(src.add(0).read_volatile());
        dst.add(1).write_volatile(src.add(1).read_volatile());
        dst.add(2).write_volatile(src.add(2).read_volatile());
        dst.add(3).write_volatile(src.add(3).read_volatile());
        dst.add(4).write_volatile(src.add(4).read_volatile());
        dst.add(5).write_volatile(src.add(5).read_volatile());
        dst.add(6).write_volatile(src.add(6).read_volatile());
        dst.add(7).write_volatile(src.add(7).read_volatile());
        dst.add(8).write_volatile(src.add(8).read_volatile());
        dst.add(9).write_volatile(src.add(9).read_volatile());
        dst.add(10).write_volatile(src.add(10).read_volatile());
        dst.add(11).write_volatile(src.add(11).read_volatile());
        dst.add(12).write_volatile(src.add(12).read_volatile());
        dst.add(13).write_volatile(src.add(13).read_volatile());
        dst.add(14).write_volatile(src.add(14).read_volatile());
        dst.add(15).write_volatile(src.add(15).read_volatile());
    }
}

#[inline(always)]
pub fn route_params_from_packet(
    params: *mut RouteParams,
    info: *const ParsedPacket,
    is_wan: bool,
    pid_pname: *const BpfPidPname,
) {
    unsafe {
        ptr::write(params, RouteParams::zeroed());
        (*params).l4proto_type = if (*info).l4proto == IPPROTO_TCP {
            L4_PROTO_TCP_MATCH
        } else {
            L4_PROTO_UDP_MATCH
        };
        (*params).ipversion_type = if (*info).is_ipv4 != 0 {
            IP_VERSION_4_MATCH
        } else {
            IP_VERSION_6_MATCH
        };
        (*params).is_wan = is_wan as u32;
        (*params).dscp = (*info).dscp as u32;
        (*params).h_sport = u16::from_be((*info).sport);
        (*params).h_dport = u16::from_be((*info).dport);
        packet::copy_ip(
            ptr::addr_of_mut!((*params).saddr),
            ptr::addr_of!((*info).sip),
        );
        packet::copy_ip(
            ptr::addr_of_mut!((*params).daddr),
            ptr::addr_of!((*info).dip),
        );
        (*params).mac.u6_addr8[10] = (*info).eth_src[0];
        (*params).mac.u6_addr8[11] = (*info).eth_src[1];
        (*params).mac.u6_addr8[12] = (*info).eth_src[2];
        (*params).mac.u6_addr8[13] = (*info).eth_src[3];
        (*params).mac.u6_addr8[14] = (*info).eth_src[4];
        (*params).mac.u6_addr8[15] = (*info).eth_src[5];
        if !pid_pname.is_null() {
            copy_process_name(
                (*params).pname.as_mut_ptr(),
                ptr::addr_of!((*pid_pname).pname).cast::<i8>(),
            );
        }
    }
}

#[inline(always)]
pub fn save_routing_result(
    key: *const BpfTuplesKey,
    info: *const ParsedPacket,
    outbound: u8,
    mark: u32,
    must: bool,
    pid_pname: *const BpfPidPname,
) -> bool {
    let mut result = BpfRoutingResult {
        mark,
        must: must as u8,
        mac: [0; 6],
        outbound,
        pname: [0; TASK_COMM_LEN],
        pid: 0,
        dscp: unsafe { (*info).dscp },
        padding: [0; 3],
    };
    unsafe {
        packet::copy_mac(result.mac.as_mut_ptr(), (*info).eth_src.as_ptr());
        if !pid_pname.is_null() {
            copy_process_name(
                result.pname.as_mut_ptr(),
                ptr::addr_of!((*pid_pname).pname).cast::<i8>(),
            );
            result.pid = (*pid_pname).pid;
        }
        helpers::bpf_map_update_elem(
            maps::routing_tuples_map_ptr(),
            key.cast::<c_void>(),
            ptr::addr_of!(result).cast::<c_void>(),
            BPF_ANY,
        ) == 0
    }
}

#[inline(always)]
pub fn outbound_alive(info: *const ParsedPacket, outbound: u8) -> bool {
    let query = BpfOutboundConnectivityQuery {
        outbound,
        l4proto: unsafe { (*info).l4proto },
        ipversion: if unsafe { (*info).is_ipv4 } != 0 {
            4
        } else {
            6
        },
    };
    let alive = unsafe {
        helpers::bpf_map_lookup_elem(
            maps::outbound_connectivity_map_ptr(),
            ptr::addr_of!(query).cast::<c_void>(),
        )
    }
    .cast::<u32>();
    alive.is_null() || unsafe { *alive } != 0
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;

    const HELPER_PARENT_ARGV0_BASENAME: &[u8] = b"daed";

    fn process_name(bytes: &[u8]) -> [i8; TASK_COMM_LEN] {
        let mut out = [0; TASK_COMM_LEN];
        for (dst, src) in out.iter_mut().zip(bytes.iter().copied()) {
            *dst = src as i8;
        }
        out
    }

    #[test]
    fn latency_helper_control_identity_uses_task_comm_not_enhanced_pname() {
        let helper_comm = process_name(&LATENCY_PROBE_HELPER_COMM);
        let enhanced_pname = process_name(HELPER_PARENT_ARGV0_BASENAME);
        let helper_identity = BpfPidPname {
            pid: 0,
            comm: helper_comm,
            pname: enhanced_pname,
        };
        assert!(unsafe { pid_pname_is_control_helper(ptr::addr_of!(helper_identity)) });

        let reversed_identity = BpfPidPname {
            pid: 0,
            comm: enhanced_pname,
            pname: helper_comm,
        };
        assert!(!unsafe { pid_pname_is_control_helper(ptr::addr_of!(reversed_identity)) });
    }

    #[test]
    fn geodata_helper_control_identity_uses_task_comm() {
        let helper_comm = process_name(&GEODATA_PREPARE_HELPER_COMM);
        let helper_identity = BpfPidPname {
            pid: 0,
            comm: helper_comm,
            pname: process_name(HELPER_PARENT_ARGV0_BASENAME),
        };
        assert!(unsafe { pid_pname_is_control_helper(ptr::addr_of!(helper_identity)) });
    }
}
