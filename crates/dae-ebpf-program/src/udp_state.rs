use core::{ffi::c_void, ptr};

use crate::abi::{BpfTuplesKey, BpfUdpConnState};
use crate::packet::{self, ParsedPacket};
use crate::{helpers, maps};

const BPF_NOEXIST: u64 = 1;
const CLOCK_MONOTONIC: u64 = 1;
const TIMEOUT_UDP_CONN_STATE_NS: u64 = 300_000_000_000;

#[inline(never)]
extern "C" fn refresh_udp_conn_state_timer_cb(
    _map: *mut c_void,
    key: *mut BpfTuplesKey,
    _val: *mut BpfUdpConnState,
) -> i32 {
    unsafe {
        let _ = helpers::bpf_map_delete_elem(maps::udp_conn_state_map_ptr(), key.cast::<c_void>());
    }
    0
}

#[inline(always)]
pub unsafe fn refresh_udp_conn_state(
    key: *mut BpfTuplesKey,
    is_wan_ingress_direction: bool,
    new_state: *mut BpfUdpConnState,
) -> *mut BpfUdpConnState {
    let state = unsafe {
        helpers::bpf_map_lookup_elem(maps::udp_conn_state_map_ptr(), key.cast::<c_void>())
    }
    .cast::<BpfUdpConnState>();
    if !state.is_null() {
        unsafe {
            let _ = helpers::bpf_timer_start(
                ptr::addr_of_mut!((*state).timer).cast::<c_void>(),
                TIMEOUT_UDP_CONN_STATE_NS,
                0,
            );
        }
        return state;
    }

    unsafe {
        ptr::write(new_state, BpfUdpConnState::new(is_wan_ingress_direction));
        if helpers::bpf_map_update_elem(
            maps::udp_conn_state_map_ptr(),
            key.cast::<c_void>(),
            new_state.cast::<c_void>(),
            BPF_NOEXIST,
        ) != 0
        {
            return ptr::null_mut();
        }
    }

    let state = unsafe {
        helpers::bpf_map_lookup_elem(maps::udp_conn_state_map_ptr(), key.cast::<c_void>())
    }
    .cast::<BpfUdpConnState>();
    if state.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let timer = ptr::addr_of_mut!((*state).timer).cast::<c_void>();
        let _ = helpers::bpf_timer_init(timer, maps::udp_conn_state_map_ptr(), CLOCK_MONOTONIC);
        let _ = helpers::bpf_timer_set_callback(
            timer,
            refresh_udp_conn_state_timer_cb as *const c_void,
        );
        let _ = helpers::bpf_timer_start(timer, TIMEOUT_UDP_CONN_STATE_NS, 0);
    }

    state
}

pub fn refresh_reversed_udp_state(info: *const ParsedPacket, from_wan: bool) -> bool {
    let mut key = BpfTuplesKey::zeroed();
    let mut reversed_key = BpfTuplesKey::zeroed();
    let mut new_state = BpfUdpConnState::new(from_wan);
    unsafe {
        packet::build_tuples(info, ptr::addr_of_mut!(key));
        packet::reverse_tuples(ptr::addr_of!(key), ptr::addr_of_mut!(reversed_key));
        !refresh_udp_conn_state(
            ptr::addr_of_mut!(reversed_key),
            from_wan,
            ptr::addr_of_mut!(new_state),
        )
        .is_null()
    }
}
