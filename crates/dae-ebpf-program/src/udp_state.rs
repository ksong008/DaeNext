use core::{ffi::c_void, ptr};

use crate::abi::{BpfTuplesKey, BpfUdpConnState, BpfUdpStateMetrics};
use crate::packet::{self, ParsedPacket};
use crate::{helpers, maps};

const BPF_NOEXIST: u64 = 1;
const CLOCK_MONOTONIC: u64 = 1;
const UDP_STATE_METRICS_KEY: u32 = 0;
const METRIC_STATE_CREATED: u32 = 0;
const METRIC_STATE_REFRESH: u32 = 1;
const METRIC_INSERT_FAILURE: u32 = 2;
const METRIC_POST_INSERT_LOOKUP_FAILURE: u32 = 3;
const METRIC_TIMER_INIT_FAILURE: u32 = 4;
const METRIC_TIMER_CALLBACK_FAILURE: u32 = 5;
const METRIC_TIMER_START_FAILURE: u32 = 6;

#[inline(never)]
fn increment_udp_state_metric(metric: u32) {
    let key = UDP_STATE_METRICS_KEY;
    let metrics = unsafe {
        helpers::bpf_map_lookup_elem(
            maps::udp_state_metrics_map_ptr(),
            ptr::addr_of!(key).cast::<c_void>(),
        )
    }
    .cast::<BpfUdpStateMetrics>();
    if metrics.is_null() {
        return;
    }
    let counter = unsafe {
        match metric {
            METRIC_STATE_CREATED => ptr::addr_of_mut!((*metrics).state_created_total),
            METRIC_STATE_REFRESH => ptr::addr_of_mut!((*metrics).state_refresh_total),
            METRIC_INSERT_FAILURE => ptr::addr_of_mut!((*metrics).insert_failure_total),
            METRIC_POST_INSERT_LOOKUP_FAILURE => {
                ptr::addr_of_mut!((*metrics).post_insert_lookup_failure_total)
            }
            METRIC_TIMER_INIT_FAILURE => {
                ptr::addr_of_mut!((*metrics).timer_init_failure_total)
            }
            METRIC_TIMER_CALLBACK_FAILURE => {
                ptr::addr_of_mut!((*metrics).timer_callback_failure_total)
            }
            METRIC_TIMER_START_FAILURE => {
                ptr::addr_of_mut!((*metrics).timer_start_failure_total)
            }
            _ => return,
        }
    };
    unsafe {
        counter.write_volatile(counter.read_volatile().wrapping_add(1));
    }
}

#[inline(always)]
unsafe fn refresh_state_timer(state: *mut BpfUdpConnState) {
    if unsafe {
        helpers::bpf_timer_start(
            ptr::addr_of_mut!((*state).timer).cast::<c_void>(),
            crate::abi::param_udp_state_idle_timeout_ns(),
            0,
        )
    } != 0
    {
        increment_udp_state_metric(METRIC_TIMER_START_FAILURE);
    }
}

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
        increment_udp_state_metric(METRIC_STATE_REFRESH);
        unsafe { refresh_state_timer(state) };
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
            let raced_state =
                helpers::bpf_map_lookup_elem(maps::udp_conn_state_map_ptr(), key.cast::<c_void>())
                    .cast::<BpfUdpConnState>();
            if !raced_state.is_null() {
                increment_udp_state_metric(METRIC_STATE_REFRESH);
                refresh_state_timer(raced_state);
                return raced_state;
            }
            increment_udp_state_metric(METRIC_INSERT_FAILURE);
            return ptr::null_mut();
        }
    }
    increment_udp_state_metric(METRIC_STATE_CREATED);

    let state = unsafe {
        helpers::bpf_map_lookup_elem(maps::udp_conn_state_map_ptr(), key.cast::<c_void>())
    }
    .cast::<BpfUdpConnState>();
    if state.is_null() {
        increment_udp_state_metric(METRIC_POST_INSERT_LOOKUP_FAILURE);
        return ptr::null_mut();
    }

    unsafe {
        let timer = ptr::addr_of_mut!((*state).timer).cast::<c_void>();
        if helpers::bpf_timer_init(timer, maps::udp_conn_state_map_ptr(), CLOCK_MONOTONIC) != 0 {
            increment_udp_state_metric(METRIC_TIMER_INIT_FAILURE);
            let _ =
                helpers::bpf_map_delete_elem(maps::udp_conn_state_map_ptr(), key.cast::<c_void>());
            return ptr::null_mut();
        }
        if helpers::bpf_timer_set_callback(timer, refresh_udp_conn_state_timer_cb as *const c_void)
            != 0
        {
            increment_udp_state_metric(METRIC_TIMER_CALLBACK_FAILURE);
            let _ =
                helpers::bpf_map_delete_elem(maps::udp_conn_state_map_ptr(), key.cast::<c_void>());
            return ptr::null_mut();
        }
        if helpers::bpf_timer_start(timer, crate::abi::param_udp_state_idle_timeout_ns(), 0) != 0 {
            increment_udp_state_metric(METRIC_TIMER_START_FAILURE);
            let _ =
                helpers::bpf_map_delete_elem(maps::udp_conn_state_map_ptr(), key.cast::<c_void>());
            return ptr::null_mut();
        }
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
