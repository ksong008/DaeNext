use core::{ffi::c_void, ptr};

use aya_ebpf::bindings::{bpf_sock, bpf_sock_addr};

use crate::abi::{BpfPidPname, TASK_COMM_LEN};
use crate::{helpers, maps};

const BPF_ANY: u64 = 0;

pub fn allow() -> i32 {
    1
}

#[inline(always)]
unsafe fn update_map_elem_by_cookie(ctx: *mut c_void) {
    let cookie = unsafe { helpers::bpf_get_socket_cookie(ctx) };
    if cookie == 0 {
        return;
    }

    let key = ptr::addr_of!(cookie).cast::<c_void>();
    if !unsafe { helpers::bpf_map_lookup_elem(maps::cookie_pid_map_ptr(), key) }.is_null() {
        return;
    }

    let mut val = BpfPidPname::zeroed();
    val.pid = (unsafe { helpers::bpf_get_current_pid_tgid() } >> 32) as u32;
    let _ = unsafe {
        helpers::bpf_get_current_comm(
            val.pname.as_mut_ptr().cast::<c_void>(),
            TASK_COMM_LEN as u32,
        )
    };

    let val_ptr = ptr::addr_of!(val).cast::<c_void>();
    let _ =
        unsafe { helpers::bpf_map_update_elem(maps::cookie_pid_map_ptr(), key, val_ptr, BPF_ANY) };
    let _ = unsafe {
        helpers::bpf_map_update_elem(
            maps::tgid_pname_map_ptr(),
            ptr::addr_of!(val.pid).cast::<c_void>(),
            val.pname.as_ptr().cast::<c_void>(),
            BPF_ANY,
        )
    };
}

#[inline(always)]
unsafe fn delete_map_elem_by_cookie(ctx: *mut c_void) {
    let cookie = unsafe { helpers::bpf_get_socket_cookie(ctx) };
    if cookie == 0 {
        return;
    }
    let _ = unsafe {
        helpers::bpf_map_delete_elem(
            maps::cookie_pid_map_ptr(),
            ptr::addr_of!(cookie).cast::<c_void>(),
        )
    };
}

pub fn update_sock(ctx: *mut bpf_sock) -> i32 {
    unsafe {
        update_map_elem_by_cookie(ctx.cast::<c_void>());
    }
    allow()
}

pub fn update_sock_addr(ctx: *mut bpf_sock_addr) -> i32 {
    unsafe {
        update_map_elem_by_cookie(ctx.cast::<c_void>());
    }
    allow()
}

pub fn release_sock(ctx: *mut bpf_sock) -> i32 {
    unsafe {
        delete_map_elem_by_cookie(ctx.cast::<c_void>());
    }
    allow()
}
