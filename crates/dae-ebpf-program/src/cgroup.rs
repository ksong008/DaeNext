use core::{ffi::c_void, ptr};

use aya_ebpf::bindings::{bpf_sock, bpf_sock_addr};

#[cfg(feature = "pname-core")]
use crate::abi;
use crate::abi::{BpfPidPname, TASK_COMM_LEN};
use crate::{helpers, maps};

const BPF_ANY: u64 = 0;
#[cfg(feature = "pname-core")]
const MAX_ARG_LEN: usize = 128;

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

    let val = unsafe { get_pid_pname() };

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
unsafe fn get_pid_pname() -> BpfPidPname {
    let mut val = BpfPidPname::zeroed();
    val.pid = (unsafe { helpers::bpf_get_current_pid_tgid() } >> 32) as u32;
    #[cfg(feature = "pname-core")]
    {
        if abi::param_has_bpf_get_current_task() != 0
            && unsafe { fill_current_task_argv0_basename(&mut val) }
        {
            return val;
        }
    }
    let _ = unsafe {
        helpers::bpf_get_current_comm(
            val.pname.as_mut_ptr().cast::<c_void>(),
            TASK_COMM_LEN as u32,
        )
    };
    val
}

#[cfg(feature = "pname-core")]
#[inline(always)]
unsafe fn fill_current_task_argv0_basename(val: &mut BpfPidPname) -> bool {
    let task = unsafe { helpers::bpf_get_current_task() };
    if task.is_null() {
        return false;
    }

    let task_struct_mm_offset = abi::param_task_struct_mm_offset();
    let mm_struct_arg_start_offset = abi::param_mm_struct_arg_start_offset();
    if task_struct_mm_offset == 0 || mm_struct_arg_start_offset == 0 {
        return false;
    }

    let mut mm_addr = 0u64;
    let mm_field_ptr = ((task as u64) + task_struct_mm_offset as u64) as *const c_void;
    let ret = unsafe {
        helpers::bpf_probe_read_kernel(
            ptr::addr_of_mut!(mm_addr).cast::<c_void>(),
            core::mem::size_of::<u64>() as u32,
            mm_field_ptr,
        )
    };
    if ret != 0 || mm_addr == 0 {
        return false;
    }

    let mut arg_start = 0u64;
    let arg_start_field_ptr = (mm_addr + mm_struct_arg_start_offset as u64) as *const c_void;
    let ret = unsafe {
        helpers::bpf_probe_read_kernel(
            ptr::addr_of_mut!(arg_start).cast::<c_void>(),
            core::mem::size_of::<u64>() as u32,
            arg_start_field_ptr,
        )
    };
    if ret != 0 {
        return false;
    }
    if arg_start == 0 {
        return false;
    }

    let mut arg_buf = [0u8; MAX_ARG_LEN];
    let ret = unsafe {
        helpers::bpf_probe_read_user_str(
            arg_buf.as_mut_ptr().cast::<c_void>(),
            MAX_ARG_LEN as u32,
            arg_start as *const c_void,
        )
    };
    if ret <= 0 {
        return false;
    }

    let mut offset = 0usize;
    let mut index = 0usize;
    while index < MAX_ARG_LEN {
        let byte = arg_buf[index];
        if byte == b'/' {
            offset = index + 1;
        }
        if byte == 0 {
            break;
        }
        index += 1;
    }

    if offset >= MAX_ARG_LEN || arg_buf[offset] == 0 {
        return false;
    }

    let mut out = 0usize;
    while out < TASK_COMM_LEN {
        let src = offset + out;
        if src < MAX_ARG_LEN && arg_buf[src] != 0 {
            val.pname[out] = arg_buf[src] as i8;
        } else {
            val.pname[out] = 0;
            break;
        }
        out += 1;
    }
    true
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
