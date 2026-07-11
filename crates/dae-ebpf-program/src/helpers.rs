use core::ffi::c_void;

#[cfg(target_arch = "bpf")]
const BPF_FUNC_MAP_LOOKUP_ELEM: usize = 1;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_MAP_UPDATE_ELEM: usize = 2;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_MAP_DELETE_ELEM: usize = 3;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_SKB_STORE_BYTES: usize = 9;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_GET_CURRENT_PID_TGID: usize = 14;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_GET_CURRENT_COMM: usize = 16;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_SKB_VLAN_POP: usize = 19;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_GET_CURRENT_TASK: usize = 35;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_REDIRECT: usize = 23;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_SKB_LOAD_BYTES: usize = 26;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_SKB_CHANGE_TYPE: usize = 32;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_SKB_CHANGE_HEAD: usize = 43;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_SKB_ADJUST_ROOM: usize = 50;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_GET_SOCKET_COOKIE: usize = 46;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_SK_LOOKUP_UDP: usize = 85;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_SK_RELEASE: usize = 86;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_SKC_LOOKUP_TCP: usize = 99;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_PROBE_READ_KERNEL: usize = 113;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_PROBE_READ_USER_STR: usize = 114;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_SK_ASSIGN: usize = 124;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_REDIRECT_PEER: usize = 155;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_TIMER_INIT: usize = 169;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_TIMER_SET_CALLBACK: usize = 170;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_TIMER_START: usize = 171;
#[cfg(target_arch = "bpf")]
const BPF_FUNC_LOOP: usize = 181;

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_map_lookup_elem(map: *mut c_void, key: *const c_void) -> *mut c_void {
    let helper: unsafe extern "C" fn(*mut c_void, *const c_void) -> *mut c_void =
        unsafe { core::mem::transmute(BPF_FUNC_MAP_LOOKUP_ELEM) };
    unsafe { helper(map, key) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_map_lookup_elem(_map: *mut c_void, _key: *const c_void) -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_map_update_elem(
    map: *mut c_void,
    key: *const c_void,
    value: *const c_void,
    flags: u64,
) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void, u64) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_MAP_UPDATE_ELEM) };
    unsafe { helper(map, key, value, flags) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_map_update_elem(
    _map: *mut c_void,
    _key: *const c_void,
    _value: *const c_void,
    _flags: u64,
) -> i64 {
    0
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_map_delete_elem(map: *mut c_void, key: *const c_void) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, *const c_void) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_MAP_DELETE_ELEM) };
    unsafe { helper(map, key) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_map_delete_elem(_map: *mut c_void, _key: *const c_void) -> i64 {
    0
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_skb_store_bytes(
    skb: *mut c_void,
    offset: u32,
    from: *const c_void,
    len: u32,
    flags: u64,
) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, u32, *const c_void, u32, u64) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_SKB_STORE_BYTES) };
    unsafe { helper(skb, offset, from, len, flags) }
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_skb_vlan_pop(skb: *mut c_void) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_SKB_VLAN_POP) };
    unsafe { helper(skb) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_skb_vlan_pop(_skb: *mut c_void) -> i64 {
    0
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_skb_store_bytes(
    _skb: *mut c_void,
    _offset: u32,
    _from: *const c_void,
    _len: u32,
    _flags: u64,
) -> i64 {
    0
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_get_current_pid_tgid() -> u64 {
    let helper: unsafe extern "C" fn() -> u64 =
        unsafe { core::mem::transmute(BPF_FUNC_GET_CURRENT_PID_TGID) };
    unsafe { helper() }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_get_current_pid_tgid() -> u64 {
    0
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_get_current_comm(buf: *mut c_void, size: u32) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, u32) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_GET_CURRENT_COMM) };
    unsafe { helper(buf, size) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_get_current_comm(_buf: *mut c_void, _size: u32) -> i64 {
    0
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_get_current_task() -> *mut c_void {
    let helper: unsafe extern "C" fn() -> *mut c_void =
        unsafe { core::mem::transmute(BPF_FUNC_GET_CURRENT_TASK) };
    unsafe { helper() }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_get_current_task() -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_redirect(ifindex: u32, flags: u64) -> i64 {
    let helper: unsafe extern "C" fn(u32, u64) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_REDIRECT) };
    unsafe { helper(ifindex, flags) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_redirect(_ifindex: u32, _flags: u64) -> i64 {
    0
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_redirect_peer(ifindex: u32, flags: u64) -> i64 {
    let helper: unsafe extern "C" fn(u32, u64) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_REDIRECT_PEER) };
    unsafe { helper(ifindex, flags) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_redirect_peer(_ifindex: u32, _flags: u64) -> i64 {
    0
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_skb_load_bytes(skb: *mut c_void, offset: u32, to: *mut c_void, len: u32) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, u32, *mut c_void, u32) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_SKB_LOAD_BYTES) };
    unsafe { helper(skb, offset, to, len) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_skb_load_bytes(
    _skb: *mut c_void,
    _offset: u32,
    _to: *mut c_void,
    _len: u32,
) -> i64 {
    0
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_skb_change_type(skb: *mut c_void, skb_type: u32) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, u32) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_SKB_CHANGE_TYPE) };
    unsafe { helper(skb, skb_type) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_skb_change_type(_skb: *mut c_void, _skb_type: u32) -> i64 {
    0
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_skb_change_head(skb: *mut c_void, head_room_len: u32, flags: u64) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, u32, u64) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_SKB_CHANGE_HEAD) };
    unsafe { helper(skb, head_room_len, flags) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_skb_change_head(_skb: *mut c_void, _head_room_len: u32, _flags: u64) -> i64 {
    0
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_skb_adjust_room(skb: *mut c_void, len_diff: i32, mode: u32, flags: u64) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, i32, u32, u64) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_SKB_ADJUST_ROOM) };
    unsafe { helper(skb, len_diff, mode, flags) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_skb_adjust_room(
    _skb: *mut c_void,
    _len_diff: i32,
    _mode: u32,
    _flags: u64,
) -> i64 {
    0
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_get_socket_cookie(ctx: *mut c_void) -> u64 {
    let helper: unsafe extern "C" fn(*mut c_void) -> u64 =
        unsafe { core::mem::transmute(BPF_FUNC_GET_SOCKET_COOKIE) };
    unsafe { helper(ctx) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_get_socket_cookie(_ctx: *mut c_void) -> u64 {
    0
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_sk_lookup_udp(
    skb: *mut c_void,
    tuple: *mut c_void,
    tuple_size: u32,
    netns: u64,
    flags: u64,
) -> *mut c_void {
    let helper: unsafe extern "C" fn(*mut c_void, *mut c_void, u32, u64, u64) -> *mut c_void =
        unsafe { core::mem::transmute(BPF_FUNC_SK_LOOKUP_UDP) };
    unsafe { helper(skb, tuple, tuple_size, netns, flags) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_sk_lookup_udp(
    _skb: *mut c_void,
    _tuple: *mut c_void,
    _tuple_size: u32,
    _netns: u64,
    _flags: u64,
) -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_sk_release(sock: *mut c_void) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_SK_RELEASE) };
    unsafe { helper(sock) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_sk_release(_sock: *mut c_void) -> i64 {
    0
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_skc_lookup_tcp(
    skb: *mut c_void,
    tuple: *mut c_void,
    tuple_size: u32,
    netns: u64,
    flags: u64,
) -> *mut c_void {
    let helper: unsafe extern "C" fn(*mut c_void, *mut c_void, u32, u64, u64) -> *mut c_void =
        unsafe { core::mem::transmute(BPF_FUNC_SKC_LOOKUP_TCP) };
    unsafe { helper(skb, tuple, tuple_size, netns, flags) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_skc_lookup_tcp(
    _skb: *mut c_void,
    _tuple: *mut c_void,
    _tuple_size: u32,
    _netns: u64,
    _flags: u64,
) -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_probe_read_kernel(dst: *mut c_void, size: u32, kernel_ptr: *const c_void) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, u32, *const c_void) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_PROBE_READ_KERNEL) };
    unsafe { helper(dst, size, kernel_ptr) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_probe_read_kernel(
    _dst: *mut c_void,
    _size: u32,
    _kernel_ptr: *const c_void,
) -> i64 {
    -1
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_probe_read_user_str(dst: *mut c_void, size: u32, user_ptr: *const c_void) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, u32, *const c_void) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_PROBE_READ_USER_STR) };
    unsafe { helper(dst, size, user_ptr) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_probe_read_user_str(
    _dst: *mut c_void,
    _size: u32,
    _user_ptr: *const c_void,
) -> i64 {
    -1
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_sk_assign(skb: *mut c_void, sock: *mut c_void, flags: u64) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, *mut c_void, u64) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_SK_ASSIGN) };
    unsafe { helper(skb, sock, flags) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_sk_assign(_skb: *mut c_void, _sock: *mut c_void, _flags: u64) -> i64 {
    0
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_timer_init(timer: *mut c_void, map: *mut c_void, flags: u64) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, *mut c_void, u64) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_TIMER_INIT) };
    unsafe { helper(timer, map, flags) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_timer_init(_timer: *mut c_void, _map: *mut c_void, _flags: u64) -> i64 {
    0
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_timer_set_callback(timer: *mut c_void, callback: *const c_void) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, *const c_void) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_TIMER_SET_CALLBACK) };
    unsafe { helper(timer, callback) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_timer_set_callback(_timer: *mut c_void, _callback: *const c_void) -> i64 {
    0
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_timer_start(timer: *mut c_void, nsecs: u64, flags: u64) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, u64, u64) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_TIMER_START) };
    unsafe { helper(timer, nsecs, flags) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_timer_start(_timer: *mut c_void, _nsecs: u64, _flags: u64) -> i64 {
    0
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn bpf_loop(
    nr_loops: u32,
    callback: *const c_void,
    callback_ctx: *mut c_void,
    flags: u64,
) -> i64 {
    let helper: unsafe extern "C" fn(u32, *const c_void, *mut c_void, u64) -> i64 =
        unsafe { core::mem::transmute(BPF_FUNC_LOOP) };
    unsafe { helper(nr_loops, callback, callback_ctx, flags) }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn bpf_loop(
    _nr_loops: u32,
    _callback: *const c_void,
    _callback_ctx: *mut c_void,
    _flags: u64,
) -> i64 {
    0
}
