use core::{cell::UnsafeCell, ffi::c_void, ptr};

use aya_ebpf::{
    bindings::{
        bpf_map_def,
        bpf_map_type::{
            BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_ARRAY_OF_MAPS, BPF_MAP_TYPE_HASH,
            BPF_MAP_TYPE_LPM_TRIE, BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_SOCKHASH,
            BPF_MAP_TYPE_SOCKMAP,
        },
    },
    macros::{btf_map, map},
};

use crate::abi::{
    BpfDomainRouting, BpfLpmKey, BpfMatchSet, BpfOutboundConnectivityQuery, BpfPidPname,
    BpfRedirectEntry, BpfRedirectTuple, BpfRoutingResult, BpfTuplesKey, BpfUdpConnState,
    MAX_COOKIE_PID_PNAME_MAPPING_NUM, MAX_DOMAIN_ROUTING_NUM, MAX_DST_MAPPING_NUM, MAX_LPM_NUM,
    MAX_LPM_SIZE, MAX_MATCH_SET_LEN, MAX_TGID_PNAME_MAPPING_NUM,
};

const BPF_F_NO_PREALLOC: u32 = 1;
const PIN_NONE: u32 = 0;
const PIN_BY_NAME: u32 = 1;

#[repr(transparent)]
pub struct RawMap {
    def: UnsafeCell<bpf_map_def>,
}

unsafe impl Sync for RawMap {}

impl RawMap {
    const fn new(
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        flags: u32,
        pinning: u32,
    ) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: map_type,
                key_size,
                value_size,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning,
            }),
        }
    }
}

#[repr(C)]
pub struct BtfMapDef<K, V, const TYPE: usize, const MAX_ENTRIES: usize> {
    pub r#type: *const [i32; TYPE],
    pub key: *const K,
    pub value: *const V,
    pub max_entries: *const [i32; MAX_ENTRIES],
}

unsafe impl<K, V, const TYPE: usize, const MAX_ENTRIES: usize> Sync
    for BtfMapDef<K, V, TYPE, MAX_ENTRIES>
{
}

impl<K, V, const TYPE: usize, const MAX_ENTRIES: usize> BtfMapDef<K, V, TYPE, MAX_ENTRIES> {
    pub const fn new() -> Self {
        Self {
            r#type: ptr::null(),
            key: ptr::null(),
            value: ptr::null(),
            max_entries: ptr::null(),
        }
    }
}

impl<K, V, const TYPE: usize, const MAX_ENTRIES: usize> Default
    for BtfMapDef<K, V, TYPE, MAX_ENTRIES>
{
    fn default() -> Self {
        Self::new()
    }
}

const fn size_of<T>() -> u32 {
    core::mem::size_of::<T>() as u32
}

#[map(name = "outbound_connectivity_map")]
static OUTBOUND_CONNECTIVITY_MAP: RawMap = RawMap::new(
    BPF_MAP_TYPE_HASH,
    size_of::<BpfOutboundConnectivityQuery>(),
    size_of::<u32>(),
    1024,
    0,
    PIN_NONE,
);

#[map(name = "listen_socket_map")]
static LISTEN_SOCKET_MAP: RawMap = RawMap::new(
    BPF_MAP_TYPE_SOCKMAP,
    size_of::<u32>(),
    size_of::<u64>(),
    4,
    0,
    PIN_NONE,
);

#[map(name = "redirect_track")]
static REDIRECT_TRACK: RawMap = RawMap::new(
    BPF_MAP_TYPE_LRU_HASH,
    size_of::<BpfRedirectTuple>(),
    size_of::<BpfRedirectEntry>(),
    65_536,
    0,
    PIN_NONE,
);

#[map(name = "tgid_pname_map")]
static TGID_PNAME_MAP: RawMap = RawMap::new(
    BPF_MAP_TYPE_LRU_HASH,
    size_of::<u32>(),
    size_of::<[u32; 4]>(),
    MAX_TGID_PNAME_MAPPING_NUM,
    0,
    PIN_BY_NAME,
);

#[map(name = "routing_tuples_map")]
static ROUTING_TUPLES_MAP: RawMap = RawMap::new(
    BPF_MAP_TYPE_LRU_HASH,
    size_of::<BpfTuplesKey>(),
    size_of::<BpfRoutingResult>(),
    MAX_DST_MAPPING_NUM,
    0,
    PIN_BY_NAME,
);

#[map(name = "fast_sock")]
static FAST_SOCK: RawMap = RawMap::new(
    BPF_MAP_TYPE_SOCKHASH,
    size_of::<BpfTuplesKey>(),
    size_of::<u64>(),
    65_535,
    0,
    PIN_NONE,
);

#[map(name = "unused_lpm_type")]
static UNUSED_LPM_TYPE: RawMap = RawMap::new(
    BPF_MAP_TYPE_LPM_TRIE,
    size_of::<BpfLpmKey>(),
    size_of::<u32>(),
    MAX_LPM_SIZE,
    BPF_F_NO_PREALLOC,
    PIN_NONE,
);

#[map(name = "lpm_array_map")]
static LPM_ARRAY_MAP: RawMap = RawMap::new(
    BPF_MAP_TYPE_ARRAY_OF_MAPS,
    size_of::<u32>(),
    size_of::<u32>(),
    MAX_LPM_NUM,
    0,
    PIN_BY_NAME,
);

#[map(name = "routing_map")]
static ROUTING_MAP: RawMap = RawMap::new(
    BPF_MAP_TYPE_ARRAY,
    size_of::<u32>(),
    size_of::<BpfMatchSet>(),
    MAX_MATCH_SET_LEN,
    0,
    PIN_NONE,
);

#[map(name = "domain_routing_map")]
static DOMAIN_ROUTING_MAP: RawMap = RawMap::new(
    BPF_MAP_TYPE_LRU_HASH,
    size_of::<[u32; 4]>(),
    size_of::<BpfDomainRouting>(),
    MAX_DOMAIN_ROUTING_NUM,
    0,
    PIN_NONE,
);

#[map(name = "cookie_pid_map")]
static COOKIE_PID_MAP: RawMap = RawMap::new(
    BPF_MAP_TYPE_LRU_HASH,
    size_of::<u64>(),
    size_of::<BpfPidPname>(),
    MAX_COOKIE_PID_PNAME_MAPPING_NUM,
    0,
    PIN_BY_NAME,
);

#[btf_map(name = "udp_conn_state_map")]
static UDP_CONN_STATE_MAP: BtfMapDef<
    BpfTuplesKey,
    BpfUdpConnState,
    { BPF_MAP_TYPE_HASH as usize },
    { MAX_DST_MAPPING_NUM as usize },
> = BtfMapDef::new();

#[inline(always)]
fn map_ptr(map: &'static RawMap) -> *mut c_void {
    ptr::addr_of!(*map).cast_mut().cast::<c_void>()
}

#[inline(always)]
fn btf_map_ptr<K, V, const TYPE: usize, const MAX_ENTRIES: usize>(
    map: &'static BtfMapDef<K, V, TYPE, MAX_ENTRIES>,
) -> *mut c_void {
    ptr::addr_of!(*map).cast_mut().cast::<c_void>()
}

#[inline(always)]
pub(crate) fn listen_socket_map_ptr() -> *mut c_void {
    map_ptr(&LISTEN_SOCKET_MAP)
}

#[inline(always)]
pub(crate) fn redirect_track_map_ptr() -> *mut c_void {
    map_ptr(&REDIRECT_TRACK)
}

#[inline(always)]
pub(crate) fn tgid_pname_map_ptr() -> *mut c_void {
    map_ptr(&TGID_PNAME_MAP)
}

#[inline(always)]
pub(crate) fn cookie_pid_map_ptr() -> *mut c_void {
    map_ptr(&COOKIE_PID_MAP)
}

#[inline(always)]
pub(crate) fn udp_conn_state_map_ptr() -> *mut c_void {
    btf_map_ptr(&UDP_CONN_STATE_MAP)
}

#[inline(always)]
pub(crate) fn routing_map_ptr() -> *mut c_void {
    map_ptr(&ROUTING_MAP)
}

#[inline(always)]
pub(crate) fn lpm_array_map_ptr() -> *mut c_void {
    map_ptr(&LPM_ARRAY_MAP)
}

#[inline(always)]
pub(crate) fn domain_routing_map_ptr() -> *mut c_void {
    map_ptr(&DOMAIN_ROUTING_MAP)
}

#[inline(always)]
pub(crate) fn routing_tuples_map_ptr() -> *mut c_void {
    map_ptr(&ROUTING_TUPLES_MAP)
}

#[inline(always)]
pub(crate) fn outbound_connectivity_map_ptr() -> *mut c_void {
    map_ptr(&OUTBOUND_CONNECTIVITY_MAP)
}
