use core::ffi::c_void;

use aya_ebpf::{
    helpers::bpf_get_func_ip,
    macros::map,
    maps::{HashMap, RingBuf},
    programs::ProbeContext,
};

const SKB_ADDRESS_MAX_ENTRIES: u32 = 1024;
const EVENTS_DEFAULT_BYTES: u32 = 1 << 29;
const IFNAMSIZ: usize = 16;
const PNAME_LEN: usize = 32;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TraceAddr {
    pub bytes: [u8; 16],
}

impl TraceAddr {
    pub const fn zeroed() -> Self {
        Self { bytes: [0; 16] }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TraceMeta {
    pub pc: u64,
    pub skb: u64,
    pub second_param: u64,
    pub mark: u32,
    pub netns: u32,
    pub ifindex: u32,
    pub pid: u32,
    pub ifname: [u8; IFNAMSIZ],
    pub pname: [u8; PNAME_LEN],
}

impl TraceMeta {
    pub const fn zeroed() -> Self {
        Self {
            pc: 0,
            skb: 0,
            second_param: 0,
            mark: 0,
            netns: 0,
            ifindex: 0,
            pid: 0,
            ifname: [0; IFNAMSIZ],
            pname: [0; PNAME_LEN],
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TraceTuple {
    pub saddr: TraceAddr,
    pub daddr: TraceAddr,
    pub sport: u16,
    pub dport: u16,
    pub l3_proto: u16,
    pub l4_proto: u8,
    pub tcp_flags: u8,
    pub payload_len: u16,
}

impl TraceTuple {
    pub const fn zeroed() -> Self {
        Self {
            saddr: TraceAddr::zeroed(),
            daddr: TraceAddr::zeroed(),
            sport: 0,
            dport: 0,
            l3_proto: 0,
            l4_proto: 0,
            tcp_flags: 0,
            payload_len: 0,
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TraceEvent {
    pub meta: TraceMeta,
    pub tuple: TraceTuple,
}

impl TraceEvent {
    pub const fn zeroed() -> Self {
        Self {
            meta: TraceMeta::zeroed(),
            tuple: TraceTuple::zeroed(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TracingConfig {
    pub port: u16,
    pub l4_proto: u16,
    pub ip_vsn: u8,
    pub pad: u8,
}

impl TracingConfig {
    pub const fn zeroed() -> Self {
        Self {
            port: 0,
            l4_proto: 0,
            ip_vsn: 0,
            pad: 0,
        }
    }
}

#[unsafe(no_mangle)]
#[used]
pub static tracing_cfg: TracingConfig = TracingConfig::zeroed();

#[map(name = "skb_addresses")]
static SKB_ADDRESSES: HashMap<u64, u8> = HashMap::with_max_entries(SKB_ADDRESS_MAX_ENTRIES, 0);

#[map(name = "events")]
static EVENTS: RingBuf = RingBuf::with_byte_size(EVENTS_DEFAULT_BYTES, 0);

#[unsafe(no_mangle)]
#[unsafe(link_section = "kprobe/skb-1")]
pub extern "C" fn kprobe_skb_1(ctx: *mut c_void) -> i32 {
    trace_skb_arg(ctx, 1)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "kprobe/skb-2")]
pub extern "C" fn kprobe_skb_2(ctx: *mut c_void) -> i32 {
    trace_skb_arg(ctx, 2)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "kprobe/skb-3")]
pub extern "C" fn kprobe_skb_3(ctx: *mut c_void) -> i32 {
    trace_skb_arg(ctx, 3)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "kprobe/skb-4")]
pub extern "C" fn kprobe_skb_4(ctx: *mut c_void) -> i32 {
    trace_skb_arg(ctx, 4)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "kprobe/skb-5")]
pub extern "C" fn kprobe_skb_5(ctx: *mut c_void) -> i32 {
    trace_skb_arg(ctx, 5)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "kprobe/skb_lifetime_termination")]
pub extern "C" fn kprobe_skb_lifetime_termination(ctx: *mut c_void) -> i32 {
    let ctx = ProbeContext::new(ctx);
    let skb_addr = match ctx.arg::<usize>(0) {
        Some(addr) => addr as u64,
        None => return 0,
    };
    let _ = SKB_ADDRESSES.remove(&skb_addr);
    0
}

#[inline(always)]
fn trace_skb_arg(ctx: *mut c_void, skb_arg_position: u8) -> i32 {
    let probe = ProbeContext::new(ctx);
    let arg_index = (skb_arg_position - 1) as usize;
    let skb_addr = match probe.arg::<usize>(arg_index) {
        Some(addr) if addr != 0 => addr as u64,
        _ => return 0,
    };

    let tracked = unsafe { SKB_ADDRESSES.get(&skb_addr).is_some() };
    if !tracked {
        let present = 1_u8;
        let _ = SKB_ADDRESSES.insert(&skb_addr, &present, 0);
    }

    let mut event = TraceEvent::zeroed();
    event.meta.pc = unsafe { bpf_get_func_ip(ctx) };
    event.meta.skb = skb_addr;
    event.meta.second_param = probe.arg::<usize>(1).unwrap_or_default() as u64;
    let _ = EVENTS.output(&event, 0);
    0
}
