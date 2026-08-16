pub fn scope_to_string(scope: u32) -> &'static str {
    match scope {
        0 => "universe",
        200 => "site",
        253 => "link",
        254 => "host",
        255 => "nowhere",
        _ => "unknown",
    }
}

/// Render a kernel route protocol (RTPROT_*) value the way `ip route show
/// protocol` does.
///
/// The 0..=16 range follows Linux `include/uapi/linux/rtnetlink.h`: RTPROT_
/// UNSPEC(0), REDIRECT(1), KERNEL(2), BOOT(3), STATIC(4), GATED(8), RA(9),
/// MRT(10), ZEBRA(11), BIRD(12), DNROUTED(13), XORP(14), NTK(15), DHCP(16).
/// 17 is the RTPROT_NRTPROT sentinel (count of kernel-defined protocols), not
/// a protocol name; 18 and 99 are not kernel RTPROT constants. The daemon
/// protocol values 42/186/187/188/189/192 (babel/bgp/isis/ospf/rip/eigrp) are
/// standardized by iproute2's rt_protos table and are kept. Any other value
/// is rendered as its decimal string instead of "unknown" so the raw kernel
/// value survives round-trips through the sysdump.
pub fn protocol_to_string(protocol: u32) -> String {
    match protocol {
        0 => "unspec".to_owned(),
        1 => "redirect".to_owned(),
        2 => "kernel".to_owned(),
        3 => "boot".to_owned(),
        4 => "static".to_owned(),
        8 => "gated".to_owned(),
        9 => "ra".to_owned(),
        10 => "mrt".to_owned(),
        11 => "zebra".to_owned(),
        12 => "bird".to_owned(),
        13 => "dnrouted".to_owned(),
        14 => "xorp".to_owned(),
        15 => "ntk".to_owned(),
        16 => "dhcp".to_owned(),
        42 => "babel".to_owned(),
        186 => "bgp".to_owned(),
        187 => "isis".to_owned(),
        188 => "ospf".to_owned(),
        189 => "rip".to_owned(),
        192 => "eigrp".to_owned(),
        _ => protocol.to_string(),
    }
}

pub fn route_type_to_string(route_type: u32) -> &'static str {
    match route_type {
        0 => "unspec",
        1 => "unicast",
        2 => "local",
        3 => "broadcast",
        4 => "anycast",
        5 => "multicast",
        6 => "blackhole",
        7 => "unreachable",
        8 => "prohibit",
        9 => "throw",
        10 => "nat",
        11 => "xresolve",
        _ => "unknown",
    }
}
