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

pub fn protocol_to_string(protocol: u32) -> &'static str {
    match protocol {
        0 => "unspec",
        2 => "kernel",
        3 => "boot",
        4 => "static",
        8 => "gated",
        9 => "ra",
        10 => "mrt",
        11 => "zebra",
        12 => "bird",
        13 => "dnrouted",
        14 => "xorp",
        16 => "dhcp",
        17 => "ntk",
        18 => "dnrouter",
        42 => "babel",
        99 => "mroute",
        186 => "bgp",
        187 => "isis",
        188 => "ospf",
        189 => "rip",
        192 => "eigrp",
        _ => "unknown",
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
