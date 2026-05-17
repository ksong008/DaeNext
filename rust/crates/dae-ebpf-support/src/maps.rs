#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapSpec {
    pub name: &'static str,
    pub map_type: &'static str,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
    pub pinning: &'static str,
}

pub fn map_catalog() -> &'static [MapSpec] {
    &MAP_CATALOG
}

pub fn pinned_reuse_maps() -> &'static [&'static str] {
    &PINNED_REUSE_MAPS
}

const PINNED_REUSE_MAPS: [&str; 3] = ["cookie_pid_map", "routing_tuples_map", "tgid_pname_map"];

const MAP_CATALOG: [MapSpec; 13] = [
    MapSpec {
        name: ".rodata",
        map_type: "Array",
        key_size: 4,
        value_size: 32,
        max_entries: 1,
        flags: 128,
        pinning: "PinNone",
    },
    MapSpec {
        name: "cookie_pid_map",
        map_type: "LRUHash",
        key_size: 8,
        value_size: 20,
        max_entries: 65536,
        flags: 0,
        pinning: "PinByName",
    },
    MapSpec {
        name: "domain_routing_map",
        map_type: "LRUHash",
        key_size: 16,
        value_size: 128,
        max_entries: 65536,
        flags: 0,
        pinning: "PinNone",
    },
    MapSpec {
        name: "fast_sock",
        map_type: "SockHash",
        key_size: 40,
        value_size: 8,
        max_entries: 65535,
        flags: 0,
        pinning: "PinNone",
    },
    MapSpec {
        name: "listen_socket_map",
        map_type: "SockMap",
        key_size: 4,
        value_size: 8,
        max_entries: 2,
        flags: 0,
        pinning: "PinNone",
    },
    MapSpec {
        name: "lpm_array_map",
        map_type: "ArrayOfMaps",
        key_size: 4,
        value_size: 4,
        max_entries: 1032,
        flags: 0,
        pinning: "PinNone",
    },
    MapSpec {
        name: "outbound_connectivity_map",
        map_type: "Hash",
        key_size: 3,
        value_size: 4,
        max_entries: 1024,
        flags: 0,
        pinning: "PinNone",
    },
    MapSpec {
        name: "redirect_track",
        map_type: "LRUHash",
        key_size: 32,
        value_size: 20,
        max_entries: 65536,
        flags: 0,
        pinning: "PinNone",
    },
    MapSpec {
        name: "routing_map",
        map_type: "Array",
        key_size: 4,
        value_size: 24,
        max_entries: 1024,
        flags: 0,
        pinning: "PinNone",
    },
    MapSpec {
        name: "routing_tuples_map",
        map_type: "LRUHash",
        key_size: 40,
        value_size: 36,
        max_entries: 131072,
        flags: 0,
        pinning: "PinByName",
    },
    MapSpec {
        name: "tgid_pname_map",
        map_type: "LRUHash",
        key_size: 4,
        value_size: 16,
        max_entries: 8192,
        flags: 0,
        pinning: "PinByName",
    },
    MapSpec {
        name: "udp_conn_state_map",
        map_type: "Hash",
        key_size: 40,
        value_size: 24,
        max_entries: 131072,
        flags: 0,
        pinning: "PinNone",
    },
    MapSpec {
        name: "unused_lpm_type",
        map_type: "LPMTrie",
        key_size: 20,
        value_size: 4,
        max_entries: 2048000,
        flags: 1,
        pinning: "PinNone",
    },
];
