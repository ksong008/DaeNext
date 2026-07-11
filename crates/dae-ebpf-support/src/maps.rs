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

mod profile;
pub use profile::*;

impl MapSpec {
    pub fn role(self) -> RuntimeMapRole {
        RuntimeMapRole::for_map_name(self.name)
    }

    pub fn pinned_by_name(self) -> bool {
        self.pinning == "PinByName"
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeMapRole {
    ParamRodata,
    PinnedReuse,
    SocketHandoff,
    Routing,
    Connectivity,
    Tracking,
    DomainRouting,
    UdpState,
    Observability,
    InnerMapCatalog,
    Other,
}

impl RuntimeMapRole {
    pub const fn for_map_name(name: &str) -> Self {
        match name.as_bytes() {
            b".rodata" => Self::ParamRodata,
            b"cookie_pid_map" | b"routing_tuples_map" => Self::PinnedReuse,
            b"listen_socket_map" => Self::SocketHandoff,
            b"routing_map" => Self::Routing,
            b"outbound_connectivity_map" => Self::Connectivity,
            b"redirect_track" => Self::Tracking,
            b"domain_routing_map" => Self::DomainRouting,
            b"udp_conn_state_map" => Self::UdpState,
            b"udp_state_metrics" => Self::Observability,
            b"lpm_array_map" | b"unused_lpm_type" => Self::InnerMapCatalog,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeMapContract {
    pub spec: MapSpec,
    pub role: RuntimeMapRole,
    pub reusable_pin: bool,
}

pub fn map_catalog() -> &'static [MapSpec] {
    &MAP_CATALOG
}

pub fn pinned_reuse_maps() -> &'static [&'static str] {
    &PINNED_REUSE_MAPS
}

pub fn runtime_map_contract() -> Vec<RuntimeMapContract> {
    MAP_CATALOG
        .iter()
        .copied()
        .map(|spec| RuntimeMapContract {
            spec,
            role: spec.role(),
            reusable_pin: PINNED_REUSE_MAPS.contains(&spec.name),
        })
        .collect()
}

const PINNED_REUSE_MAPS: [&str; 2] = ["cookie_pid_map", "routing_tuples_map"];

const MAP_CATALOG: [MapSpec; 12] = [
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
        value_size: 36,
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
        name: "listen_socket_map",
        map_type: "SockMap",
        key_size: 4,
        value_size: 8,
        max_entries: 4,
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
        pinning: "PinByName",
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
        key_size: 48,
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
        name: "udp_conn_state_map",
        map_type: "Hash",
        key_size: 40,
        value_size: 24,
        max_entries: 131072,
        flags: 0,
        pinning: "PinNone",
    },
    MapSpec {
        name: "udp_state_metrics",
        map_type: "PerCpuArray",
        key_size: 4,
        value_size: 56,
        max_entries: 1,
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
