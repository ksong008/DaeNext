#[cfg(not(feature = "native-ebpf"))]
pub(super) const EMBEDDED_SOURCE_OBJECT: &[u8] =
    include_bytes!("../../../../../../control/bpf_bpfel.o");
pub(super) const DEFAULT_SOURCE_OBJECT_ENV: &str = "RESIDENT_BPF_OBJECT";
pub(super) const DEFAULT_SOURCE_OBJECT_LEGACY_ENV: &str = "DAE_RUST_BPF_OBJECT";
#[cfg(feature = "native-ebpf")]
pub(super) const DEFAULT_NATIVE_OBJECT_ENV: &str = "RESIDENT_NATIVE_BPF_OBJECT";
#[cfg(feature = "native-ebpf")]
pub(super) const DEFAULT_NATIVE_OBJECT_LEGACY_ENV: &str = "DAE_RUST_NATIVE_BPF_OBJECT";
#[cfg(feature = "native-ebpf")]
pub(super) const DEFAULT_NATIVE_EBPF_ENV: &str = "RESIDENT_NATIVE_EBPF";
#[cfg(feature = "native-ebpf")]
pub(super) const DEFAULT_NATIVE_EBPF_LEGACY_ENV: &str = "DAE_RUST_NATIVE_EBPF";
#[cfg(feature = "native-ebpf")]
pub(super) const DEFAULT_NATIVE_BACKEND_ENV: &str = "RESIDENT_NATIVE_EBPF_BACKEND";
#[cfg(feature = "native-ebpf")]
pub(super) const DEFAULT_NATIVE_BACKEND_LEGACY_ENV: &str = "DAE_RUST_NATIVE_EBPF_BACKEND";
pub(super) const DEFAULT_RESIDENT_DATAPLANE_ENV: &str = "RESIDENT_DATAPLANE";
pub(super) const DEFAULT_RESIDENT_DATAPLANE_LEGACY_ENV: &str = "DAE_RUST_RESIDENT_DATAPLANE";
pub(super) const COOKIE_PID_MAP_NAME: &str = "cookie_pid_map";
pub(super) const LPM_ARRAY_MAP_NAME: &str = "lpm_array_map";
pub(super) const ROUTING_TUPLES_MAP_NAME: &str = "routing_tuples_map";
pub(super) const TGID_PNAME_MAP_NAME: &str = "tgid_pname_map";
pub(super) const RESIDENT_REUSABLE_MAP_NAMES: [&str; 4] = [
    ROUTING_TUPLES_MAP_NAME,
    COOKIE_PID_MAP_NAME,
    TGID_PNAME_MAP_NAME,
    LPM_ARRAY_MAP_NAME,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ReusableMapDiscovery {
    pub(super) name: &'static str,
    pub(super) id: Option<u32>,
    pub(super) source: &'static str,
    pub(super) candidate_map_ids: Vec<u32>,
}

pub(super) type RoutingTupleMapDiscovery = ReusableMapDiscovery;
