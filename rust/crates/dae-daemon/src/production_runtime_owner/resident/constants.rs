#[cfg(not(feature = "native-ebpf"))]
const EMBEDDED_SOURCE_OBJECT: &[u8] = include_bytes!("../../../../../../control/bpf_bpfel.o");
#[cfg(feature = "native-ebpf")]
const EMBEDDED_NATIVE_OBJECT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/dae-native-bpf_bpfel.o"));
const DEFAULT_SOURCE_OBJECT_ENV: &str = "DAE_RUST_BPF_OBJECT";
#[cfg(feature = "native-ebpf")]
const DEFAULT_NATIVE_OBJECT_ENV: &str = "DAE_RUST_NATIVE_BPF_OBJECT";
#[cfg(feature = "native-ebpf")]
const DEFAULT_NATIVE_EBPF_ENV: &str = "DAE_RUST_NATIVE_EBPF";
#[cfg(feature = "native-ebpf")]
const DEFAULT_NATIVE_BACKEND_ENV: &str = "DAE_RUST_NATIVE_EBPF_BACKEND";
const DEFAULT_RESIDENT_DATAPLANE_ENV: &str = "DAE_RUST_RESIDENT_DATAPLANE";
const ROUTING_TUPLES_MAP_NAME: &str = "routing_tuples_map";

#[derive(Clone, Debug, Eq, PartialEq)]
struct RoutingTupleMapDiscovery {
    id: Option<u32>,
    source: &'static str,
    candidate_map_ids: Vec<u32>,
}
