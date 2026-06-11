use super::*;
pub(super) const BPF_MAP_CREATE: libc::c_uint = 0;
pub(super) const BPF_OBJ_PIN: libc::c_uint = 6;
pub(super) const BPF_MAP_TYPE_LPM_TRIE: u32 = 11;
pub(super) const BPF_MAP_TYPE_ARRAY_OF_MAPS: u32 = 12;
pub(super) const BPF_F_NO_PREALLOC: u32 = 1;
pub(super) const LPM_ARRAY_MAP_NAME: &str = "lpm_array_map";
pub(super) const UNUSED_LPM_TYPE_NAME: &str = "unused_lpm_type";
pub const DEFAULT_ALLOWED_UNSUPPORTED_MAP_NAMES: &[&str] = &[LPM_ARRAY_MAP_NAME];
pub const TRACE_CORE_SIDELOAD_ENABLED: bool = false;

// SAFETY: BpfDaeParam is #[repr(C)], Copy, contains only integer/byte-array fields,
// and its explicit padding byte is initialized by build_dae_param before Aya global use.
unsafe impl aya::Pod for BpfDaeParam {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaUserspaceLoaderOptions<'a> {
    pub object: &'a Path,
    pub param: Option<BpfDaeParam>,
    pub map_pin_path: Option<&'a Path>,
    pub allow_unsupported_maps: bool,
    pub allowed_unsupported_map_names: &'a [&'a str],
    pub max_entries_overrides: &'a [(&'a str, u32)],
    pub prepin_lpm_array_map: bool,
}

impl<'a> AyaUserspaceLoaderOptions<'a> {
    pub fn new(object: &'a Path) -> Self {
        Self {
            object,
            param: None,
            map_pin_path: None,
            allow_unsupported_maps: true,
            allowed_unsupported_map_names: DEFAULT_ALLOWED_UNSUPPORTED_MAP_NAMES,
            max_entries_overrides: &[],
            prepin_lpm_array_map: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaUserspaceBytesLoaderOptions<'a> {
    pub object_label: &'a str,
    pub object_data: &'a [u8],
    pub param: Option<BpfDaeParam>,
    pub map_pin_path: Option<&'a Path>,
    pub allow_unsupported_maps: bool,
    pub allowed_unsupported_map_names: &'a [&'a str],
    pub max_entries_overrides: &'a [(&'a str, u32)],
    pub prepin_lpm_array_map: bool,
}

impl<'a> AyaUserspaceBytesLoaderOptions<'a> {
    pub fn new(object_label: &'a str, object_data: &'a [u8]) -> Self {
        Self {
            object_label,
            object_data,
            param: None,
            map_pin_path: None,
            allow_unsupported_maps: true,
            allowed_unsupported_map_names: DEFAULT_ALLOWED_UNSUPPORTED_MAP_NAMES,
            max_entries_overrides: &[],
            prepin_lpm_array_map: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaMapInMapPinReport {
    pub outer_map_name: &'static str,
    pub inner_template_name: &'static str,
    pub pin_path: PathBuf,
    pub outer_max_entries: u32,
    pub inner_max_entries: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaUserspaceLoadReport {
    pub object: PathBuf,
    pub param_global_set: bool,
    pub map_pin_path: Option<PathBuf>,
    pub allow_unsupported_maps: bool,
    pub allowed_unsupported_map_names: Vec<String>,
    pub loaded_map_names: Vec<String>,
    pub loaded_map_specs: Vec<AyaLoadedMapSpec>,
    pub loaded_program_names: Vec<String>,
    pub max_entries_overrides: Vec<(String, u32)>,
    pub map_in_map_pins: Vec<AyaMapInMapPinReport>,
    pub missing_catalog_maps: Vec<&'static str>,
    pub map_spec_mismatches: Vec<AyaMapSpecMismatch>,
    pub unsupported_map_names: Vec<String>,
    pub unexpected_unsupported_map_names: Vec<String>,
    pub pinned_reuse_maps_present: Vec<String>,
    pub listen_socket_map_present: bool,
    pub loader_backend: LoaderBackend,
    pub default_attach_backend: AttachBackend,
    pub external_ebpf_object_required: bool,
    pub command_attach_backend_required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaLoadedMapSpec {
    pub name: String,
    pub map_type: String,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
    pub unsupported: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaMapSpecMismatch {
    pub name: String,
    pub field: &'static str,
    pub expected: String,
    pub actual: String,
}

pub struct AyaUserspaceLoadedObject {
    pub ebpf: aya::Ebpf,
    pub report: AyaUserspaceLoadReport,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AyaTraceConfig {
    pub port: u16,
    pub l4_proto: u16,
    pub ip_version: u8,
    pub pad: u8,
}

// SAFETY: AyaTraceConfig is #[repr(C)], Copy, contains only integer fields,
// and all trace loader constructors initialize the explicit padding byte.
unsafe impl aya::Pod for AyaTraceConfig {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaTraceLoaderOptions<'a> {
    pub object: &'a Path,
    pub pin_root: &'a Path,
    pub port: u16,
    pub l4_proto: u16,
    pub ip_version: u8,
    pub ringbuf_size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaTraceLoadPinReport {
    pub object: PathBuf,
    pub pin_root: PathBuf,
    pub map_pin_root: PathBuf,
    pub program_pin_root: PathBuf,
    pub maps: Vec<AyaPinnedObject>,
    pub programs: Vec<AyaPinnedObject>,
    pub port: u16,
    pub l4_proto: u16,
    pub ip_version: u8,
    pub ringbuf_size: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AyaTraceAttachSmokeTrigger {
    LoopbackUdp,
    OpenProcSelfStat,
}

impl AyaTraceAttachSmokeTrigger {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LoopbackUdp => "loopback-udp",
            Self::OpenProcSelfStat => "open-proc-self-stat",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaTraceAttachRingbufSmokeOptions<'a> {
    pub object: &'a Path,
    pub target: &'a str,
    pub program_name: &'a str,
    pub port: u16,
    pub l4_proto: u16,
    pub ip_version: u8,
    pub ringbuf_size: u32,
    pub trigger: AyaTraceAttachSmokeTrigger,
    pub trigger_count: u32,
    pub poll_attempts: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaTraceAttachRingbufSmokeReport {
    pub object: PathBuf,
    pub target: String,
    pub program_name: String,
    pub trigger: AyaTraceAttachSmokeTrigger,
    pub trigger_count: u32,
    pub poll_attempts: u32,
    pub events_seen: u32,
    pub first_event_len: usize,
    pub first_event_pc_nonzero: bool,
    pub first_event_skb_nonzero: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaPinnedObject {
    pub name: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaNativeRuntimePinReport {
    pub native_pin_root: PathBuf,
    pub map_pin_root: PathBuf,
    pub program_pin_root: PathBuf,
    pub maps: Vec<AyaPinnedObject>,
    pub programs: Vec<AyaPinnedObject>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaTcxProgramOrderEntry {
    pub id: u32,
    pub name: Option<String>,
    pub tag: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaTcAttachDetachReport {
    pub requested_backend: AttachBackend,
    pub backend: AttachBackend,
    pub backend_switch_used: bool,
    pub backend_switch_error: Option<String>,
    pub program_id: Option<u32>,
    pub program_name: String,
    pub iface: String,
    pub netns: Option<String>,
    pub netns_entered: bool,
    pub direction: TcAttachDirection,
    pub priority: u16,
    pub handle: u32,
    pub tcx_order: TcxAttachOrder,
    pub tcx_query_revision: Option<u64>,
    pub tcx_program_order: Vec<AyaTcxProgramOrderEntry>,
    pub tcx_query_error: Option<String>,
    pub tcx_order_verified: bool,
    pub tcx_order_error: Option<String>,
    pub clsact_added_or_present: bool,
    pub loaded: bool,
    pub attached: bool,
    pub detached: bool,
    pub link_lifetime_owned_by_backend: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedTcAttachOptions<'a> {
    pub program_root: &'a Path,
    pub link_root: &'a Path,
    pub spec: &'a TcNativeAttachSpec,
    pub requested_backend: AttachBackend,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedTcAttachReport {
    pub requested_backend: AttachBackend,
    pub backend: AttachBackend,
    pub backend_switch_used: bool,
    pub backend_switch_error: Option<String>,
    pub program_id: Option<u32>,
    pub program_name: String,
    pub program_path: PathBuf,
    pub iface: String,
    pub netns: Option<String>,
    pub netns_entered: bool,
    pub direction: TcAttachDirection,
    pub priority: u16,
    pub handle: u32,
    pub tcx_order: TcxAttachOrder,
    pub tcx_query_revision: Option<u64>,
    pub tcx_program_order: Vec<AyaTcxProgramOrderEntry>,
    pub tcx_order_verified: bool,
    pub link_path: Option<PathBuf>,
    pub tc_filter_persistent: bool,
    pub clsact_added_or_present: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaCgroupAttachDetachReport {
    pub role: crate::DaeCgroupAttachRole,
    pub cgroup_path: PathBuf,
    pub program_name: String,
    pub section: String,
    pub program_kind: DaeCgroupProgramKind,
    pub attach_mode: String,
    pub loaded: bool,
    pub attached: bool,
    pub detached: bool,
    pub link_lifetime_owned_by_backend: bool,
}
