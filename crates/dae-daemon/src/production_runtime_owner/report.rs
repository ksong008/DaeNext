use std::path::Path;

use dae_ebpf_support::{
    AttachBackend, EbpfBackendCapabilityReport, LiveLoadedTproxyListenSocketMap, LoaderBackend,
    NativeBackendAdmissionEvidence, NativeBackendAdmissionReport, TproxySocketOptions,
    dae_cgroup_attach_matrix, native_backend_admission_report, report_only_ebpf_backend_capability,
};
use serde_json::{Map, Value, json};

use super::command::path_string;
use super::deep_area;
use super::native_assets;
use super::native_ebpf::{
    native_backend_runtime_decision_for_options, native_backend_runtime_decision_json,
};
use super::udp_dns_datapath_contract::udp_dns_datapath_contract_json;
use super::{
    ExecutionEvidence, FILTER_PREF, PRODUCTION_HOST_IFACE, PRODUCTION_NETNS, PRODUCTION_PEER_IFACE,
    ProductionRuntimeOwnerOptions, active_udp_loopback_target_cidr,
};

mod typed_report;
use self::typed_report::*;
mod report_value;
pub(super) use self::report_value::*;
mod ebpf_backend;
use self::ebpf_backend::*;
mod admission_json;
use self::admission_json::*;
mod live_handoff;
pub(super) use self::live_handoff::*;
