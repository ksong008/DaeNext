use std::path::{Path, PathBuf};

#[cfg(feature = "native-ebpf")]
use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "native-ebpf")]
use dae_datapath::{ACTIVE_TCP_LAN_FILTER_PREF, ACTIVE_TCP_LAN_HOST_IFACE};
use dae_ebpf_support::{
    AttachBackend, BpfDaeParam, DaeParamInput, NativeBackendAdmissionEvidence,
    NativeBackendRuntimeDecision, NativeBackendRuntimeRequest, RuntimeMapProfile, TcAttachLayer,
    build_dae_param, native_backend_admission_report, native_backend_runtime_decision,
};
#[cfg(feature = "native-ebpf")]
use dae_ebpf_support::{
    AyaCgroupAttachPreflightReport, dae_cgroup_attach_matrix, detect_cgroup2_mount,
    load_attach_aya_cgroup_program, preflight_aya_cgroup_programs,
};
#[cfg(feature = "native-ebpf")]
use dae_ebpf_support::{
    TcAttachDirection, TcAttachTarget, TcBpfAttachSpec, TcNativeAttachSpec, tc_handle,
};
use serde_json::{Value, json};

use super::ProductionRuntimeOwnerOptions;
use super::command::{mac_string, path_string};
#[cfg(feature = "native-ebpf")]
use super::{FILTER_PREF, PRODUCTION_HOST_IFACE, PRODUCTION_NETNS, PRODUCTION_PEER_IFACE};

pub(super) const EMBEDDED_NATIVE_OBJECT_IDENTITY: &str = "memory:native-ebpf-object";
pub(super) const EMBEDDED_NATIVE_OBJECT_PNAME_CORE_IDENTITY: &str =
    "memory:native-ebpf-object-pname-core";
pub(super) const NATIVE_PARAM_OBJECT_IDENTITY: &str = "memory:native-ebpf-param";

mod types;
pub(in crate::production_runtime_owner) use self::types::*;
mod map_profile;
use self::map_profile::*;
mod attach_backend;
mod attach_flow;
mod cgroup;
pub(in crate::production_runtime_owner) use self::cgroup::native_cgroup_attach_preflight;
mod map_cleanup;
mod state;
#[cfg(any(feature = "native-ebpf", test))]
use self::map_cleanup::*;
#[cfg(feature = "native-ebpf")]
use self::state::current_comm_pname_report;
mod param_backend;
pub(super) use self::param_backend::*;
mod attach_specs;
#[cfg(test)]
mod tests;
#[cfg(feature = "native-ebpf")]
use self::attach_specs::*;
