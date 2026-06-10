use std::path::{Path, PathBuf};

#[cfg(feature = "native-ebpf")]
use std::collections::BTreeMap;

#[cfg(feature = "native-ebpf")]
use dae_datapath::{ACTIVE_TCP_LAN_FILTER_PREF, ACTIVE_TCP_LAN_HOST_IFACE};
use dae_ebpf_support::{
    AttachBackend, BpfDaeParam, DaeParamInput, NativeBackendAdmissionEvidence,
    NativeBackendOptInDecision, NativeBackendOptInRequest, TcAttachLayer, build_dae_param,
    native_backend_admission_report, native_backend_opt_in_decision,
};
#[cfg(feature = "native-ebpf")]
use dae_ebpf_support::{
    TcAttachDirection, TcAttachTarget, TcBpfAttachSpec, TcNativeAttachSpec, tc_handle,
};
#[cfg(feature = "native-ebpf")]
use dae_ebpf_support::{
    dae_cgroup_attach_matrix, detect_cgroup2_mount, load_attach_aya_cgroup_program,
};
use serde_json::{Value, json};

use super::ProductionRuntimeOwnerOptions;
use super::command::{mac_string, path_string};
#[cfg(feature = "native-ebpf")]
use super::{FILTER_PREF, PRODUCTION_HOST_IFACE, PRODUCTION_NETNS, PRODUCTION_PEER_IFACE};

pub(super) const EMBEDDED_NATIVE_OBJECT_IDENTITY: &str = "memory:native-ebpf-object";
pub(super) const NATIVE_PARAM_OBJECT_IDENTITY: &str = "memory:native-ebpf-param";
#[cfg(feature = "native-ebpf")]
pub(super) const EMBEDDED_NATIVE_OBJECT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/dae-native-bpf_bpfel.o"));

mod types;
pub(in crate::production_runtime_owner) use self::types::*;
mod attach_backend;
mod attach_flow;
mod map_cleanup;
mod state;
use self::map_cleanup::*;
mod param_backend;
pub(super) use self::param_backend::*;
#[cfg(test)]
mod tests;
#[cfg(test)]
use self::tests::*;
mod attach_specs;
use self::attach_specs::*;
