use std::path::{Path, PathBuf};

#[cfg(feature = "native-ebpf")]
use std::collections::BTreeMap;

#[cfg(feature = "native-ebpf")]
use dae_datapath::{ACTIVE_TCP_LAN_FILTER_PREF, ACTIVE_TCP_LAN_HOST_IFACE};
use dae_ebpf_support::{
    AttachBackend, DaeParamInput, NativeBackendAdmissionEvidence, NativeBackendOptInDecision,
    NativeBackendOptInRequest, TcAttachLayer, build_dae_param, native_backend_admission_report,
    native_backend_opt_in_decision, write_param_aware_object,
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

mod types;
pub(in crate::production_runtime_owner) use self::types::*;
mod state;
use self::state::*;
mod attach_flow;
use self::attach_flow::*;
mod attach_backend;
use self::attach_backend::*;
mod map_cleanup;
use self::map_cleanup::*;
mod param_backend;
pub(super) use self::param_backend::*;
#[cfg(test)]
mod tests;
#[cfg(test)]
use self::tests::*;
mod attach_specs;
use self::attach_specs::*;
