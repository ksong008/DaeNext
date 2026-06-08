use std::{collections::BTreeSet, path::Path};

use dae_ebpf_support::{
    DaeParamInput, TcAttachDirection, TcAttachTarget, TcBpfAttachSpec, TcCommandSpec,
    build_dae_param, write_param_aware_object,
};
use serde_json::{Value, json};

use super::command::{
    CommandSpec, command_exists, iface_exists, mac_string, netns_exists, parse_step_mac,
    parse_step_u32, path_string, push_check, run_observation_step, run_step, tproxy_port_available,
};
use super::native_ebpf::{NativeEbpfAttachRole, NativeEbpfRuntimeState};
use super::netns_link::{
    NetnsLinkMode, cleanup_partial_link_setup, create_link_pair, netns_link_env_name,
    setup_link_pair_with_auto_fallback,
};
use super::{
    FILTER_PREF, PRODUCTION_HOST_IFACE, PRODUCTION_NETNS, PRODUCTION_PEER_IFACE,
    ProductionRuntimeOwnerOptions,
};

mod netns_setup;
pub(super) use self::netns_setup::*;
mod ipv4_datapath;
pub(super) use self::ipv4_datapath::*;
mod read_values;
pub(super) use self::read_values::*;
mod param_image;
pub(super) use self::param_image::*;
#[cfg(test)]
mod tests;
#[cfg(test)]
use self::tests::*;
mod attach_show;
pub(super) use self::attach_show::*;
mod cleanup;
pub(super) use self::cleanup::*;
mod preflight;
pub(super) use self::preflight::*;
