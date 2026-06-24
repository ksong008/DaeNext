use super::*;

// These names are domain-visible attach roles and intentionally include direction.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner) enum NativeEbpfAttachRole {
    PeerIngress,
    LanIngress,
    HostIngress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner) enum NativeInterfaceAttachRole {
    LanEgress,
    WanIngress,
    WanEgress,
}

impl NativeInterfaceAttachRole {
    pub(in crate::production_runtime_owner) const fn as_str(self) -> &'static str {
        match self {
            Self::LanEgress => "lan_egress",
            Self::WanIngress => "wan_ingress",
            Self::WanEgress => "wan_egress",
        }
    }

    #[cfg(feature = "native-ebpf")]
    pub(super) const fn direction(self) -> TcAttachDirection {
        match self {
            Self::LanEgress | Self::WanEgress => TcAttachDirection::Egress,
            Self::WanIngress => TcAttachDirection::Ingress,
        }
    }

    #[cfg(feature = "native-ebpf")]
    pub(super) const fn priority(self) -> u16 {
        match self {
            Self::LanEgress | Self::WanIngress => 1,
            Self::WanEgress => 2,
        }
    }

    #[cfg(feature = "native-ebpf")]
    pub(super) const fn handle_minor(self) -> u16 {
        match self {
            Self::LanEgress | Self::WanIngress => 0b010,
            Self::WanEgress => 0b100,
        }
    }
}

impl NativeEbpfAttachRole {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::PeerIngress => "peer_ingress",
            Self::LanIngress => "lan_ingress",
            Self::HostIngress => "host_ingress",
        }
    }

    pub(super) const fn decision_step_name(self) -> &'static str {
        match self {
            Self::PeerIngress => "native-ebpf-peer-runtime-decision",
            Self::LanIngress => "native-ebpf-lan-runtime-decision",
            Self::HostIngress => "native-ebpf-host-runtime-decision",
        }
    }

    pub(super) const fn attach_step_name(self) -> &'static str {
        match self {
            Self::PeerIngress => "attach-production-dae0peer-native-ebpf-program",
            Self::LanIngress => "attach-lan-ingress-native-ebpf-program",
            Self::HostIngress => "attach-production-dae0-native-ebpf-program",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner) struct NativeAttachOutcome {
    pub ok: bool,
    pub backend: AttachBackend,
    pub backend_switch_used: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner) struct NativeEbpfLoadInput {
    pub param: BpfDaeParam,
}

#[derive(Clone, Debug, PartialEq)]
pub(in crate::production_runtime_owner) struct NativeParamObjectPreparation {
    pub selected_param_object: PathBuf,
    pub report: Value,
    pub load_input: Option<NativeEbpfLoadInput>,
}

#[derive(Default)]
pub(in crate::production_runtime_owner) struct NativeEbpfRuntimeState {
    pub(super) peer_attached: bool,
    pub(super) lan_attached: bool,
    pub(super) host_attached: bool,
    pub(super) cgroup_attached: bool,
    #[cfg(feature = "native-ebpf")]
    pub(super) loaded: Option<dae_ebpf_support::AyaUserspaceLoadedObject>,
    #[cfg(feature = "native-ebpf")]
    pub(super) loaded_map_ids: BTreeMap<String, u32>,
    #[cfg(feature = "native-ebpf")]
    pub(super) pin_root: Option<PathBuf>,
    #[cfg(feature = "native-ebpf")]
    pub(super) load_input: Option<NativeEbpfLoadInput>,
    #[cfg(feature = "native-ebpf")]
    pub(super) pname_report: Option<Value>,
}

impl std::fmt::Debug for NativeEbpfRuntimeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("NativeEbpfRuntimeState");
        debug
            .field("peer_attached", &self.peer_attached)
            .field("lan_attached", &self.lan_attached)
            .field("host_attached", &self.host_attached)
            .field("cgroup_attached", &self.cgroup_attached);
        #[cfg(feature = "native-ebpf")]
        debug
            .field("loaded", &self.loaded.is_some())
            .field("loaded_map_ids", &self.loaded_map_ids)
            .field("pin_root", &self.pin_root)
            .field("load_input", &self.load_input)
            .field("pname_report", &self.pname_report);
        debug.finish()
    }
}
