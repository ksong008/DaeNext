use crate::kernel::Version;

pub const TCX_ATTACH_FEATURE_VERSION: Version = Version::new(6, 6, 0);
pub const ETH_P_ALL: u16 = 0x0003;
const DAE_TC_HANDLE_MAJOR: u16 = 0x2022;
const IFACE_TC_HANDLE_MAJOR: u16 = 0x2023;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachBackend {
    Auto,
    TcCommandFallback,
    TcNetlink,
    Tcx,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachBackendAvailability {
    pub tcx: bool,
    pub tc_netlink: bool,
    pub tc_command_fallback: bool,
}

impl AttachBackendAvailability {
    pub const fn command_fallback_only() -> Self {
        Self {
            tcx: false,
            tc_netlink: false,
            tc_command_fallback: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachBackendPlan {
    pub requested: AttachBackend,
    pub kernel_version: Option<Version>,
    pub tcx_supported: bool,
    pub attempt_order: Vec<AttachBackend>,
    pub selected: Option<AttachBackend>,
    pub command_fallback_used: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcNativeAttachSpec {
    pub target: TcAttachTarget,
    pub object: String,
    pub section: String,
    pub program_name: String,
    pub priority: u16,
    pub handle: u32,
    pub protocol: u16,
    pub direct_action: bool,
    pub clsact_required: bool,
    pub netns_enter_required: bool,
    pub link_lifetime_owned_by_backend: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcAttachBackendReport {
    pub plan: AttachBackendPlan,
    pub native_spec: TcNativeAttachSpec,
    pub effective_backend: Option<AttachBackend>,
    pub default_native_backend_enabled: bool,
    pub native_backend_capable: bool,
    pub tcx_attempted: bool,
    pub tc_netlink_attempted: bool,
    pub command_fallback_attempted: bool,
    pub command_fallback_required: bool,
    pub command_fallback_spec: TcCommandSpec,
    pub cleanup_fallback_spec: TcCommandSpec,
    pub show_fallback_spec: TcCommandSpec,
}

pub fn plan_attach_backend(
    requested: AttachBackend,
    kernel_version: Option<Version>,
    availability: AttachBackendAvailability,
) -> AttachBackendPlan {
    let tcx_supported = kernel_version
        .map(|version| version >= TCX_ATTACH_FEATURE_VERSION)
        .unwrap_or(false);
    let attempt_order = match requested {
        AttachBackend::Auto => {
            let mut order = Vec::new();
            if tcx_supported {
                order.push(AttachBackend::Tcx);
            }
            order.push(AttachBackend::TcNetlink);
            order.push(AttachBackend::TcCommandFallback);
            order
        }
        backend => vec![backend],
    };
    let selected = attempt_order.iter().copied().find(|backend| match backend {
        AttachBackend::Auto => false,
        AttachBackend::Tcx => tcx_supported && availability.tcx,
        AttachBackend::TcNetlink => availability.tc_netlink,
        AttachBackend::TcCommandFallback => availability.tc_command_fallback,
    });
    AttachBackendPlan {
        requested,
        kernel_version,
        tcx_supported,
        attempt_order,
        selected,
        command_fallback_used: selected == Some(AttachBackend::TcCommandFallback),
    }
}

pub const fn tc_handle(major: u16, minor: u16) -> u32 {
    ((major as u32) << 16) | minor as u32
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcAttachSectionPrefix {
    Tc,
    Classifier,
}

impl TcAttachSectionPrefix {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tc => "tc",
            Self::Classifier => "classifier",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcAttachLayer {
    L2,
    L3,
}

impl TcAttachLayer {
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::L2 => "l2",
            Self::L3 => "l3",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaeTcAttachRole {
    LanIngress,
    LanEgress,
    WanIngress,
    WanEgress,
    Dae0peerIngress,
    Dae0Ingress,
}

impl DaeTcAttachRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LanIngress => "lan_ingress",
            Self::LanEgress => "lan_egress",
            Self::WanIngress => "wan_ingress",
            Self::WanEgress => "wan_egress",
            Self::Dae0peerIngress => "dae0peer_ingress",
            Self::Dae0Ingress => "dae0_ingress",
        }
    }

    const fn has_link_layer_variant(self) -> bool {
        matches!(
            self,
            Self::LanIngress | Self::LanEgress | Self::WanIngress | Self::WanEgress
        )
    }

    const fn direction(self) -> TcAttachDirection {
        match self {
            Self::LanIngress | Self::WanIngress | Self::Dae0peerIngress | Self::Dae0Ingress => {
                TcAttachDirection::Ingress
            }
            Self::LanEgress | Self::WanEgress => TcAttachDirection::Egress,
        }
    }

    const fn priority(self) -> u16 {
        match self {
            Self::LanIngress | Self::WanEgress => 2,
            Self::LanEgress | Self::WanIngress => 1,
            Self::Dae0peerIngress | Self::Dae0Ingress => 0,
        }
    }

    const fn handle_major(self) -> u16 {
        match self {
            Self::LanIngress | Self::LanEgress | Self::WanIngress | Self::WanEgress => {
                IFACE_TC_HANDLE_MAJOR
            }
            Self::Dae0peerIngress | Self::Dae0Ingress => DAE_TC_HANDLE_MAJOR,
        }
    }

    const fn handle_minor_base(self) -> u16 {
        match self {
            Self::LanIngress | Self::WanEgress => 0b100,
            Self::LanEgress | Self::WanIngress | Self::Dae0peerIngress | Self::Dae0Ingress => 0b010,
        }
    }

    fn source_uses_flipped_cleanup_on_fresh_start(self) -> bool {
        // control_plane_core.go computes a flipped peer cleanup filter but
        // currently deletes the original dae0peer filter in that branch.
        self != Self::Dae0peerIngress
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaeTcAttachMatrixInput {
    pub object: String,
    pub lan_iface: String,
    pub wan_iface: String,
    pub host_iface: String,
    pub peer_iface: String,
    pub peer_netns: String,
    pub section_prefix: TcAttachSectionPrefix,
    pub link_layer: TcAttachLayer,
    pub flip: u16,
    pub is_reload: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaeTcAttachLine {
    pub role: DaeTcAttachRole,
    pub go_filter_name: String,
    pub attach: TcBpfAttachSpec,
    pub native: TcNativeAttachSpec,
    pub stale_cleanup_handle_on_fresh_start: Option<u32>,
}

pub fn dae_tc_attach_matrix(input: DaeTcAttachMatrixInput) -> Vec<DaeTcAttachLine> {
    [
        DaeTcAttachRole::LanIngress,
        DaeTcAttachRole::LanEgress,
        DaeTcAttachRole::WanIngress,
        DaeTcAttachRole::WanEgress,
        DaeTcAttachRole::Dae0peerIngress,
        DaeTcAttachRole::Dae0Ingress,
    ]
    .into_iter()
    .map(|role| dae_tc_attach_line(&input, role))
    .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcAttachDirection {
    Ingress,
    Egress,
}

impl TcAttachDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        }
    }
}

fn dae_tc_attach_line(input: &DaeTcAttachMatrixInput, role: DaeTcAttachRole) -> DaeTcAttachLine {
    let target = match role {
        DaeTcAttachRole::LanIngress | DaeTcAttachRole::LanEgress => {
            TcAttachTarget::host(input.lan_iface.clone(), role.direction())
        }
        DaeTcAttachRole::WanIngress | DaeTcAttachRole::WanEgress => {
            TcAttachTarget::host(input.wan_iface.clone(), role.direction())
        }
        DaeTcAttachRole::Dae0Ingress => {
            TcAttachTarget::host(input.host_iface.clone(), role.direction())
        }
        DaeTcAttachRole::Dae0peerIngress => TcAttachTarget::netns(
            input.peer_netns.clone(),
            input.peer_iface.clone(),
            role.direction(),
        ),
    };
    let suffix = if role.has_link_layer_variant() {
        format!("_{}", input.link_layer.suffix())
    } else {
        String::new()
    };
    let section_name = format!("{}{}", role.as_str(), suffix);
    let section = format!("{}/{}", input.section_prefix.as_str(), section_name);
    let program_name = format!("tproxy_{section_name}");
    let go_filter_name = format!("dae_{section_name}");
    let attach = TcBpfAttachSpec::new(
        target,
        role.priority().to_string(),
        input.object.clone(),
        section,
    );
    let handle_minor = role.handle_minor_base() + (input.flip & 1);
    let native = attach.native_attach_spec(
        program_name,
        role.priority(),
        tc_handle(role.handle_major(), handle_minor),
    );
    let stale_cleanup_handle_on_fresh_start =
        if input.is_reload || !role.source_uses_flipped_cleanup_on_fresh_start() {
            None
        } else {
            Some(native.handle ^ 1)
        };
    DaeTcAttachLine {
        role,
        go_filter_name,
        attach,
        native,
        stale_cleanup_handle_on_fresh_start,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcAttachTarget {
    pub iface: String,
    pub netns: Option<String>,
    pub direction: TcAttachDirection,
}

impl TcAttachTarget {
    pub fn host(iface: impl Into<String>, direction: TcAttachDirection) -> Self {
        Self {
            iface: iface.into(),
            netns: None,
            direction,
        }
    }

    pub fn netns(
        netns: impl Into<String>,
        iface: impl Into<String>,
        direction: TcAttachDirection,
    ) -> Self {
        Self {
            iface: iface.into(),
            netns: Some(netns.into()),
            direction,
        }
    }

    pub fn clsact_qdisc_add_command(&self) -> TcCommandSpec {
        self.tc_command([
            "qdisc".to_owned(),
            "add".to_owned(),
            "dev".to_owned(),
            self.iface.clone(),
            "clsact".to_owned(),
        ])
    }

    pub fn clsact_qdisc_del_command(&self) -> TcCommandSpec {
        self.tc_command([
            "qdisc".to_owned(),
            "del".to_owned(),
            "dev".to_owned(),
            self.iface.clone(),
            "clsact".to_owned(),
        ])
    }

    pub fn filter_show_command(&self, stats: bool) -> TcCommandSpec {
        let mut args = Vec::new();
        if stats {
            args.push("-s".to_owned());
        }
        args.extend([
            "filter".to_owned(),
            "show".to_owned(),
            "dev".to_owned(),
            self.iface.clone(),
            self.direction.as_str().to_owned(),
        ]);
        self.tc_command(args)
    }

    pub fn filter_del_command(&self, pref: impl Into<String>) -> TcCommandSpec {
        self.tc_command([
            "filter".to_owned(),
            "del".to_owned(),
            "dev".to_owned(),
            self.iface.clone(),
            self.direction.as_str().to_owned(),
            "pref".to_owned(),
            pref.into(),
        ])
    }

    fn tc_command(&self, args: impl IntoIterator<Item = String>) -> TcCommandSpec {
        let args = args.into_iter().collect::<Vec<_>>();
        match &self.netns {
            Some(netns) => {
                let mut wrapped = vec![
                    "netns".to_owned(),
                    "exec".to_owned(),
                    netns.clone(),
                    "tc".to_owned(),
                ];
                wrapped.extend(args);
                TcCommandSpec {
                    program: "ip".to_owned(),
                    args: wrapped,
                }
            }
            None => TcCommandSpec {
                program: "tc".to_owned(),
                args,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcBpfAttachSpec {
    pub target: TcAttachTarget,
    pub pref: String,
    pub object: String,
    pub section: String,
    pub direct_action: bool,
}

impl TcBpfAttachSpec {
    pub fn new(
        target: TcAttachTarget,
        pref: impl Into<String>,
        object: impl Into<String>,
        section: impl Into<String>,
    ) -> Self {
        Self {
            target,
            pref: pref.into(),
            object: object.into(),
            section: section.into(),
            direct_action: true,
        }
    }

    pub fn filter_add_command(&self) -> TcCommandSpec {
        let mut args = vec![
            "filter".to_owned(),
            "add".to_owned(),
            "dev".to_owned(),
            self.target.iface.clone(),
            self.target.direction.as_str().to_owned(),
            "pref".to_owned(),
            self.pref.clone(),
            "bpf".to_owned(),
        ];
        if self.direct_action {
            args.push("da".to_owned());
        }
        args.extend([
            "obj".to_owned(),
            self.object.clone(),
            "sec".to_owned(),
            self.section.clone(),
        ]);
        self.target.tc_command(args)
    }

    pub fn filter_show_command(&self, stats: bool) -> TcCommandSpec {
        self.target.filter_show_command(stats)
    }

    pub fn filter_del_command(&self) -> TcCommandSpec {
        self.target.filter_del_command(self.pref.clone())
    }

    pub fn native_attach_spec(
        &self,
        program_name: impl Into<String>,
        priority: u16,
        handle: u32,
    ) -> TcNativeAttachSpec {
        TcNativeAttachSpec {
            target: self.target.clone(),
            object: self.object.clone(),
            section: self.section.clone(),
            program_name: program_name.into(),
            priority,
            handle,
            protocol: ETH_P_ALL,
            direct_action: self.direct_action,
            clsact_required: true,
            netns_enter_required: self.target.netns.is_some(),
            link_lifetime_owned_by_backend: true,
        }
    }

    pub fn attach_backend_report(
        &self,
        requested: AttachBackend,
        kernel_version: Option<Version>,
        availability: AttachBackendAvailability,
        default_native_backend_enabled: bool,
        native_spec: TcNativeAttachSpec,
    ) -> TcAttachBackendReport {
        let plan = plan_attach_backend(requested, kernel_version, availability);
        let native_backend_capable = matches!(
            plan.selected,
            Some(AttachBackend::Tcx | AttachBackend::TcNetlink)
        );
        let effective_backend = if default_native_backend_enabled {
            plan.selected
        } else {
            Some(AttachBackend::TcCommandFallback)
        };
        TcAttachBackendReport {
            tcx_attempted: plan.attempt_order.contains(&AttachBackend::Tcx),
            tc_netlink_attempted: plan.attempt_order.contains(&AttachBackend::TcNetlink),
            command_fallback_attempted: plan
                .attempt_order
                .contains(&AttachBackend::TcCommandFallback),
            command_fallback_required: effective_backend == Some(AttachBackend::TcCommandFallback),
            command_fallback_spec: self.filter_add_command(),
            cleanup_fallback_spec: self.filter_del_command(),
            show_fallback_spec: self.filter_show_command(true),
            plan,
            native_spec,
            effective_backend,
            default_native_backend_enabled,
            native_backend_capable,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcCommandSpec {
    pub program: String,
    pub args: Vec<String>,
}
