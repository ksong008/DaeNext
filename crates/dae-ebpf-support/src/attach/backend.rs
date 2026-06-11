use super::*;
pub const TCX_ATTACH_FEATURE_VERSION: Version = Version::new(6, 6, 0);
pub const ETH_P_ALL: u16 = 0x0003;
pub(super) const DAE_TC_HANDLE_MAJOR: u16 = 0x2022;
pub(super) const IFACE_TC_HANDLE_MAJOR: u16 = 0x2023;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachBackend {
    Auto,
    TcCommand,
    TcNetlink,
    Tcx,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachBackendAvailability {
    pub tcx: bool,
    pub tc_netlink: bool,
    pub tc_command: bool,
}

impl AttachBackendAvailability {
    pub const fn tc_command_only() -> Self {
        Self {
            tcx: false,
            tc_netlink: false,
            tc_command: true,
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
    pub command_backend_used: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcNativeAttachSpec {
    pub target: TcAttachTarget,
    pub object: String,
    pub section: String,
    pub program_name: String,
    pub priority: u16,
    pub handle: u32,
    pub tcx_order: TcxAttachOrder,
    pub protocol: u16,
    pub direct_action: bool,
    pub clsact_required: bool,
    pub netns_enter_required: bool,
    pub link_lifetime_owned_by_backend: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcxAttachOrder {
    First,
    Last,
}

impl TcxAttachOrder {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::First => "first",
            Self::Last => "last",
        }
    }

    pub const fn from_tc_priority(priority: u16) -> Self {
        if priority <= 1 {
            Self::First
        } else {
            Self::Last
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcAttachBackendReport {
    pub plan: AttachBackendPlan,
    pub native_spec: TcNativeAttachSpec,
    pub effective_backend: Option<AttachBackend>,
    pub native_backend_requested: bool,
    pub native_backend_capable: bool,
    pub tcx_attempted: bool,
    pub tc_netlink_attempted: bool,
    pub command_backend_attempted: bool,
    pub command_backend_required: bool,
    pub command_backend_spec: TcCommandSpec,
    pub cleanup_command_backend_spec: TcCommandSpec,
    pub show_command_backend_spec: TcCommandSpec,
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
            order.push(AttachBackend::TcCommand);
            order
        }
        backend => vec![backend],
    };
    let selected = attempt_order.iter().copied().find(|backend| match backend {
        AttachBackend::Auto => false,
        AttachBackend::Tcx => tcx_supported && availability.tcx,
        AttachBackend::TcNetlink => availability.tc_netlink,
        AttachBackend::TcCommand => availability.tc_command,
    });
    AttachBackendPlan {
        requested,
        kernel_version,
        tcx_supported,
        attempt_order,
        selected,
        command_backend_used: selected == Some(AttachBackend::TcCommand),
    }
}

pub const fn tc_handle(major: u16, minor: u16) -> u32 {
    ((major as u32) << 16) | minor as u32
}
