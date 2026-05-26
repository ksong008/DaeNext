use crate::{
    AttachBackend, AttachBackendAvailability, AttachBackendPlan, LoaderBackend, LoaderContract,
    Version, loader_contract, plan_attach_backend,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EbpfBackendCapabilityReport {
    pub report_only: bool,
    pub aya_userspace_available: bool,
    pub tc_netlink_available: bool,
    pub tcx_supported: bool,
    pub tcx_available: bool,
    pub selected_backend: Option<AttachBackend>,
    pub command_fallback_used: bool,
    pub fallback_reason: Option<&'static str>,
    pub attach_plan: AttachBackendPlan,
    pub loader_contract: LoaderContract,
}

pub fn report_only_ebpf_backend_capability(
    kernel_version: Option<Version>,
) -> EbpfBackendCapabilityReport {
    let attach_plan = plan_attach_backend(
        AttachBackend::Auto,
        kernel_version,
        AttachBackendAvailability::command_fallback_only(),
    );
    let loader = loader_contract();
    EbpfBackendCapabilityReport {
        report_only: true,
        aya_userspace_available: cfg!(feature = "aya-loader"),
        tc_netlink_available: false,
        tcx_supported: attach_plan.tcx_supported,
        tcx_available: false,
        selected_backend: attach_plan.selected,
        command_fallback_used: attach_plan.command_fallback_used,
        fallback_reason: if attach_plan.command_fallback_used {
            Some("native_backends_report_only")
        } else {
            None
        },
        attach_plan,
        loader_contract: loader,
    }
}

impl AttachBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::TcCommandFallback => "tc_command_fallback",
            Self::TcNetlink => "tc_netlink",
            Self::Tcx => "tcx",
        }
    }
}

impl LoaderBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TcCommandObject => "tc_command_object",
            Self::RustSyscallMaps => "rust_syscall_maps",
            Self::AyaUserspace => "aya_userspace",
        }
    }
}
