use crate::AttachBackend;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OptionalAdmissionEvidence {
    Passed,
    NotRequired,
    Missing,
    Failed,
}

impl OptionalAdmissionEvidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::NotRequired => "not_required",
            Self::Missing => "missing",
            Self::Failed => "failed",
        }
    }

    const fn satisfied(self) -> bool {
        matches!(self, Self::Passed | Self::NotRequired)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeBackendAdmissionCheck {
    AyaUserspaceLoadSmoke,
    MapInMapPrepinSmoke,
    TcNetlinkHostAttachSmoke,
    TcNetlinkNetnsAttachSmoke,
    TcAttachMatrixParity,
    CgroupAttachMatrixParity,
    CgroupAttachSmoke,
    NativeEbpfObjectDefault,
    ExternalEbpfObjectAbsent,
    TcCommandBackendAvailable,
}

impl NativeBackendAdmissionCheck {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AyaUserspaceLoadSmoke => "aya_userspace_load_smoke",
            Self::MapInMapPrepinSmoke => "map_in_map_prepin_smoke",
            Self::TcNetlinkHostAttachSmoke => "tc_netlink_host_attach_smoke",
            Self::TcNetlinkNetnsAttachSmoke => "tc_netlink_netns_attach_smoke",
            Self::TcAttachMatrixParity => "tc_attach_matrix_parity",
            Self::CgroupAttachMatrixParity => "cgroup_attach_matrix_parity",
            Self::CgroupAttachSmoke => "cgroup_attach_smoke",
            Self::NativeEbpfObjectDefault => "native_ebpf_object_default",
            Self::ExternalEbpfObjectAbsent => "external_ebpf_object_absent",
            Self::TcCommandBackendAvailable => "tc_command_backend_available",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeBackendAdmissionEvidence {
    pub aya_userspace_load_smoke_passed: bool,
    pub map_in_map_prepin_smoke_passed: bool,
    pub tc_netlink_host_attach_smoke_passed: bool,
    pub tc_netlink_netns_attach_smoke_passed: bool,
    pub tcx_optional_smoke: OptionalAdmissionEvidence,
    pub tc_attach_matrix_parity_passed: bool,
    pub cgroup_attach_matrix_parity_passed: bool,
    pub cgroup_attach_smoke_passed: bool,
    pub native_ebpf_object_default: bool,
    pub external_ebpf_object_absent: bool,
    pub tc_command_backend_available: bool,
}

impl NativeBackendAdmissionEvidence {
    pub const fn report_only() -> Self {
        Self {
            aya_userspace_load_smoke_passed: false,
            map_in_map_prepin_smoke_passed: false,
            tc_netlink_host_attach_smoke_passed: false,
            tc_netlink_netns_attach_smoke_passed: false,
            tcx_optional_smoke: OptionalAdmissionEvidence::Missing,
            tc_attach_matrix_parity_passed: false,
            cgroup_attach_matrix_parity_passed: false,
            cgroup_attach_smoke_passed: false,
            native_ebpf_object_default: true,
            external_ebpf_object_absent: true,
            tc_command_backend_available: true,
        }
    }

    pub const fn verified_local() -> Self {
        Self {
            aya_userspace_load_smoke_passed: true,
            map_in_map_prepin_smoke_passed: true,
            tc_netlink_host_attach_smoke_passed: true,
            tc_netlink_netns_attach_smoke_passed: true,
            tcx_optional_smoke: OptionalAdmissionEvidence::Passed,
            tc_attach_matrix_parity_passed: true,
            cgroup_attach_matrix_parity_passed: true,
            cgroup_attach_smoke_passed: true,
            native_ebpf_object_default: true,
            external_ebpf_object_absent: true,
            tc_command_backend_available: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBackendAdmissionReport {
    pub schema: &'static str,
    pub report_only: bool,
    pub admitted: bool,
    pub automatic_enable_allowed: bool,
    pub selected_native_backend: Option<AttachBackend>,
    pub command_backend_required: bool,
    pub tcx_optional_smoke: OptionalAdmissionEvidence,
    pub required_checks: Vec<NativeBackendAdmissionCheck>,
    pub missing_checks: Vec<NativeBackendAdmissionCheck>,
    pub failed_optional_checks: Vec<&'static str>,
}

pub fn native_backend_admission_report(
    evidence: NativeBackendAdmissionEvidence,
    report_only: bool,
) -> NativeBackendAdmissionReport {
    let required = native_backend_required_checks();
    let missing_checks = required
        .iter()
        .copied()
        .filter(|check| !required_check_passed(evidence, *check))
        .collect::<Vec<_>>();
    let failed_optional_checks = if evidence.tcx_optional_smoke.satisfied() {
        Vec::new()
    } else {
        vec!["tcx_optional_smoke"]
    };
    let admitted = missing_checks.is_empty() && failed_optional_checks.is_empty();
    let selected_native_backend =
        if admitted && evidence.tcx_optional_smoke == OptionalAdmissionEvidence::Passed {
            Some(AttachBackend::Tcx)
        } else if admitted {
            Some(AttachBackend::TcNetlink)
        } else {
            None
        };
    NativeBackendAdmissionReport {
        schema: "native-ebpf-backend-admission",
        report_only,
        admitted,
        automatic_enable_allowed: false,
        selected_native_backend,
        command_backend_required: !admitted || report_only,
        tcx_optional_smoke: evidence.tcx_optional_smoke,
        required_checks: required,
        missing_checks,
        failed_optional_checks,
    }
}

pub fn native_backend_required_checks() -> Vec<NativeBackendAdmissionCheck> {
    vec![
        NativeBackendAdmissionCheck::AyaUserspaceLoadSmoke,
        NativeBackendAdmissionCheck::MapInMapPrepinSmoke,
        NativeBackendAdmissionCheck::TcNetlinkHostAttachSmoke,
        NativeBackendAdmissionCheck::TcNetlinkNetnsAttachSmoke,
        NativeBackendAdmissionCheck::TcAttachMatrixParity,
        NativeBackendAdmissionCheck::CgroupAttachMatrixParity,
        NativeBackendAdmissionCheck::CgroupAttachSmoke,
        NativeBackendAdmissionCheck::NativeEbpfObjectDefault,
        NativeBackendAdmissionCheck::ExternalEbpfObjectAbsent,
        NativeBackendAdmissionCheck::TcCommandBackendAvailable,
    ]
}

fn required_check_passed(
    evidence: NativeBackendAdmissionEvidence,
    check: NativeBackendAdmissionCheck,
) -> bool {
    match check {
        NativeBackendAdmissionCheck::AyaUserspaceLoadSmoke => {
            evidence.aya_userspace_load_smoke_passed
        }
        NativeBackendAdmissionCheck::MapInMapPrepinSmoke => evidence.map_in_map_prepin_smoke_passed,
        NativeBackendAdmissionCheck::TcNetlinkHostAttachSmoke => {
            evidence.tc_netlink_host_attach_smoke_passed
        }
        NativeBackendAdmissionCheck::TcNetlinkNetnsAttachSmoke => {
            evidence.tc_netlink_netns_attach_smoke_passed
        }
        NativeBackendAdmissionCheck::TcAttachMatrixParity => {
            evidence.tc_attach_matrix_parity_passed
        }
        NativeBackendAdmissionCheck::CgroupAttachMatrixParity => {
            evidence.cgroup_attach_matrix_parity_passed
        }
        NativeBackendAdmissionCheck::CgroupAttachSmoke => evidence.cgroup_attach_smoke_passed,
        NativeBackendAdmissionCheck::NativeEbpfObjectDefault => evidence.native_ebpf_object_default,
        NativeBackendAdmissionCheck::ExternalEbpfObjectAbsent => {
            evidence.external_ebpf_object_absent
        }
        NativeBackendAdmissionCheck::TcCommandBackendAvailable => {
            evidence.tc_command_backend_available
        }
    }
}
