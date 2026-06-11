use crate::{AttachBackend, NativeBackendAdmissionReport};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeBackendRuntimeReason {
    NativeBackendNotRequested,
    CommandBackendRequested,
    AdmissionNotMet,
    NativeLoaderUnavailable,
    CommandBackendUnavailable,
    RequestedNativeBackendUnavailable,
    NativeBackendCandidateSelected,
}

impl NativeBackendRuntimeReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeBackendNotRequested => "native_backend_not_requested",
            Self::CommandBackendRequested => "command_backend_requested",
            Self::AdmissionNotMet => "admission_not_met",
            Self::NativeLoaderUnavailable => "native_loader_unavailable",
            Self::CommandBackendUnavailable => "command_backend_unavailable",
            Self::RequestedNativeBackendUnavailable => "requested_native_backend_unavailable",
            Self::NativeBackendCandidateSelected => "native_backend_candidate_selected",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBackendRuntimeRequest {
    pub native_backend_requested: bool,
    pub requested_backend: AttachBackend,
    pub admission_report: NativeBackendAdmissionReport,
    pub native_loader_available: bool,
    pub tc_command_available: bool,
}

impl NativeBackendRuntimeRequest {
    pub fn report_only(admission_report: NativeBackendAdmissionReport) -> Self {
        Self {
            native_backend_requested: false,
            requested_backend: AttachBackend::Auto,
            admission_report,
            native_loader_available: cfg!(feature = "aya-loader"),
            tc_command_available: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBackendRuntimeDecision {
    pub schema: &'static str,
    pub native_backend_requested: bool,
    pub requested_backend: AttachBackend,
    pub admission_admitted: bool,
    pub native_loader_available: bool,
    pub attempt_native_backend: bool,
    pub selected_backend: Option<AttachBackend>,
    pub native_backend_candidate: Option<AttachBackend>,
    pub command_backend: Option<AttachBackend>,
    pub command_backend_required: bool,
    pub command_backend_available: bool,
    pub automatic_enable_allowed: bool,
    pub reason: NativeBackendRuntimeReason,
}

pub fn native_backend_runtime_decision(
    request: NativeBackendRuntimeRequest,
) -> NativeBackendRuntimeDecision {
    let command_backend = request
        .tc_command_available
        .then_some(AttachBackend::TcCommand);
    if !request.tc_command_available {
        return NativeBackendRuntimeDecision {
            schema: "native-ebpf-backend-runtime-decision",
            native_backend_requested: request.native_backend_requested,
            requested_backend: request.requested_backend,
            admission_admitted: request.admission_report.admitted,
            native_loader_available: request.native_loader_available,
            attempt_native_backend: false,
            selected_backend: None,
            native_backend_candidate: None,
            command_backend,
            command_backend_required: true,
            command_backend_available: false,
            automatic_enable_allowed: false,
            reason: NativeBackendRuntimeReason::CommandBackendUnavailable,
        };
    }

    if request.requested_backend == AttachBackend::TcCommand {
        return command_backend_decision(
            request,
            NativeBackendRuntimeReason::CommandBackendRequested,
        );
    }

    if !request.native_backend_requested {
        return command_backend_decision(
            request,
            NativeBackendRuntimeReason::NativeBackendNotRequested,
        );
    }

    if !request.admission_report.admitted {
        return command_backend_decision(request, NativeBackendRuntimeReason::AdmissionNotMet);
    }

    if !request.native_loader_available {
        return command_backend_decision(
            request,
            NativeBackendRuntimeReason::NativeLoaderUnavailable,
        );
    }

    let candidate = requested_native_backend_candidate(
        request.requested_backend,
        request.admission_report.selected_native_backend,
    );
    let Some(candidate) = candidate else {
        return command_backend_decision(
            request,
            NativeBackendRuntimeReason::RequestedNativeBackendUnavailable,
        );
    };

    NativeBackendRuntimeDecision {
        schema: "native-ebpf-backend-runtime-decision",
        native_backend_requested: request.native_backend_requested,
        requested_backend: request.requested_backend,
        admission_admitted: request.admission_report.admitted,
        native_loader_available: request.native_loader_available,
        attempt_native_backend: true,
        selected_backend: Some(candidate),
        native_backend_candidate: Some(candidate),
        command_backend,
        command_backend_required: true,
        command_backend_available: true,
        automatic_enable_allowed: false,
        reason: NativeBackendRuntimeReason::NativeBackendCandidateSelected,
    }
}

fn command_backend_decision(
    request: NativeBackendRuntimeRequest,
    reason: NativeBackendRuntimeReason,
) -> NativeBackendRuntimeDecision {
    NativeBackendRuntimeDecision {
        schema: "native-ebpf-backend-runtime-decision",
        native_backend_requested: request.native_backend_requested,
        requested_backend: request.requested_backend,
        admission_admitted: request.admission_report.admitted,
        native_loader_available: request.native_loader_available,
        attempt_native_backend: false,
        selected_backend: Some(AttachBackend::TcCommand),
        native_backend_candidate: None,
        command_backend: Some(AttachBackend::TcCommand),
        command_backend_required: true,
        command_backend_available: true,
        automatic_enable_allowed: false,
        reason,
    }
}

fn requested_native_backend_candidate(
    requested: AttachBackend,
    admitted_candidate: Option<AttachBackend>,
) -> Option<AttachBackend> {
    match requested {
        AttachBackend::Auto => admitted_candidate,
        AttachBackend::TcNetlink => Some(AttachBackend::TcNetlink),
        AttachBackend::Tcx => match admitted_candidate {
            Some(AttachBackend::Tcx) => Some(AttachBackend::Tcx),
            _ => None,
        },
        AttachBackend::TcCommand => None,
    }
}
