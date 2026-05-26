use crate::{AttachBackend, NativeBackendAdmissionReport};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeBackendOptInReason {
    NotOptedIn,
    FallbackRequested,
    AdmissionNotMet,
    NativeLoaderUnavailable,
    FallbackUnavailable,
    RequestedNativeBackendUnavailable,
    NativeBackendCandidateSelected,
}

impl NativeBackendOptInReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotOptedIn => "not_opted_in",
            Self::FallbackRequested => "fallback_requested",
            Self::AdmissionNotMet => "admission_not_met",
            Self::NativeLoaderUnavailable => "native_loader_unavailable",
            Self::FallbackUnavailable => "fallback_unavailable",
            Self::RequestedNativeBackendUnavailable => "requested_native_backend_unavailable",
            Self::NativeBackendCandidateSelected => "native_backend_candidate_selected",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBackendOptInRequest {
    pub opt_in_enabled: bool,
    pub requested_backend: AttachBackend,
    pub admission_report: NativeBackendAdmissionReport,
    pub native_loader_available: bool,
    pub tc_command_fallback_available: bool,
}

impl NativeBackendOptInRequest {
    pub fn report_only(admission_report: NativeBackendAdmissionReport) -> Self {
        Self {
            opt_in_enabled: false,
            requested_backend: AttachBackend::Auto,
            admission_report,
            native_loader_available: cfg!(feature = "aya-loader"),
            tc_command_fallback_available: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBackendOptInDecision {
    pub schema: &'static str,
    pub opt_in_enabled: bool,
    pub requested_backend: AttachBackend,
    pub admission_admitted: bool,
    pub native_loader_available: bool,
    pub attempt_native_backend: bool,
    pub selected_backend: Option<AttachBackend>,
    pub native_backend_candidate: Option<AttachBackend>,
    pub fallback_backend: Option<AttachBackend>,
    pub fallback_required: bool,
    pub fallback_preserved: bool,
    pub default_enable_allowed: bool,
    pub reason: NativeBackendOptInReason,
}

pub fn native_backend_opt_in_decision(
    request: NativeBackendOptInRequest,
) -> NativeBackendOptInDecision {
    let fallback_backend = request
        .tc_command_fallback_available
        .then_some(AttachBackend::TcCommandFallback);
    if !request.tc_command_fallback_available {
        return NativeBackendOptInDecision {
            schema: "native-ebpf-backend-opt-in-v1",
            opt_in_enabled: request.opt_in_enabled,
            requested_backend: request.requested_backend,
            admission_admitted: request.admission_report.admitted,
            native_loader_available: request.native_loader_available,
            attempt_native_backend: false,
            selected_backend: None,
            native_backend_candidate: None,
            fallback_backend,
            fallback_required: true,
            fallback_preserved: false,
            default_enable_allowed: false,
            reason: NativeBackendOptInReason::FallbackUnavailable,
        };
    }

    if request.requested_backend == AttachBackend::TcCommandFallback {
        return fallback_decision(request, NativeBackendOptInReason::FallbackRequested);
    }

    if !request.opt_in_enabled {
        return fallback_decision(request, NativeBackendOptInReason::NotOptedIn);
    }

    if !request.admission_report.admitted {
        return fallback_decision(request, NativeBackendOptInReason::AdmissionNotMet);
    }

    if !request.native_loader_available {
        return fallback_decision(request, NativeBackendOptInReason::NativeLoaderUnavailable);
    }

    let candidate = requested_native_backend_candidate(
        request.requested_backend,
        request.admission_report.selected_native_backend,
    );
    let Some(candidate) = candidate else {
        return fallback_decision(
            request,
            NativeBackendOptInReason::RequestedNativeBackendUnavailable,
        );
    };

    NativeBackendOptInDecision {
        schema: "native-ebpf-backend-opt-in-v1",
        opt_in_enabled: request.opt_in_enabled,
        requested_backend: request.requested_backend,
        admission_admitted: request.admission_report.admitted,
        native_loader_available: request.native_loader_available,
        attempt_native_backend: true,
        selected_backend: Some(candidate),
        native_backend_candidate: Some(candidate),
        fallback_backend,
        fallback_required: true,
        fallback_preserved: true,
        default_enable_allowed: false,
        reason: NativeBackendOptInReason::NativeBackendCandidateSelected,
    }
}

fn fallback_decision(
    request: NativeBackendOptInRequest,
    reason: NativeBackendOptInReason,
) -> NativeBackendOptInDecision {
    NativeBackendOptInDecision {
        schema: "native-ebpf-backend-opt-in-v1",
        opt_in_enabled: request.opt_in_enabled,
        requested_backend: request.requested_backend,
        admission_admitted: request.admission_report.admitted,
        native_loader_available: request.native_loader_available,
        attempt_native_backend: false,
        selected_backend: Some(AttachBackend::TcCommandFallback),
        native_backend_candidate: None,
        fallback_backend: Some(AttachBackend::TcCommandFallback),
        fallback_required: true,
        fallback_preserved: true,
        default_enable_allowed: false,
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
        AttachBackend::TcCommandFallback => None,
    }
}
