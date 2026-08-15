use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NativeTcpProbeStage {
    Admission,
    OwnerAcquire,
    Connect,
    Security,
    ProtocolOpen,
    RequestWrite,
    ResponseRead,
    Cleanup,
}

impl NativeTcpProbeStage {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::OwnerAcquire => "owner-acquire",
            Self::Connect => "connect",
            Self::Security => "security",
            Self::ProtocolOpen => "protocol-open",
            Self::RequestWrite => "request-write",
            Self::ResponseRead => "response-read",
            Self::Cleanup => "cleanup",
        }
    }
}

#[derive(Debug)]
pub(super) struct NativeTcpProbeFailure {
    stage: NativeTcpProbeStage,
    detail: String,
}

impl NativeTcpProbeFailure {
    pub(super) fn new(stage: NativeTcpProbeStage, detail: impl Into<String>) -> Self {
        Self {
            stage,
            detail: detail.into(),
        }
    }

    pub(super) fn deadline(stage: NativeTcpProbeStage) -> Self {
        Self::new(stage, "deadline elapsed")
    }

    #[cfg(test)]
    pub(super) fn stage(&self) -> NativeTcpProbeStage {
        self.stage
    }
}

impl fmt::Display for NativeTcpProbeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "native outbound probe [{}]: {}",
            self.stage.as_str(),
            self.detail
        )
    }
}

pub(super) enum NativeTcpProbeError {
    NotAdmitted,
    OwnerAcquire(String),
    Connect(String),
    Security(String),
    Open(String),
}
