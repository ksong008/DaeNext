use std::{fmt, future::Future};

use tokio::time;

mod bytes;
mod io;

pub(in crate::production_runtime_owner::resident_dataplane) use self::bytes::{
    ProxyDnsPendingRequestBytes, ProxyDnsQueuedRequestBytes,
};
pub(in crate::production_runtime_owner::resident_dataplane) use self::io::exchange_proxy_dns_framed_stream;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ProxyDnsRequestStage {
    Enqueue,
    Queued,
    Parse,
    Identifier,
    Pending,
    OwnerAcquire,
    Connect,
    Authenticate,
    Send,
    Read,
    Retry,
    Cleanup,
}

impl ProxyDnsRequestStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Enqueue => "enqueue",
            Self::Queued => "queued",
            Self::Parse => "parse",
            Self::Identifier => "identifier",
            Self::Pending => "pending",
            Self::OwnerAcquire => "owner-acquire",
            Self::Connect => "connect",
            Self::Authenticate => "authenticate",
            Self::Send => "send",
            Self::Read => "read",
            Self::Retry => "retry",
            Self::Cleanup => "cleanup",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ProxyDnsRequestFailure {
    Cancelled,
    Deadline,
    Network,
    Protocol,
    Capacity,
}

impl ProxyDnsRequestFailure {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::Deadline => "deadline",
            Self::Network => "network",
            Self::Protocol => "protocol",
            Self::Capacity => "capacity",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ProxyDnsRequestError {
    stage: ProxyDnsRequestStage,
    failure: ProxyDnsRequestFailure,
    detail: String,
}

impl ProxyDnsRequestError {
    #[cold]
    #[inline(never)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn new(
        stage: ProxyDnsRequestStage,
        failure: ProxyDnsRequestFailure,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            failure,
            detail: detail.into(),
        }
    }

    #[cold]
    #[inline(never)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn cancelled(
        stage: ProxyDnsRequestStage,
    ) -> Self {
        Self::new(
            stage,
            ProxyDnsRequestFailure::Cancelled,
            "response receiver closed",
        )
    }

    #[cold]
    #[inline(never)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn deadline(
        stage: ProxyDnsRequestStage,
    ) -> Self {
        Self::new(
            stage,
            ProxyDnsRequestFailure::Deadline,
            "absolute deadline expired",
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn stage(
        &self,
    ) -> ProxyDnsRequestStage {
        self.stage
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn failure(
        &self,
    ) -> ProxyDnsRequestFailure {
        self.failure
    }

    #[cold]
    #[inline(never)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn with_context(
        self,
        context: impl fmt::Display,
    ) -> Self {
        Self::new(self.stage, self.failure, format!("{context}: {self}"))
    }
}

impl fmt::Display for ProxyDnsRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "proxy DNS request {} during {}: {}",
            self.failure.as_str(),
            self.stage.as_str(),
            self.detail
        )
    }
}

impl std::error::Error for ProxyDnsRequestError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ProxyDnsRequestContext {
    deadline: time::Instant,
}

impl ProxyDnsRequestContext {
    pub(in crate::production_runtime_owner::resident_dataplane) fn from_timeout(
        timeout: std::time::Duration,
    ) -> Self {
        Self {
            deadline: time::Instant::now() + timeout,
        }
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn from_deadline(
        deadline: time::Instant,
    ) -> Self {
        Self { deadline }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn deadline(self) -> time::Instant {
        self.deadline
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn ensure(
        self,
        stage: ProxyDnsRequestStage,
    ) -> Result<(), ProxyDnsRequestError> {
        if time::Instant::now() >= self.deadline {
            Err(ProxyDnsRequestError::deadline(stage))
        } else {
            Ok(())
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) async fn run<T, E, F>(
        self,
        stage: ProxyDnsRequestStage,
        failure: ProxyDnsRequestFailure,
        future: F,
    ) -> Result<T, ProxyDnsRequestError>
    where
        E: ToString,
        F: Future<Output = Result<T, E>>,
    {
        self.ensure(stage)?;
        match time::timeout_at(self.deadline, future).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(proxy_dns_request_stage_error(
                stage,
                failure,
                error.to_string(),
            )),
            Err(_) => Err(ProxyDnsRequestError::deadline(stage)),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) async fn run_typed<T, F>(
        self,
        stage: ProxyDnsRequestStage,
        future: F,
    ) -> Result<T, ProxyDnsRequestError>
    where
        F: Future<Output = Result<T, ProxyDnsRequestError>>,
    {
        self.ensure(stage)?;
        match time::timeout_at(self.deadline, future).await {
            Ok(result) => result,
            Err(_) => Err(ProxyDnsRequestError::deadline(stage)),
        }
    }
}

#[cold]
#[inline(never)]
fn proxy_dns_request_stage_error(
    stage: ProxyDnsRequestStage,
    failure: ProxyDnsRequestFailure,
    detail: String,
) -> ProxyDnsRequestError {
    ProxyDnsRequestError::new(stage, failure, detail)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ProxyDnsRequestOutcome {
    Pending,
    ResponseForwarded,
}

#[cfg(test)]
mod tests;
