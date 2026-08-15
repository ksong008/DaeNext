use std::error::Error;
use std::fmt;
use std::io;
use std::net::SocketAddr;

#[derive(Debug)]
pub(crate) struct SocketAddressResolutionError {
    context: Box<str>,
    authority: Box<str>,
    kind: SocketAddressResolutionErrorKind,
}

#[derive(Debug)]
enum SocketAddressResolutionErrorKind {
    TimedOut,
    Resolve(io::Error),
    NoAddress,
}

impl SocketAddressResolutionError {
    pub(super) fn timed_out(context: &str, authority: &str) -> Self {
        Self::new(
            context,
            authority,
            SocketAddressResolutionErrorKind::TimedOut,
        )
    }

    pub(super) fn resolve(context: &str, authority: &str, source: io::Error) -> Self {
        Self::new(
            context,
            authority,
            SocketAddressResolutionErrorKind::Resolve(source),
        )
    }

    pub(super) fn no_address(context: &str, authority: &str) -> Self {
        Self::new(
            context,
            authority,
            SocketAddressResolutionErrorKind::NoAddress,
        )
    }

    fn new(context: &str, authority: &str, kind: SocketAddressResolutionErrorKind) -> Self {
        Self {
            context: context.into(),
            authority: authority.into(),
            kind,
        }
    }
}

impl fmt::Display for SocketAddressResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            SocketAddressResolutionErrorKind::TimedOut => write!(
                formatter,
                "{} {}: resolution timed out",
                self.context, self.authority
            ),
            SocketAddressResolutionErrorKind::Resolve(source) => write!(
                formatter,
                "{} {}: resolve failed: {source}",
                self.context, self.authority
            ),
            SocketAddressResolutionErrorKind::NoAddress => {
                write!(
                    formatter,
                    "{} {}: no IP address",
                    self.context, self.authority
                )
            }
        }
    }
}

impl Error for SocketAddressResolutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.kind {
            SocketAddressResolutionErrorKind::Resolve(source) => Some(source),
            SocketAddressResolutionErrorKind::TimedOut
            | SocketAddressResolutionErrorKind::NoAddress => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum SocketCandidateAttemptError {
    Empty {
        context: Box<str>,
    },
    AllFailed {
        context: Box<str>,
        candidate_count: usize,
        failures: Vec<SocketCandidateFailure>,
        omitted: usize,
    },
    Deadline {
        context: Box<str>,
        candidate_count: usize,
        attempted_count: usize,
        failures: Vec<SocketCandidateFailure>,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SocketCandidateFailure {
    candidate: SocketAddr,
    detail: String,
}

impl SocketCandidateAttemptError {
    pub(super) fn empty(context: &str) -> Self {
        Self::Empty {
            context: context.into(),
        }
    }

    pub(super) fn all_failed(
        context: &str,
        candidate_count: usize,
        failures: Vec<(SocketAddr, String)>,
    ) -> Self {
        let omitted = candidate_count.saturating_sub(failures.len());
        Self::AllFailed {
            context: context.into(),
            candidate_count,
            failures: failures
                .into_iter()
                .map(|(candidate, detail)| SocketCandidateFailure { candidate, detail })
                .collect(),
            omitted,
        }
    }

    pub(super) fn deadline(
        context: &str,
        candidate_count: usize,
        attempted_count: usize,
        failures: Vec<(SocketAddr, String)>,
    ) -> Self {
        Self::Deadline {
            context: context.into(),
            candidate_count,
            attempted_count,
            failures: failures
                .into_iter()
                .map(|(candidate, detail)| SocketCandidateFailure { candidate, detail })
                .collect(),
        }
    }
}

impl fmt::Display for SocketCandidateAttemptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { context } => {
                write!(formatter, "{context}: no resolved address candidates")
            }
            Self::AllFailed {
                context,
                candidate_count,
                failures,
                omitted,
            } => {
                write!(
                    formatter,
                    "{context}: all {candidate_count} resolved address candidates failed"
                )?;
                if !failures.is_empty() {
                    formatter.write_str(": ")?;
                    for (index, failure) in failures.iter().enumerate() {
                        if index != 0 {
                            formatter.write_str("; ")?;
                        }
                        write!(formatter, "{}: {}", failure.candidate, failure.detail)?;
                    }
                }
                if *omitted > 0 {
                    write!(formatter, "; {omitted} additional failures omitted")?;
                }
                Ok(())
            }
            Self::Deadline {
                context,
                candidate_count,
                attempted_count,
                failures,
            } => {
                write!(
                    formatter,
                    "{context}: resolved address candidate deadline elapsed after starting {attempted_count} of {candidate_count} candidates"
                )?;
                if !failures.is_empty() {
                    formatter.write_str(": ")?;
                    for (index, failure) in failures.iter().enumerate() {
                        if index != 0 {
                            formatter.write_str("; ")?;
                        }
                        write!(formatter, "{}: {}", failure.candidate, failure.detail)?;
                    }
                }
                Ok(())
            }
        }
    }
}

impl Error for SocketCandidateAttemptError {}
