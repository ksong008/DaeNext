use std::fmt;

use super::{ProxyDnsRequestError, ProxyDnsRequestFailure, ProxyDnsRequestStage};

#[derive(Debug)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) enum ResidentDnsTransportError {
    Message(String),
    Proxy(ProxyDnsRequestError),
}

impl ResidentDnsTransportError {
    pub(super) fn message(error: impl Into<String>) -> Self {
        Self::Message(error.into())
    }

    pub(super) fn proxy(error: ProxyDnsRequestError) -> Self {
        Self::Proxy(error)
    }

    pub(super) fn allows_next_candidate(&self) -> bool {
        match self {
            Self::Message(_) => true,
            Self::Proxy(error) => {
                error.failure() == ProxyDnsRequestFailure::Network
                    && error.stage() != ProxyDnsRequestStage::Cleanup
            }
        }
    }
}

impl fmt::Display for ResidentDnsTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(error) => formatter.write_str(error),
            Self::Proxy(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ResidentDnsTransportError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_failure_class_controls_candidate_fallback_without_string_matching() {
        for failure in [
            ProxyDnsRequestFailure::Cancelled,
            ProxyDnsRequestFailure::Deadline,
            ProxyDnsRequestFailure::Protocol,
            ProxyDnsRequestFailure::Capacity,
        ] {
            let error = ResidentDnsTransportError::proxy(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Read,
                failure,
                "fixture",
            ));
            assert!(!error.allows_next_candidate(), "failure={failure:?}");
        }

        let network = ResidentDnsTransportError::proxy(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Network,
            "fixture",
        ));
        assert!(network.allows_next_candidate());
        let cleanup = ResidentDnsTransportError::proxy(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Cleanup,
            ProxyDnsRequestFailure::Network,
            "fixture",
        ));
        assert!(!cleanup.allows_next_candidate());
        assert!(ResidentDnsTransportError::message("direct failure").allows_next_candidate());
    }
}
