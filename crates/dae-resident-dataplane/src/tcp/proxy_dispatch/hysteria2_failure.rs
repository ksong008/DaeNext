use std::fmt;

use dae_runtime_control::OwnerFailureClass;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Hysteria2FailureClass {
    NetworkAddress,
    NetworkPort,
    TlsCertificate,
    TlsPin,
    Http3Authentication,
    Resource,
    Deadline,
    Draining,
    Cancelled,
    Configuration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Hysteria2RetryDisposition {
    Address,
    Port,
    Capacity,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Hysteria2Failure {
    class: Hysteria2FailureClass,
    operation: &'static str,
    public_detail: &'static str,
}

impl Hysteria2Failure {
    pub(crate) const fn new(
        class: Hysteria2FailureClass,
        operation: &'static str,
        public_detail: &'static str,
    ) -> Self {
        Self {
            class,
            operation,
            public_detail,
        }
    }

    pub(crate) const fn class(self) -> Hysteria2FailureClass {
        self.class
    }

    pub(crate) const fn operation(self) -> &'static str {
        self.operation
    }

    pub(crate) const fn retry_disposition(self) -> Hysteria2RetryDisposition {
        match self.class {
            Hysteria2FailureClass::NetworkAddress => Hysteria2RetryDisposition::Address,
            Hysteria2FailureClass::NetworkPort => Hysteria2RetryDisposition::Port,
            Hysteria2FailureClass::Resource => Hysteria2RetryDisposition::Capacity,
            Hysteria2FailureClass::TlsCertificate
            | Hysteria2FailureClass::TlsPin
            | Hysteria2FailureClass::Http3Authentication
            | Hysteria2FailureClass::Deadline
            | Hysteria2FailureClass::Draining
            | Hysteria2FailureClass::Cancelled
            | Hysteria2FailureClass::Configuration => Hysteria2RetryDisposition::Terminal,
        }
    }

    pub(crate) const fn allows_candidate_retry(self) -> bool {
        matches!(
            self.retry_disposition(),
            Hysteria2RetryDisposition::Address | Hysteria2RetryDisposition::Port
        )
    }

    pub(crate) const fn owner_failure_class(self) -> OwnerFailureClass {
        match self.class() {
            Hysteria2FailureClass::NetworkAddress | Hysteria2FailureClass::NetworkPort => {
                OwnerFailureClass::Connect
            }
            Hysteria2FailureClass::TlsCertificate
            | Hysteria2FailureClass::TlsPin
            | Hysteria2FailureClass::Configuration => OwnerFailureClass::Transport,
            Hysteria2FailureClass::Http3Authentication => OwnerFailureClass::Authentication,
            Hysteria2FailureClass::Resource => OwnerFailureClass::Resource,
            Hysteria2FailureClass::Deadline
            | Hysteria2FailureClass::Draining
            | Hysteria2FailureClass::Cancelled => OwnerFailureClass::Cancelled,
        }
    }
}

impl fmt::Display for Hysteria2Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.operation, self.public_detail)
    }
}

impl std::error::Error for Hysteria2Failure {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_disposition_is_limited_to_network_and_capacity_classes() {
        assert_eq!(
            Hysteria2Failure::new(
                Hysteria2FailureClass::NetworkAddress,
                "resolve",
                "address failed",
            )
            .retry_disposition(),
            Hysteria2RetryDisposition::Address
        );
        assert_eq!(
            Hysteria2Failure::new(Hysteria2FailureClass::NetworkPort, "connect", "port failed",)
                .retry_disposition(),
            Hysteria2RetryDisposition::Port
        );
        assert_eq!(
            Hysteria2Failure::new(
                Hysteria2FailureClass::Resource,
                "admission",
                "capacity unavailable",
            )
            .retry_disposition(),
            Hysteria2RetryDisposition::Capacity
        );
        for class in [
            Hysteria2FailureClass::TlsCertificate,
            Hysteria2FailureClass::TlsPin,
            Hysteria2FailureClass::Http3Authentication,
            Hysteria2FailureClass::Deadline,
            Hysteria2FailureClass::Draining,
            Hysteria2FailureClass::Cancelled,
            Hysteria2FailureClass::Configuration,
        ] {
            assert_eq!(
                Hysteria2Failure::new(class, "terminal", "terminal failure").retry_disposition(),
                Hysteria2RetryDisposition::Terminal
            );
        }
    }

    #[test]
    fn public_failure_contains_only_static_redacted_fields() {
        let failure = Hysteria2Failure::new(
            Hysteria2FailureClass::TlsPin,
            "hysteria2-tls-pin",
            "Hysteria2 certificate pin verification failed",
        );
        let display = failure.to_string();
        let debug = format!("{failure:?}");
        assert_eq!(
            display,
            "hysteria2-tls-pin: Hysteria2 certificate pin verification failed"
        );
        assert!(!debug.contains("0123456789abcdef"));
        assert!(!debug.contains("hysteria2://"));
    }
}
