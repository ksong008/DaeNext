use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SubscriptionFetchFailureKind {
    InvalidSource,
    TlsUnknownIssuer,
    TlsCertificate,
    Dns,
    Connect,
    Timeout,
    HttpStatus,
    Redirect,
    ContentDecode,
    ResponseTooLarge,
    AccessDenied,
    ControlBusy,
    ControlUnavailable,
    SourceIo,
}

impl SubscriptionFetchFailureKind {
    fn code(self) -> &'static str {
        match self {
            Self::InvalidSource => "invalid_source",
            Self::TlsUnknownIssuer => "tls_unknown_issuer",
            Self::TlsCertificate => "tls_certificate",
            Self::Dns => "dns",
            Self::Connect => "connect",
            Self::Timeout => "timeout",
            Self::HttpStatus => "http_status",
            Self::Redirect => "redirect",
            Self::ContentDecode => "content_decode",
            Self::ResponseTooLarge => "response_too_large",
            Self::AccessDenied => "access_denied",
            Self::ControlBusy => "control_busy",
            Self::ControlUnavailable => "control_unavailable",
            Self::SourceIo => "source_io",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::InvalidSource => "subscription source is invalid",
            Self::TlsUnknownIssuer => {
                "subscription TLS certificate is not issued by a trusted authority"
            }
            Self::TlsCertificate => "subscription TLS certificate validation failed",
            Self::Dns => "subscription endpoint name could not be resolved",
            Self::Connect => "subscription endpoint connection failed",
            Self::Timeout => "subscription fetch timed out",
            Self::HttpStatus => "subscription server returned an unsuccessful HTTP status",
            Self::Redirect => "subscription redirect was rejected",
            Self::ContentDecode => "subscription response content could not be decoded",
            Self::ResponseTooLarge => "subscription response exceeds the configured size limit",
            Self::AccessDenied => "subscription source access was denied",
            Self::ControlBusy => "subscription fetch capacity is currently busy",
            Self::ControlUnavailable => "subscription fetch service is unavailable",
            Self::SourceIo => "subscription source could not be read",
        }
    }

    fn retryable(self) -> bool {
        matches!(
            self,
            Self::Dns
                | Self::Connect
                | Self::Timeout
                | Self::HttpStatus
                | Self::ControlBusy
                | Self::ControlUnavailable
                | Self::SourceIo
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SubscriptionFetchFailure {
    kind: SubscriptionFetchFailureKind,
}

impl SubscriptionFetchFailure {
    pub(super) fn from_io_error(error: &io::Error) -> Self {
        let message = error.to_string().to_ascii_lowercase();
        let kind = if rustls_certificate_error(error).is_some_and(|certificate| {
            matches!(certificate, rustls::CertificateError::UnknownIssuer)
        }) || message.contains("unknownissuer")
        {
            SubscriptionFetchFailureKind::TlsUnknownIssuer
        } else if rustls_certificate_error(error).is_some()
            || message.contains("invalid peer certificate")
            || message.contains("certificate validation")
        {
            SubscriptionFetchFailureKind::TlsCertificate
        } else if message.contains("redirect") {
            SubscriptionFetchFailureKind::Redirect
        } else if message.contains("returned http") {
            SubscriptionFetchFailureKind::HttpStatus
        } else if message.contains("not utf-8")
            || message.contains("content-encoding")
            || message.contains("chunked body")
            || message.contains("brotli")
            || message.contains("gzip")
        {
            SubscriptionFetchFailureKind::ContentDecode
        } else if message.contains("exceeds") && message.contains("subscription") {
            SubscriptionFetchFailureKind::ResponseTooLarge
        } else if message.contains("resolve tcp endpoint")
            || message.contains("resolved to no socket addresses")
            || message.contains("lookup address")
        {
            SubscriptionFetchFailureKind::Dns
        } else if message.contains("control runtime is busy")
            || error.kind() == io::ErrorKind::WouldBlock
        {
            SubscriptionFetchFailureKind::ControlBusy
        } else if error.kind() == io::ErrorKind::NotConnected {
            SubscriptionFetchFailureKind::ControlUnavailable
        } else if error.kind() == io::ErrorKind::TimedOut {
            SubscriptionFetchFailureKind::Timeout
        } else if matches!(
            error.kind(),
            io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::AddrNotAvailable
                | io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::HostUnreachable
        ) {
            SubscriptionFetchFailureKind::Connect
        } else if error.kind() == io::ErrorKind::InvalidInput {
            SubscriptionFetchFailureKind::InvalidSource
        } else if error.kind() == io::ErrorKind::PermissionDenied {
            SubscriptionFetchFailureKind::AccessDenied
        } else {
            SubscriptionFetchFailureKind::SourceIo
        };
        Self { kind }
    }

    pub(super) fn message(&self) -> &'static str {
        self.kind.message()
    }

    pub(super) fn response_value(&self) -> Value {
        json!({
            "code": self.kind.code(),
            "message": self.kind.message(),
            "retryable": self.kind.retryable(),
        })
    }
}

fn rustls_certificate_error(error: &io::Error) -> Option<&rustls::CertificateError> {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(candidate) = current {
        if let Some(rustls::Error::InvalidCertificate(certificate)) =
            candidate.downcast_ref::<rustls::Error>()
        {
            return Some(certificate);
        }
        current = candidate.source();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_issuer_is_a_tls_fetch_failure() {
        let error = io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        );
        let failure = SubscriptionFetchFailure::from_io_error(&error);
        assert_eq!(failure.kind, SubscriptionFetchFailureKind::TlsUnknownIssuer);
        assert_eq!(failure.response_value()["code"], "tls_unknown_issuer");
        assert_eq!(failure.response_value()["retryable"], false);
    }

    #[test]
    fn transport_timeout_remains_retryable() {
        let error = io::Error::new(io::ErrorKind::TimedOut, "read subscription response");
        let failure = SubscriptionFetchFailure::from_io_error(&error);
        assert_eq!(failure.kind, SubscriptionFetchFailureKind::Timeout);
        assert_eq!(failure.response_value()["retryable"], true);
    }

    #[test]
    fn error_response_never_echoes_source_text() {
        let error = io::Error::other(
            "https://example.invalid/api/subscribe?token=do-not-return failed unexpectedly",
        );
        let response = SubscriptionFetchFailure::from_io_error(&error).response_value();
        let encoded = response.to_string();
        assert!(!encoded.contains("example.invalid"));
        assert!(!encoded.contains("do-not-return"));
    }
}
