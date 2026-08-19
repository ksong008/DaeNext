use std::fmt;
use std::net::SocketAddr;

use super::{ProxyDnsRequestError, ProxyDnsRequestFailure, ProxyDnsRequestStage};

#[derive(Debug)]
pub enum ResidentDnsTransportError {
    Message(String),
    TargetConnect(String),
    Refresh(String),
    ResponseTimeout(String),
    Protocol(String),
    UdpTruncated(SocketAddr),
    Proxy(ProxyDnsRequestError),
}

impl ResidentDnsTransportError {
    pub fn message(error: impl Into<String>) -> Self {
        Self::Message(error.into())
    }

    pub fn proxy(error: ProxyDnsRequestError) -> Self {
        Self::Proxy(error)
    }

    pub fn response_timeout(error: impl Into<String>) -> Self {
        Self::ResponseTimeout(error.into())
    }

    pub fn refresh(error: impl Into<String>) -> Self {
        Self::Refresh(error.into())
    }

    pub fn protocol(error: impl Into<String>) -> Self {
        Self::Protocol(error.into())
    }

    pub fn udp_truncated(target: SocketAddr) -> Self {
        Self::UdpTruncated(target)
    }

    pub fn combined_attempts(context: &str, first: Self, retry: Self) -> Self {
        let invalidates_stale_target =
            first.invalidates_stale_target() && retry.invalidates_stale_target();
        let detail = format!("{context} failed after {first}: {retry}");
        if invalidates_stale_target {
            Self::TargetConnect(detail)
        } else {
            Self::Message(detail)
        }
    }

    pub fn allows_next_candidate(&self) -> bool {
        match self {
            Self::Message(_) => true,
            Self::TargetConnect(_) => true,
            Self::Refresh(_) => false,
            Self::ResponseTimeout(_) => true,
            Self::Protocol(_) => false,
            Self::UdpTruncated(_) => true,
            Self::Proxy(error) => match (error.stage(), error.failure()) {
                (ProxyDnsRequestStage::Cleanup, _) => false,
                (_, ProxyDnsRequestFailure::Network) => true,
                (ProxyDnsRequestStage::Connect, ProxyDnsRequestFailure::Deadline) => true,
                _ => false,
            },
        }
    }

    pub fn invalidates_stale_target(&self) -> bool {
        match self {
            Self::Message(_) => false,
            Self::TargetConnect(_) => true,
            Self::Refresh(_) => false,
            Self::ResponseTimeout(_) | Self::Protocol(_) => false,
            Self::UdpTruncated(_) => false,
            Self::Proxy(error) => {
                error.stage() == ProxyDnsRequestStage::Connect
                    && matches!(
                        error.failure(),
                        ProxyDnsRequestFailure::Network | ProxyDnsRequestFailure::Deadline
                    )
            }
        }
    }

    pub const fn is_udp_truncated(&self) -> bool {
        matches!(self, Self::UdpTruncated(_))
    }
}

impl fmt::Display for ResidentDnsTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(error)
            | Self::TargetConnect(error)
            | Self::Refresh(error)
            | Self::ResponseTimeout(error)
            | Self::Protocol(error) => formatter.write_str(error),
            Self::UdpTruncated(target) => write!(formatter, "{target} UDP response truncated"),
            Self::Proxy(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ResidentDnsTransportError {}

#[cfg(all(test, feature = "dns-runtime-tests"))]
mod tests {
    use super::*;

    #[test]
    fn proxy_failure_class_controls_candidate_fallback_without_string_matching() {
        for failure in [
            ProxyDnsRequestFailure::Cancelled,
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
        let connect_deadline = ResidentDnsTransportError::proxy(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Connect,
            ProxyDnsRequestFailure::Deadline,
            "fixture",
        ));
        assert!(connect_deadline.allows_next_candidate());
        assert!(connect_deadline.invalidates_stale_target());
        let read_deadline = ResidentDnsTransportError::proxy(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Deadline,
            "fixture",
        ));
        assert!(!read_deadline.allows_next_candidate());
        assert!(!read_deadline.invalidates_stale_target());
        let cleanup = ResidentDnsTransportError::proxy(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Cleanup,
            ProxyDnsRequestFailure::Network,
            "fixture",
        ));
        assert!(!cleanup.allows_next_candidate());
        assert!(ResidentDnsTransportError::message("direct failure").allows_next_candidate());
        let protocol = ResidentDnsTransportError::protocol("malformed DNS response");
        assert!(!protocol.allows_next_candidate());
        assert!(!protocol.invalidates_stale_target());
        let refresh = ResidentDnsTransportError::refresh("resolver unavailable");
        assert!(!refresh.allows_next_candidate());
        assert!(!refresh.invalidates_stale_target());
        assert!(!network.invalidates_stale_target());
        let connect_network = ResidentDnsTransportError::proxy(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Connect,
            ProxyDnsRequestFailure::Network,
            "fixture",
        ));
        assert!(connect_network.invalidates_stale_target());
        assert!(!ResidentDnsTransportError::message("connect timeout").invalidates_stale_target());
        let truncated = ResidentDnsTransportError::udp_truncated("127.0.0.1:53".parse().unwrap());
        assert!(truncated.allows_next_candidate());
        assert!(!truncated.invalidates_stale_target());
        assert!(truncated.is_udp_truncated());
        assert_eq!(truncated.to_string(), "127.0.0.1:53 UDP response truncated");

        let combined_connect = ResidentDnsTransportError::combined_attempts(
            "fixture retry",
            connect_deadline,
            connect_network,
        );
        assert!(combined_connect.invalidates_stale_target());
        let mixed = ResidentDnsTransportError::combined_attempts(
            "fixture retry",
            combined_connect,
            ResidentDnsTransportError::message("TLS certificate rejected"),
        );
        assert!(!mixed.invalidates_stale_target());
    }
}
