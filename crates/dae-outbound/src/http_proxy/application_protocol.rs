use crate::error::OutboundError;

pub const HTTP_1_1_ALPN: &str = "http/1.1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectiveHttpProxyApplicationProtocol {
    Http1,
}

impl EffectiveHttpProxyApplicationProtocol {
    pub const fn alpn(self) -> &'static str {
        match self {
            Self::Http1 => HTTP_1_1_ALPN,
        }
    }

    pub fn from_configured_alpn(configured: Option<&str>) -> Result<Self, OutboundError> {
        let Some(configured) = configured else {
            return Ok(Self::Http1);
        };
        let supports_http1 = configured
            .split(',')
            .map(str::trim)
            .any(|protocol| protocol == HTTP_1_1_ALPN);
        if supports_http1 {
            Ok(Self::Http1)
        } else {
            Err(OutboundError::BadHttpProxy(
                "HTTPS proxy application protocol has no supported ALPN".to_owned(),
            ))
        }
    }

    pub fn validate_negotiated_alpn(self, negotiated: Option<&[u8]>) -> Result<(), OutboundError> {
        match negotiated {
            None => Ok(()),
            Some(protocol) if protocol == self.alpn().as_bytes() => Ok(()),
            Some(protocol) => Err(OutboundError::BadHttpProxy(format!(
                "HTTPS proxy negotiated unsupported application protocol: {}",
                String::from_utf8_lossy(protocol)
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_alpn_uses_the_supported_intersection() {
        for configured in [None, Some("http/1.1"), Some("h2,http/1.1")] {
            assert_eq!(
                EffectiveHttpProxyApplicationProtocol::from_configured_alpn(configured).unwrap(),
                EffectiveHttpProxyApplicationProtocol::Http1
            );
        }
    }

    #[test]
    fn configured_alpn_without_http1_is_rejected() {
        for configured in [Some(""), Some("h2"), Some("h3,h2")] {
            let error = EffectiveHttpProxyApplicationProtocol::from_configured_alpn(configured)
                .unwrap_err()
                .to_string();
            assert!(error.contains("no supported ALPN"), "{error}");
        }
    }

    #[test]
    fn negotiated_alpn_accepts_only_absent_or_http1() {
        let protocol = EffectiveHttpProxyApplicationProtocol::Http1;
        assert!(protocol.validate_negotiated_alpn(None).is_ok());
        assert!(
            protocol
                .validate_negotiated_alpn(Some(HTTP_1_1_ALPN.as_bytes()))
                .is_ok()
        );
        assert!(protocol.validate_negotiated_alpn(Some(b"h2")).is_err());
    }
}
