use boring_sys as bffi;
use quinn_proto::{TransportError, TransportErrorCode};
use std::ffi::{c_int, CStr};
use std::fmt;
use std::fmt::{Display, Formatter};

#[derive(Copy, Clone)]
pub(crate) struct Alert(u8);

impl Alert {
    pub(crate) fn from(value: u8) -> Self {
        Alert(value)
    }

    pub(crate) fn handshake_failure() -> Self {
        Alert(bffi::SSL_AD_HANDSHAKE_FAILURE as u8)
    }

    pub(crate) fn get_description(&self) -> &'static str {
        unsafe {
            CStr::from_ptr(bffi::SSL_alert_desc_string_long(self.0 as c_int))
                .to_str()
                .unwrap()
        }
    }
}

impl Display for Alert {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "SSL alert [{}]: {}", self.0, self.get_description())
    }
}

impl From<Alert> for TransportErrorCode {
    fn from(alert: Alert) -> Self {
        TransportErrorCode::crypto(alert.0)
    }
}

impl From<Alert> for TransportError {
    fn from(alert: Alert) -> Self {
        TransportError {
            code: alert.into(),
            frame: None,
            reason: alert.get_description().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_alert_maps_to_the_rfc9001_crypto_error_space() {
        let alert = Alert::handshake_failure();
        let error: TransportError = alert.into();

        assert_eq!(
            u64::from(error.code),
            0x100 | u64::from(bffi::SSL_AD_HANDSHAKE_FAILURE as u8)
        );
        assert!(!error.reason.is_empty());
        assert!(error.frame.is_none());
    }
}
