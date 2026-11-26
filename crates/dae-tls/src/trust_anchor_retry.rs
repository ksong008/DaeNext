use std::sync::{Arc, Mutex};

use boring::x509::{X509StoreContext, X509StoreContextRef, X509VerifyError};
use foreign_types::ForeignTypeRef;

/// Certificate selection feedback for a single, normally verified TLS handshake.
#[derive(Clone)]
pub struct TrustAnchorRetry {
    trusted_ids: Arc<[u8]>,
    selected: Arc<Mutex<Option<Vec<u8>>>>,
}

impl TrustAnchorRetry {
    pub fn new(trusted_ids: Arc<[u8]>) -> Option<Self> {
        (!trusted_ids.is_empty()).then(|| Self {
            trusted_ids,
            selected: Arc::default(),
        })
    }

    pub fn record_verification(&self, valid: bool, context: &X509StoreContextRef) -> bool {
        if valid
            || !matches!(
                context.verify_result(),
                Err(X509VerifyError::UNABLE_TO_GET_ISSUER_CERT_LOCALLY
                    | X509VerifyError::UNABLE_TO_VERIFY_LEAF_SIGNATURE
                    | X509VerifyError::SELF_SIGNED_CERT_IN_CHAIN
                    | X509VerifyError::DEPTH_ZERO_SELF_SIGNED_CERT
                    | X509VerifyError::CERT_UNTRUSTED)
            )
        {
            return valid;
        }
        let Ok(index) = X509StoreContext::ssl_idx() else {
            return false;
        };
        let Some(ssl) = context.ex_data(index) else {
            return false;
        };
        let mut list = std::ptr::null();
        let mut len = 0;
        // BoringSSL owns this buffer until the verification callback returns.
        unsafe {
            boring_sys::SSL_get0_peer_available_trust_anchors(ssl.as_ptr(), &mut list, &mut len);
        }
        if !list.is_null() && len != 0 {
            let offered = unsafe { std::slice::from_raw_parts(list, len) };
            *self.selected.lock().unwrap_or_else(|err| err.into_inner()) =
                select_trusted_id(offered, &self.trusted_ids).map(<[u8]>::to_vec);
        }
        false
    }

    /// The first locally trusted ID in the peer's order, with its wire length.
    pub fn take_selected(&self) -> Option<Vec<u8>> {
        self.selected
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .take()
    }
}

fn entries(mut list: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::from_fn(move || {
        let len = usize::from(*list.first()?);
        if len == 0 || len >= list.len() {
            list = &[];
            return None;
        }
        let (id, rest) = list.split_at(len + 1);
        list = rest;
        Some(id)
    })
}

fn select_trusted_id<'a>(offered: &'a [u8], trusted: &[u8]) -> Option<&'a [u8]> {
    entries(offered).find(|offered_id| entries(trusted).any(|trusted_id| offered_id == &trusted_id))
}
