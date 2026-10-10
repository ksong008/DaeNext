use super::*;

#[derive(Default)]
pub(super) struct ProtocolIdentityCache<const N: usize> {
    value: Option<(&'static [u8], [u8; N], UdpResponseIdentityToken)>,
}

impl<const N: usize> ProtocolIdentityCache<N> {
    pub(super) fn token(
        &mut self,
        domain: &'static [u8],
        identity: [u8; N],
    ) -> Option<UdpResponseIdentityToken> {
        if let Some((cached_domain, cached_identity, token)) = self.value
            && cached_domain == domain
            && cached_identity == identity
        {
            return Some(token);
        }
        let token = UdpResponseIdentityToken::from_protocol_identity(domain, &identity)?;
        self.value = Some((domain, identity, token));
        Some(token)
    }
}

#[cfg(test)]
#[path = "identity_cache_tests.rs"]
mod tests;
