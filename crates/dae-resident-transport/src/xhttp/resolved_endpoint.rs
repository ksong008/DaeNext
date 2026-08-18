use std::net::SocketAddr;

use crate::{RESIDENT_CONNECT_TIMEOUT, authority_from_host_port, resolve_socket_addr_candidates};
use dae_resident_plan::ResidentXhttpEndpointPlan;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum XhttpAddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct XhttpResolvedEndpointIdentity {
    candidates: Vec<SocketAddr>,
    families: Vec<XhttpAddressFamily>,
}

pub struct XhttpResolvedEndpoint {
    candidates: Vec<SocketAddr>,
    identity: XhttpResolvedEndpointIdentity,
}

impl XhttpResolvedEndpoint {
    pub async fn resolve(endpoint: &ResidentXhttpEndpointPlan) -> Result<Self, String> {
        let authority = authority_from_host_port(&endpoint.server_host, endpoint.server_port);
        let candidates = resolve_socket_addr_candidates(
            &authority,
            RESIDENT_CONNECT_TIMEOUT,
            "resolve xHTTP shared endpoint",
        )
        .await
        .map_err(|err| err.to_string())?;
        Ok(Self::from_candidates(candidates))
    }

    pub fn candidates(&self) -> &[SocketAddr] {
        &self.candidates
    }

    pub fn identity(&self) -> &XhttpResolvedEndpointIdentity {
        &self.identity
    }

    fn from_candidates(candidates: Vec<SocketAddr>) -> Self {
        let identity = XhttpResolvedEndpointIdentity::from_candidates(&candidates);
        Self {
            candidates,
            identity,
        }
    }
}

impl XhttpResolvedEndpointIdentity {
    pub fn from_candidates(candidates: &[SocketAddr]) -> Self {
        let mut canonical = candidates.to_vec();
        canonical.sort_unstable();
        canonical.dedup();
        let mut families = canonical
            .iter()
            .map(|candidate| {
                if candidate.is_ipv4() {
                    XhttpAddressFamily::Ipv4
                } else {
                    XhttpAddressFamily::Ipv6
                }
            })
            .collect::<Vec<_>>();
        families.sort_unstable();
        families.dedup();
        Self {
            candidates: canonical,
            families,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_identity_is_order_independent_but_family_sensitive() {
        let ipv4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let ipv6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();

        assert_eq!(
            XhttpResolvedEndpointIdentity::from_candidates(&[ipv4, ipv6]),
            XhttpResolvedEndpointIdentity::from_candidates(&[ipv6, ipv4, ipv4])
        );
        assert_ne!(
            XhttpResolvedEndpointIdentity::from_candidates(&[ipv4]),
            XhttpResolvedEndpointIdentity::from_candidates(&[ipv6])
        );
    }
}
