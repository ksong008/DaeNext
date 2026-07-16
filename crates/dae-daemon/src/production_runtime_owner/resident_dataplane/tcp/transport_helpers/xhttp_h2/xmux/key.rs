use std::hash::{Hash, Hasher};

use sha2::{Digest, Sha256};

use crate::production_runtime_owner::resident_dataplane::plan::{
    ResidentRealityUnderlayPlan, ResidentUtlsFingerprintPlan,
};

use super::super::resolved_endpoint::XhttpResolvedEndpointIdentity;
use super::*;

const XHTTP_QUIC_PROVENANCE_DOMAIN: &[u8] = b"dae/xhttp/quic-provenance/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum XhttpCarrierRole {
    Primary,
    Download,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum XhttpCarrierProtocol {
    Http2,
    Http3,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum XhttpTrustIdentity {
    WebPkiRoots,
    ExplicitInsecure,
    Reality,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct XhttpGraphNodeIdentity {
    graph_id: String,
    link_hash: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct XhttpSecurityIdentity {
    trust: XhttpTrustIdentity,
    reality: Option<[u8; 32]>,
    fingerprint: Option<[u8; 32]>,
    tls_fragment: Option<(usize, usize, u64, u64)>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct XhttpSocketIdentity {
    mark: u32,
    mptcp: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(in super::super) struct XhttpXmuxKey {
    role: XhttpCarrierRole,
    graph: Vec<XhttpGraphNodeIdentity>,
    runtime_generation: u64,
    declared_server_host: String,
    declared_server_port: u16,
    resolved_endpoint: XhttpResolvedEndpointIdentity,
    carrier_protocol: XhttpCarrierProtocol,
    server_name: String,
    alpn: Vec<String>,
    security: XhttpSecurityIdentity,
    request_route_identity: [u8; 32],
    xmux: ResidentXhttpXmuxPlan,
    socket: XhttpSocketIdentity,
}

impl XhttpXmuxKey {
    pub(in super::super) fn primary(
        proxy: &ResidentProxyPlan,
        endpoint: &ResidentXhttpEndpointPlan,
        resolved_endpoint: &XhttpResolvedEndpointIdentity,
        xmux: &ResidentXhttpXmuxPlan,
        mark: u32,
        mptcp: bool,
    ) -> Self {
        Self::new(
            XhttpCarrierRole::Primary,
            proxy,
            endpoint,
            resolved_endpoint,
            proxy.utls_fingerprint.as_ref(),
            xmux,
            mark,
            mptcp,
        )
    }

    pub(in super::super) fn download(
        proxy: &ResidentProxyPlan,
        endpoint: &ResidentXhttpEndpointPlan,
        resolved_endpoint: &XhttpResolvedEndpointIdentity,
        xmux: &ResidentXhttpXmuxPlan,
        mark: u32,
        mptcp: bool,
    ) -> Self {
        // Download endpoints use the fixed rustls endpoint client. The primary source fingerprint
        // remains represented by the full graph hash, while no inactive fingerprint option is
        // projected as a download transport setting.
        Self::new(
            XhttpCarrierRole::Download,
            proxy,
            endpoint,
            resolved_endpoint,
            None,
            xmux,
            mark,
            mptcp,
        )
    }

    fn new(
        role: XhttpCarrierRole,
        proxy: &ResidentProxyPlan,
        endpoint: &ResidentXhttpEndpointPlan,
        resolved_endpoint: &XhttpResolvedEndpointIdentity,
        fingerprint: Option<&ResidentUtlsFingerprintPlan>,
        xmux: &ResidentXhttpXmuxPlan,
        mark: u32,
        mptcp: bool,
    ) -> Self {
        let xmux = xmux.clone().official_normalized();
        Self {
            role,
            graph: graph_identity(proxy),
            runtime_generation: xmux.runtime_generation,
            declared_server_host: endpoint.server_host.clone(),
            declared_server_port: endpoint.server_port,
            resolved_endpoint: resolved_endpoint.clone(),
            carrier_protocol: match endpoint.http_version() {
                ResidentXhttpHttpVersion::H3 => XhttpCarrierProtocol::Http3,
                ResidentXhttpHttpVersion::H1 | ResidentXhttpHttpVersion::H2 => {
                    XhttpCarrierProtocol::Http2
                }
            },
            server_name: endpoint.server_name.clone(),
            alpn: endpoint.alpn.clone(),
            security: security_identity(endpoint, fingerprint),
            request_route_identity: request_route_identity(endpoint),
            xmux,
            socket: XhttpSocketIdentity { mark, mptcp },
        }
    }

    pub(super) fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }

    pub(in super::super) fn quic_provenance_identity(&self) -> [u8; 32] {
        let mut hasher = XhttpQuicProvenanceHasher::new();
        self.hash(&mut hasher);
        hasher.finalize()
    }

    #[cfg(test)]
    pub(super) fn isolated_test(
        nonce: u64,
        protocol: ResidentXhttpHttpVersion,
        xmux: ResidentXhttpXmuxPlan,
    ) -> Self {
        let resolved_endpoint =
            XhttpResolvedEndpointIdentity::from_candidates(&["192.0.2.10:443".parse().unwrap()]);
        Self {
            role: XhttpCarrierRole::Primary,
            graph: vec![XhttpGraphNodeIdentity {
                graph_id: format!("resident-graph:{nonce}"),
                link_hash: format!("sha256:{nonce}"),
            }],
            runtime_generation: xmux.runtime_generation,
            declared_server_host: "xmux.invalid".to_owned(),
            declared_server_port: 443,
            resolved_endpoint,
            carrier_protocol: match protocol {
                ResidentXhttpHttpVersion::H3 => XhttpCarrierProtocol::Http3,
                ResidentXhttpHttpVersion::H1 | ResidentXhttpHttpVersion::H2 => {
                    XhttpCarrierProtocol::Http2
                }
            },
            server_name: "xmux.invalid".to_owned(),
            alpn: vec![protocol.alpn_label().to_owned()],
            security: XhttpSecurityIdentity {
                trust: XhttpTrustIdentity::WebPkiRoots,
                reality: None,
                fingerprint: None,
                tls_fragment: None,
            },
            request_route_identity: identity_digest("xhttp-test-route", &[b"/xhttp"]),
            xmux,
            socket: XhttpSocketIdentity {
                mark: 0,
                mptcp: false,
            },
        }
    }
}

struct XhttpQuicProvenanceHasher(Sha256);

impl XhttpQuicProvenanceHasher {
    fn new() -> Self {
        let mut digest = Sha256::new();
        update_identity_part(&mut digest, XHTTP_QUIC_PROVENANCE_DOMAIN);
        Self(digest)
    }

    fn finalize(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

impl Hasher for XhttpQuicProvenanceHasher {
    fn finish(&self) -> u64 {
        let digest = self.0.clone().finalize();
        u64::from_be_bytes(
            digest[..8]
                .try_into()
                .expect("SHA-256 prefix is eight bytes"),
        )
    }

    fn write(&mut self, bytes: &[u8]) {
        update_identity_part(&mut self.0, bytes);
    }
}

fn graph_identity(proxy: &ResidentProxyPlan) -> Vec<XhttpGraphNodeIdentity> {
    let mut identity = Vec::new();
    let mut current = Some(proxy);
    while let Some(node) = current {
        identity.push(XhttpGraphNodeIdentity {
            graph_id: node.graph_id.clone(),
            link_hash: node.graph_link_hash.clone(),
        });
        current = node.chain_parent.as_deref();
    }
    identity
}

fn security_identity(
    endpoint: &ResidentXhttpEndpointPlan,
    fingerprint: Option<&ResidentUtlsFingerprintPlan>,
) -> XhttpSecurityIdentity {
    XhttpSecurityIdentity {
        trust: if endpoint.reality.is_some() {
            XhttpTrustIdentity::Reality
        } else if endpoint.allow_insecure {
            XhttpTrustIdentity::ExplicitInsecure
        } else {
            XhttpTrustIdentity::WebPkiRoots
        },
        reality: endpoint.reality.as_ref().map(reality_identity),
        fingerprint: fingerprint.map(fingerprint_identity),
        tls_fragment: endpoint.tls_fragment.as_ref().map(|fragment| {
            (
                fragment.min_length,
                fragment.max_length,
                fragment.min_interval_ms,
                fragment.max_interval_ms,
            )
        }),
    }
}

fn reality_identity(reality: &ResidentRealityUnderlayPlan) -> [u8; 32] {
    identity_digest(
        "xhttp-reality",
        &[
            reality.public_key.as_slice(),
            reality.short_id.as_slice(),
            reality.spider_x.as_bytes(),
        ],
    )
}

fn fingerprint_identity(fingerprint: &ResidentUtlsFingerprintPlan) -> [u8; 32] {
    let randomized = [u8::from(fingerprint.randomized)];
    let mut parts = vec![
        fingerprint.source.as_bytes(),
        fingerprint.requested.as_bytes(),
        fingerprint.name.as_bytes(),
        fingerprint.canonical.as_bytes(),
        fingerprint.family.as_bytes(),
        fingerprint.client.as_bytes(),
        randomized.as_slice(),
        fingerprint.alpn_policy.as_bytes(),
    ];
    parts.extend(
        fingerprint
            .default_alpn
            .iter()
            .map(|protocol| protocol.as_bytes()),
    );
    identity_digest("xhttp-fingerprint", &parts)
}

fn request_route_identity(endpoint: &ResidentXhttpEndpointPlan) -> [u8; 32] {
    identity_digest(
        "xhttp-request-route",
        &[
            endpoint.stream_host.as_bytes(),
            endpoint.stream_path.as_bytes(),
            endpoint.mode.as_str().as_bytes(),
        ],
    )
}

fn identity_digest(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    update_identity_part(&mut hasher, domain.as_bytes());
    for part in parts {
        update_identity_part(&mut hasher, part);
    }
    hasher.finalize().into()
}

fn update_identity_part(hasher: &mut Sha256, part: &[u8]) {
    hasher.update((part.len() as u64).to_be_bytes());
    hasher.update(part);
}

#[cfg(test)]
#[path = "key/tests.rs"]
mod tests;
