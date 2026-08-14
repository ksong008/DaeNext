use std::hash::{Hash, Hasher};

use sha2::{Digest, Sha256};

use crate::production_runtime_owner::resident_dataplane::plan::{
    ResidentRealityUnderlayPlan, ResidentUtlsFingerprintPlan, ResidentXhttpQuicTlsProvider,
};

use super::super::resolved_endpoint::XhttpResolvedEndpointIdentity;
use super::*;

const XHTTP_QUIC_PROVENANCE_DOMAIN: &[u8] = b"dae/xhttp/quic-provenance/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum XhttpCarrierRole {
    Primary,
    Download,
}

impl XhttpCarrierRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Download => "download",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum XhttpCarrierProtocol {
    Http2,
    Http3,
}

impl XhttpCarrierProtocol {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Http2 => "http2",
            Self::Http3 => "http3",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum XhttpTrustIdentity {
    SystemRoots,
    ExplicitInsecure,
    Reality,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct XhttpSystemCaIdentity {
    path: String,
    sha256: String,
    certificate_count: usize,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct XhttpGraphNodeIdentity {
    graph_id: String,
    link_hash: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct XhttpSecurityIdentity {
    trust: XhttpTrustIdentity,
    system_ca: Option<XhttpSystemCaIdentity>,
    ech: Option<[u8; 32]>,
    reality: Option<[u8; 32]>,
    fingerprint: Option<[u8; 32]>,
    quic_tls_provider: Option<ResidentXhttpQuicTlsProvider>,
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
    session_namespace: [u8; 32],
    request_route_identity: [u8; 32],
    xmux: ResidentXhttpXmuxPlan,
    socket: XhttpSocketIdentity,
}

impl XhttpXmuxKey {
    pub(in super::super) fn primary(
        binding: &ResidentProxyBinding,
        endpoint: &ResidentXhttpEndpointPlan,
        resolved_endpoint: &XhttpResolvedEndpointIdentity,
        xmux: &ResidentXhttpXmuxPlan,
        mark: u32,
        mptcp: bool,
    ) -> Result<Self, String> {
        Self::new(
            XhttpCarrierRole::Primary,
            binding,
            endpoint,
            resolved_endpoint,
            xmux,
            XhttpSocketIdentity { mark, mptcp },
        )
    }

    pub(in super::super) fn download(
        binding: &ResidentProxyBinding,
        endpoint: &ResidentXhttpEndpointPlan,
        resolved_endpoint: &XhttpResolvedEndpointIdentity,
        xmux: &ResidentXhttpXmuxPlan,
        mark: u32,
        mptcp: bool,
    ) -> Result<Self, String> {
        Self::new(
            XhttpCarrierRole::Download,
            binding,
            endpoint,
            resolved_endpoint,
            xmux,
            XhttpSocketIdentity { mark, mptcp },
        )
    }

    fn new(
        role: XhttpCarrierRole,
        binding: &ResidentProxyBinding,
        endpoint: &ResidentXhttpEndpointPlan,
        resolved_endpoint: &XhttpResolvedEndpointIdentity,
        xmux: &ResidentXhttpXmuxPlan,
        socket: XhttpSocketIdentity,
    ) -> Result<Self, String> {
        let proxy = binding.plan();
        let mut xmux = xmux.clone().official_normalized();
        xmux.runtime_generation = binding.runtime_generation().get();
        let carrier_protocol = match endpoint.http_version() {
            ResidentXhttpHttpVersion::H3 => XhttpCarrierProtocol::Http3,
            ResidentXhttpHttpVersion::H1 | ResidentXhttpHttpVersion::H2 => {
                XhttpCarrierProtocol::Http2
            }
        };
        let fingerprint = endpoint.utls_fingerprint.as_ref();
        let quic_tls_provider = match carrier_protocol {
            XhttpCarrierProtocol::Http3 => {
                Some(ResidentXhttpQuicTlsProvider::for_endpoint(fingerprint)?)
            }
            XhttpCarrierProtocol::Http2 => None,
        };
        let system_ca = xhttp_system_ca_identity(endpoint)?;
        let session_namespace = xhttp_session_namespace(
            role,
            carrier_protocol,
            endpoint,
            fingerprint,
            quic_tls_provider,
            system_ca.as_ref(),
        );
        Ok(Self {
            role,
            graph: graph_identity(proxy),
            runtime_generation: binding.runtime_generation().get(),
            declared_server_host: endpoint.server_host.clone(),
            declared_server_port: endpoint.server_port,
            resolved_endpoint: resolved_endpoint.clone(),
            carrier_protocol,
            server_name: endpoint.server_name.clone(),
            alpn: endpoint.alpn.clone(),
            security: security_identity(endpoint, fingerprint, quic_tls_provider, system_ca),
            session_namespace,
            request_route_identity: request_route_identity(endpoint),
            xmux,
            socket,
        })
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
                trust: XhttpTrustIdentity::SystemRoots,
                system_ca: None,
                ech: None,
                reality: None,
                fingerprint: None,
                quic_tls_provider: match protocol {
                    ResidentXhttpHttpVersion::H3 => Some(ResidentXhttpQuicTlsProvider::Rustls),
                    ResidentXhttpHttpVersion::H1 | ResidentXhttpHttpVersion::H2 => None,
                },
                tls_fragment: None,
            },
            session_namespace: identity_digest("xhttp-test-session", &[&nonce.to_be_bytes()]),
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
    quic_tls_provider: Option<ResidentXhttpQuicTlsProvider>,
    system_ca: Option<XhttpSystemCaIdentity>,
) -> XhttpSecurityIdentity {
    XhttpSecurityIdentity {
        trust: if endpoint.reality.is_some() {
            XhttpTrustIdentity::Reality
        } else if endpoint.allow_insecure {
            XhttpTrustIdentity::ExplicitInsecure
        } else {
            XhttpTrustIdentity::SystemRoots
        },
        system_ca,
        ech: endpoint.ech.as_ref().map(|ech| *ech.config_list_sha256()),
        reality: endpoint.reality.as_ref().map(reality_identity),
        fingerprint: fingerprint.map(fingerprint_identity),
        quic_tls_provider,
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

fn xhttp_system_ca_identity(
    endpoint: &ResidentXhttpEndpointPlan,
) -> Result<Option<XhttpSystemCaIdentity>, String> {
    if endpoint.allow_insecure || endpoint.reality.is_some() {
        return Ok(None);
    }
    let snapshot = dae_outbound::shared_transport::system_ca_snapshot()
        .map_err(|err| format!("load xHTTP xmux system CA bundle: {err}"))?;
    let identity = snapshot.identity();
    Ok(Some(XhttpSystemCaIdentity {
        path: identity.path.to_string_lossy().into_owned(),
        sha256: identity.sha256.clone(),
        certificate_count: identity.certificate_count,
    }))
}

fn xhttp_session_namespace(
    role: XhttpCarrierRole,
    protocol: XhttpCarrierProtocol,
    endpoint: &ResidentXhttpEndpointPlan,
    fingerprint: Option<&ResidentUtlsFingerprintPlan>,
    quic_tls_provider: Option<ResidentXhttpQuicTlsProvider>,
    system_ca: Option<&XhttpSystemCaIdentity>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    update_identity_part(&mut digest, b"dae/xhttp/session-namespace/v1");
    update_identity_part(&mut digest, role.as_str().as_bytes());
    update_identity_part(&mut digest, protocol.as_str().as_bytes());
    update_identity_part(&mut digest, endpoint.server_name.as_bytes());
    for alpn in &endpoint.alpn {
        update_identity_part(&mut digest, alpn.as_bytes());
    }
    update_identity_part(&mut digest, &[u8::from(endpoint.allow_insecure)]);
    if let Some(provider) = quic_tls_provider {
        update_identity_part(&mut digest, provider.as_str().as_bytes());
    }
    if let Some(system_ca) = system_ca {
        update_identity_part(&mut digest, system_ca.path.as_bytes());
        update_identity_part(&mut digest, system_ca.sha256.as_bytes());
        update_identity_part(
            &mut digest,
            &(system_ca.certificate_count as u64).to_be_bytes(),
        );
    }
    if let Some(ech) = endpoint.ech.as_ref() {
        update_identity_part(&mut digest, ech.config_list_sha256());
    }
    if let Some(reality) = endpoint.reality.as_ref() {
        update_identity_part(&mut digest, &reality_identity(reality));
    }
    if let Some(fingerprint) = fingerprint {
        update_identity_part(&mut digest, &fingerprint_identity(fingerprint));
    }
    digest.finalize().into()
}

fn reality_identity(reality: &ResidentRealityUnderlayPlan) -> [u8; 32] {
    let mldsa65_verify = reality
        .mldsa65_verify
        .as_ref()
        .map(|key| key.sha256().as_slice())
        .unwrap_or_default();
    identity_digest(
        "xhttp-reality",
        &[
            reality.public_key.as_slice(),
            reality.short_id.as_slice(),
            reality.spider_x.as_bytes(),
            mldsa65_verify,
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
