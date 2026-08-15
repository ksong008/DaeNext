use super::*;

/// Provider-independent certificate/authentication policy consumed by the
/// resident TLS factory. Keeping this separate from BoringSSL configuration
/// objects keeps every transport on the same typed intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ResidentPeerVerificationPolicy {
    SystemRoots,
    ExplicitInsecure,
    Reality {
        public_key: [u8; 32],
        short_id: Vec<u8>,
    },
}

impl ResidentPeerVerificationPolicy {
    pub(crate) const fn evidence_label(&self) -> &'static str {
        match self {
            Self::SystemRoots => "system-roots",
            Self::ExplicitInsecure => "explicit-insecure",
            Self::Reality { .. } => "reality-auth-key",
        }
    }

    pub(crate) const fn allow_insecure(&self) -> bool {
        matches!(self, Self::ExplicitInsecure)
    }

    pub(crate) fn reality_material(&self) -> Option<(&[u8; 32], &[u8])> {
        match self {
            Self::Reality {
                public_key,
                short_id,
            } => Some((public_key, short_id)),
            Self::SystemRoots | Self::ExplicitInsecure => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidentTlsSessionPolicy {
    /// Preserve the provider's current TLS session-cache behavior. Application
    /// data is never sent as TLS early data on the resident TCP path.
    ProviderManagedNoEarlyData,
    /// QUIC owns resumption. Application data may only use 0-RTT when the
    /// protocol executor explicitly opts into Quinn's early connection path.
    QuicManaged {
        cache_scope: ResidentTlsSessionCacheScope,
        zero_rtt: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidentTlsSessionCacheScope {
    ProviderConfig,
    ReloadGeneration,
}

impl ResidentTlsSessionCacheScope {
    pub(crate) const fn evidence_label(self) -> &'static str {
        match self {
            Self::ProviderConfig => "provider-config",
            Self::ReloadGeneration => "reload-generation",
        }
    }
}

impl ResidentTlsSessionPolicy {
    pub(crate) const fn resumption_label(self) -> &'static str {
        match self {
            Self::ProviderManagedNoEarlyData => "provider-managed",
            Self::QuicManaged { .. } => "quic-session-cache",
        }
    }

    pub(crate) const fn zero_rtt_admitted(self) -> bool {
        matches!(self, Self::QuicManaged { zero_rtt: true, .. })
    }

    pub(crate) const fn cache_scope_label(self) -> &'static str {
        match self {
            Self::ProviderManagedNoEarlyData => "provider-config",
            Self::QuicManaged { cache_scope, .. } => cache_scope.evidence_label(),
        }
    }
}

/// Protocol-generic TLS policy. This is deliberately free of provider types
/// so BoringSSL transport shapes cannot diverge in SNI, ALPN, verification,
/// Reality authentication, resumption, or 0-RTT intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentTlsPolicy {
    pub(crate) server_name: String,
    pub(crate) alpn: Vec<String>,
    pub(crate) verification: ResidentPeerVerificationPolicy,
    pub(crate) session: ResidentTlsSessionPolicy,
}

impl ResidentTlsPolicy {
    pub(crate) fn from_proxy(proxy: &ResidentProxyPlan) -> Self {
        Self {
            server_name: proxy.server_name.clone(),
            alpn: proxy.alpn.clone(),
            verification: verification_policy(proxy.allow_insecure, proxy.reality.as_ref()),
            session: ResidentTlsSessionPolicy::ProviderManagedNoEarlyData,
        }
    }

    pub(crate) fn from_xhttp_endpoint(endpoint: &ResidentXhttpEndpointPlan) -> Self {
        Self {
            server_name: endpoint.server_name.clone(),
            alpn: endpoint.alpn.clone(),
            verification: verification_policy(endpoint.allow_insecure, endpoint.reality.as_ref()),
            session: ResidentTlsSessionPolicy::ProviderManagedNoEarlyData,
        }
    }
}

fn verification_policy(
    allow_insecure: bool,
    reality: Option<&ResidentRealityUnderlayPlan>,
) -> ResidentPeerVerificationPolicy {
    if let Some(reality) = reality {
        ResidentPeerVerificationPolicy::Reality {
            public_key: reality.public_key,
            short_id: reality.short_id.clone(),
        }
    } else if allow_insecure {
        ResidentPeerVerificationPolicy::ExplicitInsecure
    } else {
        ResidentPeerVerificationPolicy::SystemRoots
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentTlsFactorySelection {
    pub(crate) provider: ResidentTlsProvider,
    pub(crate) policy: ResidentTlsPolicy,
}

impl ResidentTlsFactorySelection {
    pub(crate) fn from_proxy(proxy: &ResidentProxyPlan) -> Result<Self, String> {
        Ok(Self {
            provider: ResidentTlsProvider::from_proxy(proxy)?,
            policy: ResidentTlsPolicy::from_proxy(proxy),
        })
    }

    pub(crate) fn from_xhttp_endpoint(
        endpoint: &ResidentXhttpEndpointPlan,
    ) -> Result<Self, String> {
        Ok(Self {
            provider: ResidentTlsProvider::from_xhttp_endpoint(endpoint)?,
            policy: ResidentTlsPolicy::from_xhttp_endpoint(endpoint),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{ResidentProxyProtocolPlan, ResidentXhttpMode, ResidentXhttpSettingsPlan};

    #[test]
    fn ordinary_tls_factory_keeps_typed_system_root_policy() {
        let proxy = test_proxy_plan(ResidentProxyProtocolPlan::TrojanTcpTls {
            password: "secret".to_owned(),
        });
        let selection = ResidentTlsFactorySelection::from_proxy(&proxy).unwrap();

        assert_eq!(
            selection.provider,
            ResidentTlsProvider::FingerprintAwareBoring
        );
        assert_eq!(selection.policy.server_name, proxy.server_name);
        assert_eq!(selection.policy.alpn, proxy.alpn);
        assert_eq!(
            selection.policy.verification,
            ResidentPeerVerificationPolicy::SystemRoots
        );
        assert_eq!(
            selection.policy.session,
            ResidentTlsSessionPolicy::ProviderManagedNoEarlyData
        );
        assert!(!selection.policy.session.zero_rtt_admitted());
    }

    #[test]
    fn reality_factory_keeps_auth_material_in_typed_policy() {
        let mut proxy = test_proxy_plan(ResidentProxyProtocolPlan::VlessVisionTcpTls {
            key: [0; 16],
            encryption: None,
        });
        proxy.tls = "reality".to_owned();
        proxy.reality = Some(ResidentRealityUnderlayPlan {
            public_key: [7; 32],
            short_id: vec![1, 2, 3, 4],
            spider_x: "/".to_owned(),
            mldsa65_verify: None,
        });
        proxy.materialize_execution();

        let selection = ResidentTlsFactorySelection::from_proxy(&proxy).unwrap();
        assert_eq!(
            selection.provider,
            ResidentTlsProvider::RealityFingerprintBoring
        );
        assert_eq!(
            selection.policy.verification,
            ResidentPeerVerificationPolicy::Reality {
                public_key: [7; 32],
                short_id: vec![1, 2, 3, 4],
            }
        );
        assert_eq!(
            selection.policy.verification.evidence_label(),
            "reality-auth-key"
        );
    }

    #[test]
    fn xhttp_endpoint_policy_preserves_insecure_and_alpn_intent() {
        let mut proxy = test_proxy_plan(ResidentProxyProtocolPlan::VlessVisionTcpTls {
            key: [0; 16],
            encryption: None,
        });
        proxy.allow_insecure = true;
        proxy.alpn = vec!["h2".to_owned()];
        let endpoint = ResidentXhttpEndpointPlan::from_proxy(&proxy);
        let selection = ResidentTlsFactorySelection::from_xhttp_endpoint(&endpoint).unwrap();

        assert_eq!(selection.policy.alpn, vec!["h2"]);
        assert_eq!(
            selection.policy.verification,
            ResidentPeerVerificationPolicy::ExplicitInsecure
        );
        assert_eq!(
            selection.provider,
            ResidentTlsProvider::FingerprintAwareBoring
        );
    }

    fn test_proxy_plan(handler: ResidentProxyProtocolPlan) -> ResidentProxyPlan {
        let mut proxy = ResidentProxyPlan {
            graph_id: "resident-graph:test".to_owned(),
            graph_link_hash: "sha256:test".to_owned(),
            redacted_link_source: "source:<redacted>".to_owned(),
            protocol: "trojan",
            group_name: "proxy".to_owned(),
            group_policy: "fixed".to_owned(),
            node_tag: "test".to_owned(),
            server_host: "127.0.0.1".to_owned(),
            server_port: 443,
            server_name: "example.com".to_owned(),
            alpn: Vec::new(),
            flow: String::new(),
            net: "tcp".to_owned(),
            stream_host: String::new(),
            stream_path: String::new(),
            grpc_mode: dae_outbound::shared_transport::GrpcMode::Gun,
            xhttp_download: None,
            xhttp_mode: ResidentXhttpMode::PacketUp,
            xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
            xhttp_xmux: None,
            tls: "tls".to_owned(),
            allow_insecure: false,
            tls_fragment: None,
            utls_fingerprint: None,
            ech: None,
            reality: None,
            handler,
            execution: None,
            chain_parent: None,
            mark: 0,
            mptcp: false,
        };
        proxy.materialize_execution();
        proxy
    }
}
