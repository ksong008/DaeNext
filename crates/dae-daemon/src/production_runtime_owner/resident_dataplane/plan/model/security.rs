use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentSecurityUnderlayPlan {
    None,
    Aead,
    Aead2022,
    LegacyCipher,
    StandardTls,
    InsecureTls,
    FragmentedTls,
    FingerprintAwareTls,
    RealityRustls,
    RealityFingerprint,
    QuicTls,
    Unsupported,
}

impl ResidentSecurityUnderlayPlan {
    pub(super) fn from_proxy(
        proxy: &ResidentProxyPlan,
        wrapper: ResidentStreamWrapperPlan,
    ) -> Self {
        if matches!(
            wrapper,
            ResidentStreamWrapperPlan::Xhttp(ResidentXhttpHttpVersion::H3)
        ) {
            return Self::QuicTls;
        }
        if proxy.tls == "reality" {
            return if proxy.utls_fingerprint.is_some() {
                Self::RealityFingerprint
            } else {
                Self::RealityRustls
            };
        }
        if proxy.utls_fingerprint.is_some() {
            return Self::FingerprintAwareTls;
        }
        match proxy.tls.as_str() {
            "" | "none" => Self::None,
            "aead" => Self::Aead,
            "aead-2022" => Self::Aead2022,
            "legacy-cipher" => Self::LegacyCipher,
            "quic" => Self::QuicTls,
            "tls" if proxy.allow_insecure => Self::InsecureTls,
            "tls" if proxy.tls_fragment.is_some() => Self::FragmentedTls,
            "tls" => Self::StandardTls,
            _ => Self::Unsupported,
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn transport_label(
        self,
    ) -> &'static str {
        match self {
            Self::QuicTls => "quic",
            _ => "tcp",
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn graph_label(
        self,
    ) -> &'static str {
        match self {
            Self::None => "none",
            Self::Aead => "aead",
            Self::Aead2022 => "aead-2022",
            Self::LegacyCipher => "legacy-cipher",
            Self::StandardTls => "standard-tls",
            Self::InsecureTls => "insecure-tls",
            Self::FragmentedTls => "tls-fragment",
            Self::FingerprintAwareTls => "fingerprint-aware-tls",
            Self::RealityRustls | Self::RealityFingerprint => "reality",
            Self::QuicTls => "quic-tls",
            Self::Unsupported => "unsupported",
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn is_tls_stream(self) -> bool {
        matches!(
            self,
            Self::StandardTls
                | Self::InsecureTls
                | Self::FragmentedTls
                | Self::FingerprintAwareTls
                | Self::RealityRustls
                | Self::RealityFingerprint
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn is_standard_tls_stream(
        self,
    ) -> bool {
        matches!(
            self,
            Self::StandardTls | Self::InsecureTls | Self::FragmentedTls | Self::FingerprintAwareTls
        )
    }
}
