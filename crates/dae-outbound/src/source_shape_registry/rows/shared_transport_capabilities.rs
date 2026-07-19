use super::*;

// Protocol-closed: proxy transport mode covers HTTP/HTTPS CONNECT
// stream behavior and does not imply CONNECT-UDP/MASQUE support.
pub(super) const PROXY_TRANSPORT_MODE: SourceShapeRegistryRow =
    scoped_evidence_capability_admitted_row(
        registry_source("proxy-transport-mode", "http-proxy", &["http", "https"])
            .with_transport(
                "plain-or-tls-stream-variants",
                "http-transport",
                "protocol-closed",
            )
            .with_runtime(
                FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
                "registry:proxy-transport-mode",
            ),
        PROXY_TRANSPORT_CAPABILITY,
    );

// Protocol-closed: insecure TLS alters certificate verification for
// HTTPS CONNECT, but UDP remains outside the admitted proxy semantics.
pub(super) const INSECURE_SECURE_ENDPOINT_UNDERLAY: SourceShapeRegistryRow =
    scoped_evidence_capability_admitted_row(
        registry_source(
            "insecure-secure-endpoint-underlay",
            "proxy-endpoint",
            &["https"],
        )
        .with_transport("insecure-tls-variants", "none", "protocol-closed")
        .with_runtime(
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
            "registry:insecure-secure-endpoint-underlay",
        ),
        INSECURE_SECURITY_UNDERLAY_CAPABILITY,
    );

// Protocol-closed: fingerprint-aware TLS alters the HTTPS CONNECT
// underlay only; it does not add a UDP packet executor.
pub(super) const FINGERPRINT_SECURE_ENDPOINT_UNDERLAY: SourceShapeRegistryRow =
    scoped_evidence_capability_admitted_row(
        registry_source(
            "fingerprint-secure-endpoint-underlay",
            "proxy-endpoint",
            &["https"],
        )
        .with_transport("fingerprint-aware-tls-variants", "none", "protocol-closed")
        .with_runtime(
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
            "registry:fingerprint-secure-endpoint-underlay",
        ),
        FINGERPRINT_SECURITY_UNDERLAY_CAPABILITY,
    );

pub(super) const INSECURE_FRAME_STREAM_UNDERLAY: SourceShapeRegistryRow =
    scoped_evidence_capability_admitted_row(
        registry_source("insecure-frame-stream-underlay", "anytls", &["anytls"])
            .with_transport("insecure-tls-variants", "frame-stream", "udp-over-stream")
            .with_runtime(
                FLOW_STREAM_PACKET_OWNERSHIP,
                "registry:insecure-frame-stream-underlay",
            ),
        INSECURE_SECURITY_UNDERLAY_CAPABILITY,
    );

pub(super) const FULL_UTLS_SECURITY_UNDERLAY: SourceShapeRegistryRow = blocked_row(
    registry_source(
        "full-utls-security-underlay",
        "shared-transport",
        &["https", "vless", "vmess", "trojan", "trojan-go", "anytls"],
    )
    .with_transport(
        "full-utls",
        "none-or-stream-wrapper",
        "udp-over-stream-or-datagram",
    )
    .with_runtime(
        MATERIALIZED_STREAM_SECURITY_OWNERSHIP,
        "registry:full-utls-security-underlay",
    ),
    "full-utls-wire-parity-not-proven",
);

pub(super) const TLS_FRAGMENT_SECURITY_UNDERLAY: SourceShapeRegistryRow =
    scoped_evidence_capability_admitted_row(
        registry_source(
            "tls-fragment-security-underlay",
            "shared-transport",
            &[
                "https",
                "vless",
                "vmess",
                "trojan",
                "trojan-go",
                "anytls",
                "ss",
                "shadowsocks",
                "socks",
                "socks5",
                "http",
            ],
        )
        .with_transport(
            "tls-fragment",
            "none-or-stream-wrapper",
            "udp-over-stream-or-datagram",
        )
        .with_runtime(
            MATERIALIZED_STREAM_SECURITY_OWNERSHIP,
            "registry:tls-fragment-security-underlay",
        ),
        TLS_FRAGMENT_SECURITY_UNDERLAY_CAPABILITY,
    );

pub(super) const SHARED_REALITY_SECURITY_UNDERLAY: SourceShapeRegistryRow =
    scoped_evidence_capability_admitted_row(
        registry_source(
            "shared-reality-security-underlay",
            "shared-transport",
            &["vless"],
        )
        .with_transport(
            "reality",
            "none-or-stream-wrapper",
            "udp-over-stream-or-datagram",
        )
        .with_runtime(
            MATERIALIZED_STREAM_SECURITY_OWNERSHIP,
            "registry:shared-reality-security-underlay",
        ),
        REALITY_SECURITY_UNDERLAY_CAPABILITY,
    );

pub(super) const MUX_TRANSPORT_WRAPPER: SourceShapeRegistryRow =
    scoped_evidence_capability_admitted_row(
        registry_source("mux-transport-wrapper", "vless", &["vless"])
            .with_transport("tls-stream-variants", "mux", "multiplexed-stream")
            .with_runtime(
                GENERATION_OWNED_VLESS_MUX_OWNERSHIP,
                "registry:mux-transport-wrapper",
            ),
        MUX_TRANSPORT_CAPABILITY,
    );

pub(super) const PASSTHROUGH_UDP_TRANSPORT: SourceShapeRegistryRow = blocked_row(
    registry_source(
        "passthrough-udp-transport",
        "shared-transport",
        &["ss", "shadowsocks", "vless", "vmess", "trojan", "trojan-go"],
    )
    .with_transport(
        "plain-or-native-underlay",
        "none-or-stream-wrapper",
        "passthrough-udp",
    )
    .with_runtime(
        FLOW_STREAM_PACKET_OWNERSHIP,
        "registry:passthrough-udp-transport",
    ),
    "missing-packet-semantics",
);

pub(super) const LEGACY_CIPHER_PROTOCOL_SHAPE: SourceShapeRegistryRow =
    scoped_evidence_capability_admitted_row(
        registry_source(
            "legacy-cipher-protocol-shape",
            "shadowsocksr",
            &["ssr", "shadowsocksr"],
        )
        .with_transport("legacy-cipher", "legacy-obfs", "legacy-udp-fail-closed")
        .with_runtime(
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
            "registry:legacy-cipher-protocol-shape",
        ),
        LEGACY_STREAM_CAPABILITY,
    );
