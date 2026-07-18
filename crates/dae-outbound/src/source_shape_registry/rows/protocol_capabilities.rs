use super::*;

pub(super) const LEGACY_LAYER_SHAPE: SourceShapeRegistryRow = blocked_row(
    registry_source(
        "legacy-layer-shape",
        "vmess",
        &["vmess", "socks", "socks5", "http"],
    )
    .with_transport(
        "plain-or-tls-stream-variants",
        "none-or-stream-wrapper",
        "udp-over-stream-or-protocol-closed",
    )
    .with_runtime(
        MATERIALIZED_STREAM_PACKET_OR_POLICY_CLOSED_OWNERSHIP,
        "registry:legacy-layer-shape",
    ),
    "legacy-vmess-wire-parity-not-proven",
);

pub(super) const QUIC_OPTION_SURFACE: SourceShapeRegistryRow = admitted_row(
    registry_source(
        "quic-option-surface",
        "quic-family",
        &["hysteria2", "hy2", "tuic", "juicity"],
    )
    .with_transport("quic-tls", "quic-stream", "quic-datagram-or-stream")
    .with_runtime(
        QUIC_FAMILY_MATERIALIZED_OWNERSHIP,
        "registry:quic-option-surface",
    ),
);

// Protocol-closed: HTTPS proxy endpoints still expose CONNECT/TCP
// semantics; TLS changes the underlay, not UDP support.
pub(super) const SECURE_ENDPOINT_CAPABILITY: SourceShapeRegistryRow = scoped_evidence_admitted_row(
    registry_source("secure-endpoint-capability", "proxy-endpoint", &["https"])
        .with_transport("standard-or-fragmented-tls", "none", "protocol-closed")
        .with_runtime(
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
            "registry:secure-endpoint-capability",
        ),
);

pub(super) const SECURE_WEBSOCKET_FRAMED_ENDPOINT: SourceShapeRegistryRow =
    scoped_evidence_capability_admitted_row(
        registry_source("secure-websocket-framed-endpoint", "vmess", &["vmess"])
            .with_transport("tls-stream-variants", "websocket", "udp-over-stream")
            .with_runtime(
                FLOW_STREAM_PACKET_OWNERSHIP,
                "registry:secure-websocket-framed-endpoint",
            ),
        SECURE_FRAME_STREAM_CAPABILITY,
    );

pub(super) const SECURE_HTTPUPGRADE_FRAMED_ENDPOINT: SourceShapeRegistryRow =
    scoped_evidence_capability_admitted_row(
        registry_source("secure-httpupgrade-framed-endpoint", "vmess", &["vmess"])
            .with_transport("tls-stream-variants", "httpupgrade", "udp-over-stream")
            .with_runtime(
                FLOW_STREAM_PACKET_OWNERSHIP,
                "registry:secure-httpupgrade-framed-endpoint",
            ),
        SECURE_FRAME_STREAM_CAPABILITY,
    );

pub(super) const REALITY_SECURITY_UNDERLAY: SourceShapeRegistryRow =
    scoped_evidence_capability_admitted_row(
        registry_source("reality-security-underlay", "vless", &["vless"])
            .with_transport("reality", "none", "xudp")
            .with_runtime(
                FLOW_STREAM_PACKET_OWNERSHIP,
                "registry:reality-security-underlay",
            ),
        REALITY_SECURITY_UNDERLAY_CAPABILITY,
    );

pub(super) const QUIC_PORT_HOPPING_SURFACE: SourceShapeRegistryRow =
    scoped_evidence_capability_admitted_row(
        registry_source(
            "quic-port-hopping-surface",
            "hysteria2",
            &["hysteria2", "hy2"],
        )
        .with_transport("quic-tls", "quic-stream", "quic-datagram")
        .with_runtime(
            GENERATION_OWNED_HYSTERIA2_OWNERSHIP,
            "registry:quic-port-hopping-surface",
        ),
        QUIC_PORT_HOPPING_CAPABILITY,
    );

pub(super) const VERIFIED_QUIC_SECURITY_UNDERLAY: SourceShapeRegistryRow =
    scoped_evidence_capability_admitted_row(
        registry_source("verified-quic-security-underlay", "tuic", &["tuic"])
            .with_transport("verified-quic-tls", "quic-stream", "quic-packet")
            .with_runtime(
                GENERATION_OWNED_TUIC_OWNERSHIP,
                "registry:verified-quic-security-underlay",
            ),
        VERIFIED_QUIC_CAPABILITY,
    );

pub(super) const INNER_ENCRYPTION_STREAM_WRAPPER: SourceShapeRegistryRow =
    scoped_evidence_capability_admitted_row(
        registry_source(
            "inner-encryption-stream-wrapper",
            "trojan-go",
            &["trojan", "trojan-go"],
        )
        .with_transport(
            "tls-stream-variants-without-fingerprint",
            "websocket",
            "protocol-closed",
        )
        .with_runtime(
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
            "registry:inner-encryption-stream-wrapper",
        ),
        INNER_ENCRYPTION_STREAM_CAPABILITY,
    );

pub(super) const TLS_WEBSOCKET_PLUGIN_WRAPPER: SourceShapeRegistryRow =
    scoped_evidence_capability_admitted_row(
        registry_source(
            "tls-websocket-plugin-wrapper",
            "shadowsocks",
            &["ss", "shadowsocks"],
        )
        .with_transport(
            "standard-or-fragmented-tls",
            "v2ray-plugin-tls-websocket",
            "plugin-udp-policy-closed",
        )
        .with_runtime(
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
            "registry:tls-websocket-plugin-wrapper",
        ),
        PLUGIN_WRAPPER_STREAM_CAPABILITY,
    );

pub(super) const OBFS_TLS_PLUGIN_WRAPPER: SourceShapeRegistryRow =
    scoped_evidence_capability_admitted_row(
        registry_source(
            "obfs-tls-plugin-wrapper",
            "shadowsocks",
            &["ss", "shadowsocks"],
        )
        .with_transport("aead", "simple-obfs-tls", "plugin-udp-policy-closed")
        .with_runtime(
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
            "registry:obfs-tls-plugin-wrapper",
        ),
        PLUGIN_WRAPPER_STREAM_CAPABILITY,
    );

pub(super) const AEAD_2022_PLUGIN_WRAPPER: SourceShapeRegistryRow =
    scoped_evidence_capability_admitted_row(
        registry_source(
            "aead-2022-plugin-wrapper",
            "shadowsocks",
            &["ss", "shadowsocks"],
        )
        .with_transport("aead-2022", "simple-obfs-http", "plugin-udp-policy-closed")
        .with_runtime(
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
            "registry:aead-2022-plugin-wrapper",
        ),
        PLUGIN_WRAPPER_STREAM_CAPABILITY,
    );
