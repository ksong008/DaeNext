use super::*;

pub(super) const BASELINE_AEAD_CIPHER_ENDPOINT: SourceShapeRegistryRow = admitted_row(
    registry_source(
        "baseline-aead-cipher-endpoint",
        "shadowsocks",
        &["ss", "shadowsocks"],
    )
    .with_transport("aead", "none", "datagram-aead")
    .with_runtime(
        FLOW_STREAM_PACKET_OWNERSHIP,
        "registry:baseline-aead-cipher-endpoint",
    ),
);

pub(super) const BASELINE_AEAD_2022_CIPHER_ENDPOINT: SourceShapeRegistryRow = admitted_row(
    registry_source(
        "baseline-aead-2022-cipher-endpoint",
        "shadowsocks",
        &["ss", "shadowsocks"],
    )
    .with_transport("aead-2022", "none", "datagram-aead-2022")
    .with_runtime(
        FLOW_STREAM_PACKET_OWNERSHIP,
        "registry:baseline-aead-2022-cipher-endpoint",
    ),
);

pub(super) const BASELINE_TLS_AUTH_ENDPOINT: SourceShapeRegistryRow = admitted_row(
    registry_source(
        "baseline-tls-auth-endpoint",
        "trojan",
        &["trojan", "trojan-go"],
    )
    .with_transport("tls-stream-variants", "none", "udp-over-stream")
    .with_runtime(
        FLOW_STREAM_PACKET_OWNERSHIP,
        "registry:baseline-tls-auth-endpoint",
    ),
);

pub(super) const BASELINE_AEAD_FRAMED_ENDPOINT: SourceShapeRegistryRow = admitted_row(
    registry_source("baseline-aead-framed-endpoint", "vmess", &["vmess"])
        .with_transport("plain-or-tls-stream-variants", "none", "udp-over-stream")
        .with_runtime(
            FLOW_STREAM_PACKET_OWNERSHIP,
            "registry:baseline-aead-framed-endpoint",
        ),
);

pub(super) const VLESS_NATIVE_TCP_ENDPOINT: SourceShapeRegistryRow = admitted_row(
    registry_source("vless-native-tcp-endpoint", "vless", &["vless"])
        .with_transport(
            "plain-or-tls-stream-variants-or-reality",
            "none",
            "udp-over-stream",
        )
        .with_runtime(
            FLOW_STREAM_PACKET_OWNERSHIP,
            "registry:vless-native-tcp-endpoint",
        ),
);

pub(super) const BASELINE_TLS_VISION_ENDPOINT: SourceShapeRegistryRow = admitted_row(
    registry_source("baseline-tls-vision-endpoint", "vless", &["vless"])
        .with_transport("tls-stream-variants", "none", "xudp")
        .with_runtime(
            FLOW_STREAM_PACKET_OWNERSHIP,
            "registry:baseline-tls-vision-endpoint",
        ),
);

pub(super) const BASELINE_QUIC_AUTH_ENDPOINT: SourceShapeRegistryRow = admitted_row(
    registry_source(
        "baseline-quic-auth-endpoint",
        "hysteria2",
        &["hysteria2", "hy2"],
    )
    .with_transport("quic-tls", "quic-stream", "quic-datagram")
    .with_runtime(
        CALLER_SCOPED_HYSTERIA2_OWNERSHIP,
        "registry:baseline-quic-auth-endpoint",
    ),
);

pub(super) const BASELINE_QUIC_UUID_ENDPOINT: SourceShapeRegistryRow = admitted_row(
    registry_source("baseline-quic-uuid-endpoint", "tuic", &["tuic"])
        .with_transport("quic-tls", "quic-stream", "quic-packet")
        .with_runtime(
            CALLER_SCOPED_TUIC_OWNERSHIP,
            "registry:baseline-quic-uuid-endpoint",
        ),
);

pub(super) const BASELINE_QUIC_PASSWORD_ENDPOINT: SourceShapeRegistryRow = admitted_row(
    registry_source("baseline-quic-password-endpoint", "juicity", &["juicity"])
        .with_transport("quic-tls", "quic-stream", "quic-stream-packet")
        .with_runtime(
            CALLER_SCOPED_JUICITY_OWNERSHIP,
            "registry:baseline-quic-password-endpoint",
        ),
);

pub(super) const BASELINE_FRAME_STREAM_ENDPOINT: SourceShapeRegistryRow = admitted_row(
    registry_source("baseline-frame-stream-endpoint", "anytls", &["anytls"])
        .with_transport(
            "standard-or-fragmented-tls",
            "frame-stream",
            "udp-over-stream",
        )
        .with_runtime(
            FLOW_STREAM_PACKET_OWNERSHIP,
            "registry:baseline-frame-stream-endpoint",
        ),
);

// Protocol-closed: plain HTTP proxy import maps to CONNECT/TCP only;
// UDP requires a protocol with explicit datagram semantics.
pub(super) const BASELINE_CONNECT_ENDPOINT: SourceShapeRegistryRow = admitted_row(
    registry_source("baseline-connect-endpoint", "http-proxy", &["http"])
        .with_transport("none", "none", "protocol-closed")
        .with_runtime(
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
            "registry:baseline-connect-endpoint",
        ),
);

pub(super) const BASELINE_SOCKS_ENDPOINT: SourceShapeRegistryRow = admitted_row(
    registry_source("baseline-socks-endpoint", "socks5", &["socks5", "socks"])
        .with_transport("none", "none", "udp-associate")
        .with_runtime(
            FLOW_STREAM_ASSOCIATION_OWNERSHIP,
            "registry:baseline-socks-endpoint",
        ),
);

pub(super) const CONNECT_UDP_H2_ENDPOINT: SourceShapeRegistryRow = not_supported_row(
    registry_source("connect-udp-h2-endpoint", "connect-udp", &["masque"])
        .with_transport(
            "standard-or-insecure-tls",
            "connect-udp-h2",
            "connect-udp-capsule",
        )
        .with_runtime(
            SOURCE_REJECTED_OWNERSHIP,
            "registry:connect-udp-h2-endpoint",
        ),
    "unsupported-source-policy",
);

pub(super) const CONNECT_UDP_H3_ENDPOINT: SourceShapeRegistryRow = not_supported_row(
    registry_source("connect-udp-h3-endpoint", "connect-udp", &["masque"])
        .with_transport("quic-tls", "connect-udp-h3", "connect-udp-http-datagram")
        .with_runtime(
            SOURCE_REJECTED_OWNERSHIP,
            "registry:connect-udp-h3-endpoint",
        ),
    "unsupported-source-policy",
);
