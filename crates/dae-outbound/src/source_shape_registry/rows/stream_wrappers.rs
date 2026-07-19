use super::*;

pub(super) const STREAM_WRAPPER_WEBSOCKET: SourceShapeRegistryRow = admitted_row(
    registry_source(
        "stream-wrapper-websocket",
        "multi-protocol",
        &["vless", "trojan", "trojan-go"],
    )
    .with_transport(
        "tls-stream-variants-or-reality",
        "websocket",
        "udp-over-stream",
    )
    .with_runtime(
        FLOW_STREAM_PACKET_OWNERSHIP,
        "registry:stream-wrapper-websocket",
    ),
);

pub(super) const PLAIN_WEBSOCKET_FRAMED_ENDPOINT: SourceShapeRegistryRow = admitted_row(
    registry_source("plain-websocket-framed-endpoint", "vmess", &["vmess"])
        .with_transport("none", "websocket", "udp-over-stream")
        .with_runtime(
            FLOW_STREAM_PACKET_OWNERSHIP,
            "registry:plain-websocket-framed-endpoint",
        ),
);

pub(super) const STREAM_WRAPPER_GRPC: SourceShapeRegistryRow = admitted_row(
    registry_source(
        "stream-wrapper-grpc",
        "multi-protocol",
        &["vless", "vmess", "trojan", "trojan-go"],
    )
    .with_transport("tls-stream-variants-or-reality", "grpc", "udp-over-stream")
    .with_runtime(FLOW_STREAM_PACKET_OWNERSHIP, "registry:stream-wrapper-grpc"),
);

pub(super) const STREAM_WRAPPER_HTTPUPGRADE: SourceShapeRegistryRow = admitted_row(
    registry_source(
        "stream-wrapper-httpupgrade",
        "multi-protocol",
        &["vless", "trojan", "trojan-go"],
    )
    .with_transport(
        "tls-stream-variants-or-reality",
        "httpupgrade",
        "udp-over-stream",
    )
    .with_runtime(
        FLOW_STREAM_PACKET_OWNERSHIP,
        "registry:stream-wrapper-httpupgrade",
    ),
);

pub(super) const PLAIN_HTTPUPGRADE_FRAMED_ENDPOINT: SourceShapeRegistryRow = admitted_row(
    registry_source("plain-httpupgrade-framed-endpoint", "vmess", &["vmess"])
        .with_transport("none", "httpupgrade", "udp-over-stream")
        .with_runtime(
            FLOW_STREAM_PACKET_OWNERSHIP,
            "registry:plain-httpupgrade-framed-endpoint",
        ),
);

pub(super) const STREAM_WRAPPER_MEEK: SourceShapeRegistryRow = scoped_evidence_admitted_row(
    registry_source("stream-wrapper-meek", "multi-protocol", &["vless"])
        .with_transport("tls-stream-variants-or-reality", "meek", "protocol-closed")
        .with_runtime(
            GENERATION_OWNED_MEEK_OWNERSHIP,
            "registry:stream-wrapper-meek",
        ),
);

pub(super) const VLESS_MEEK_TLS_STREAM_WRAPPER: SourceShapeRegistryRow = admitted_row(
    registry_source("vless-meek-tls-stream-wrapper", "vless", &["vless"])
        .with_transport("tls-stream-variants", "meek", "protocol-closed")
        .with_runtime(
            GENERATION_OWNED_MEEK_OWNERSHIP,
            "registry:vless-meek-tls-stream-wrapper",
        ),
);

pub(super) const VLESS_MEEK_REALITY_STREAM_WRAPPER: SourceShapeRegistryRow = admitted_row(
    registry_source("vless-meek-reality-stream-wrapper", "vless", &["vless"])
        .with_transport("reality", "meek", "protocol-closed")
        .with_runtime(
            GENERATION_OWNED_MEEK_OWNERSHIP,
            "registry:vless-meek-reality-stream-wrapper",
        ),
);

pub(super) const VLESS_H2_STREAM_WRAPPER: SourceShapeRegistryRow = admitted_row(
    registry_source("vless-h2-stream-wrapper", "vless", &["vless"])
        .with_transport("tls-stream-variants", "h2", "udp-over-stream")
        .with_runtime(
            FLOW_STREAM_PACKET_OWNERSHIP,
            "registry:vless-h2-stream-wrapper",
        ),
);

pub(super) const VMESS_H2_STREAM_WRAPPER: SourceShapeRegistryRow = admitted_row(
    registry_source("vmess-h2-stream-wrapper", "vmess", &["vmess"])
        .with_transport("tls-stream-variants", "h2", "protocol-closed")
        .with_runtime(
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
            "registry:vmess-h2-stream-wrapper",
        ),
);

pub(super) const XHTTP_H1_WRAPPER: SourceShapeRegistryRow = admitted_row(
    registry_source("xhttp-h1-wrapper", "vless", &["vless"])
        .with_transport("tls-stream-variants", "xhttp", "udp-over-stream")
        .with_runtime(CONFIGURED_HTTP_OWNERSHIP, "registry:xhttp-h1-wrapper"),
);

pub(super) const STREAM_WRAPPER_XHTTP: SourceShapeRegistryRow = scoped_evidence_admitted_row(
    registry_source("stream-wrapper-xhttp", "vless", &["vless"])
        .with_transport("tls-stream-variants-or-reality", "xhttp", "udp-over-stream")
        .with_runtime(CONFIGURED_HTTP_OWNERSHIP, "registry:stream-wrapper-xhttp"),
);

pub(super) const NESTED_CHAIN_SHAPE: SourceShapeRegistryRow = scoped_evidence_chain_admitted_row(
    registry_source(
        "nested-chain-shape",
        "multi-protocol",
        &["socks", "socks5", "http"],
    )
    .with_transport(
        "plain-parent-connect-with-child-security-variants",
        "baseline-or-plugin-wrapper",
        "tcp-resident-chain",
    )
    .with_runtime(MATERIALIZED_CHAIN_OWNERSHIP, "registry:nested-chain-shape"),
);

pub(super) const PLUGIN_WRAPPER_LAYER: SourceShapeRegistryRow =
    scoped_evidence_plugin_wrapper_admitted_row(
        registry_source(
            "plugin-wrapper-layer",
            "shadowsocks",
            &["ss", "shadowsocks"],
        )
        .with_transport("aead", "simple-obfs-http", "plugin-udp-policy-closed")
        .with_runtime(
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
            "registry:plugin-wrapper-layer",
        ),
    );
