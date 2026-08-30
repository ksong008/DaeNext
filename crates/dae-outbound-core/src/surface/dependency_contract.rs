use super::*;
pub(super) const DEPENDENCY_BOUNDARY_CONTRACT: [OutboundDependencyContract; 23] = [
    dep("aes", OutboundDependencyBoundary::CoreRuntime, true, None),
    dep(
        "aes-gcm",
        OutboundDependencyBoundary::CoreRuntime,
        true,
        None,
    ),
    dep(
        "base64",
        OutboundDependencyBoundary::CoreRuntime,
        true,
        None,
    ),
    dep(
        "blake3",
        OutboundDependencyBoundary::CoreRuntime,
        true,
        None,
    ),
    dep("bytes", OutboundDependencyBoundary::CoreRuntime, true, None),
    dep(
        "chacha20poly1305",
        OutboundDependencyBoundary::CoreRuntime,
        true,
        None,
    ),
    dep(
        "dae-core-types",
        OutboundDependencyBoundary::CoreRuntime,
        true,
        None,
    ),
    dep("hkdf", OutboundDependencyBoundary::CoreRuntime, true, None),
    dep(
        "http",
        OutboundDependencyBoundary::FormalTransport,
        true,
        None,
    ),
    dep("md-5", OutboundDependencyBoundary::CoreRuntime, true, None),
    dep("regex", OutboundDependencyBoundary::CoreRuntime, true, None),
    dep(
        "boring",
        OutboundDependencyBoundary::FormalTransport,
        true,
        None,
    ),
    dep(
        "boring-sys",
        OutboundDependencyBoundary::FormalTransport,
        true,
        None,
    ),
    dep(
        "serde_json",
        OutboundDependencyBoundary::CoreRuntime,
        true,
        None,
    ),
    dep("sha1", OutboundDependencyBoundary::CoreRuntime, true, None),
    dep("sha2", OutboundDependencyBoundary::CoreRuntime, true, None),
    dep("sha3", OutboundDependencyBoundary::CoreRuntime, true, None),
    dep("url", OutboundDependencyBoundary::CoreRuntime, true, None),
    dep(
        "tokio",
        OutboundDependencyBoundary::FormalTransport,
        true,
        Some("transport-runtime"),
    ),
    dep(
        "quinn",
        OutboundDependencyBoundary::FormalTransport,
        true,
        Some("quic-h3"),
    ),
    dep(
        "quinn-boring",
        OutboundDependencyBoundary::FormalTransport,
        true,
        Some("quic-h3"),
    ),
    dep(
        "h3",
        OutboundDependencyBoundary::FormalTransport,
        true,
        Some("quic-h3"),
    ),
    dep(
        "h3-quinn",
        OutboundDependencyBoundary::FormalTransport,
        true,
        Some("quic-h3"),
    ),
];

pub const TEST_SUPPORT_DEPENDENCIES: [OutboundDependencyContract; 1] = [dep(
    "dae-golden",
    OutboundDependencyBoundary::BenchmarkOnly,
    false,
    Some("test-support"),
)];
