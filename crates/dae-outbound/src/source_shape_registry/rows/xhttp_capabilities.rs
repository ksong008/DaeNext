use super::*;

pub(super) const XHTTP_H3_WRAPPER: SourceShapeRegistryRow = scoped_evidence_admitted_row(
    registry_source("xhttp-h3-wrapper", "vless", &["vless"])
        .with_transport("quic-tls", "xhttp", "udp-over-stream")
        .with_runtime(
            GENERATION_OWNED_XHTTP_OWNERSHIP,
            "registry:xhttp-h3-wrapper",
        ),
);

// Aggregate report row: extended settings are admitted by individual xHTTP
// builders, but this row does not yet classify every version/download tuple.
pub(super) const XHTTP_EXTENDED_SETTINGS_WRAPPER: SourceShapeRegistryRow = blocked_row(
    registry_source("xhttp-extended-settings-wrapper", "vless", &["vless"])
        .with_transport("plain-or-native-underlay", "xhttp", "extended-xhttp")
        .with_runtime(
            GENERATION_OWNED_XHTTP_OWNERSHIP,
            "registry:xhttp-extended-settings-wrapper",
        ),
    "extended-xhttp-shape-not-exactly-classified",
);
