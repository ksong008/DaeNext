use super::*;

// Policy-closed: these rows require non-Rust-native ABI/runtime/executor
// ownership and must not silently fall back inside the Rust-native matrix.
pub(super) const NON_NATIVE_ABI_OUTBOUND_SHAPE: SourceShapeRegistryRow = not_supported_row(
    registry_source(
        "non-native-abi-outbound-shape",
        "non-rust-native",
        &["ffi", "c-abi"],
    )
    .with_transport("non-native", "non-native", "non-native")
    .with_runtime(
        SOURCE_REJECTED_OWNERSHIP,
        "registry:non-native-abi-outbound-shape",
    ),
    "unsupported-source-policy",
);

pub(super) const EXTERNAL_RUNTIME_DEPENDENT_SHAPE: SourceShapeRegistryRow = not_supported_row(
    registry_source(
        "external-runtime-dependent-shape",
        "foreign-runtime",
        &["foreign-runtime"],
    )
    .with_transport("external", "external", "external")
    .with_runtime(
        SOURCE_REJECTED_OWNERSHIP,
        "registry:external-runtime-dependent-shape",
    ),
    "unsupported-source-policy",
);

pub(super) const NON_NATIVE_EXECUTOR_DEPENDENT_SHAPE: SourceShapeRegistryRow = not_supported_row(
    registry_source(
        "non-native-executor-dependent-shape",
        "non-native-executor",
        &["non-native-executor"],
    )
    .with_transport(
        "non-native-executor",
        "non-native-executor",
        "non-native-executor",
    )
    .with_runtime(
        SOURCE_REJECTED_OWNERSHIP,
        "registry:non-native-executor-dependent-shape",
    ),
    "unsupported-source-policy",
);
