mod client;
mod system_ca;

pub use client::{
    BoringTlsVerification, TlsClientError, TlsClientErrorKind, build_boring_tls_context,
    build_boring_tls_context_with_alpn, build_boring_tls_context_with_system_ca,
    configure_boring_tls_client, connect_boring_tls_async, connect_boring_tls_sync,
};
pub use system_ca::{
    SYSTEM_CA_BUNDLE_PATHS, SystemCaError, SystemCaIdentity, SystemCaSnapshot,
    invalidate_system_ca_snapshot, system_ca_snapshot,
};
