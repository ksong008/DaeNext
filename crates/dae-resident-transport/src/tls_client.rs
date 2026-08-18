use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use boring::ex_data::Index;
use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, ConnectConfiguration, Ssl,
    SslConnector, SslConnectorBuilder, SslMethod, SslRef, SslSession, SslSessionCacheMode,
    SslVerifyMode, SslVersion,
};
use boring::x509::{X509StoreContext, X509VerifyError};
use dae_outbound::shared_transport::{
    EchConfigList, Mldsa65VerifyKey, SystemCaIdentity, SystemCaSnapshot, TlsFragmentOptions,
    UTLS_ALPN_POLICY_RANDOMIZED_ALPN, UTLS_ALPN_POLICY_RANDOMIZED_NO_ALPN, UTLS_FAMILY_360,
    UTLS_FAMILY_ANDROID, UTLS_FAMILY_CHROME, UTLS_FAMILY_EDGE, UTLS_FAMILY_FIREFOX, UTLS_FAMILY_QQ,
    UTLS_FAMILY_RANDOM, system_ca_snapshot,
};
#[cfg(test)]
use tokio::io::AsyncReadExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::time;

use crate::{DirectTcpConnection, open_direct_tcp_connection_async};
use crate::{TcpCandidateRacePolicy, authority_from_host_port, try_tcp_socket_addr_candidates};
use dae_resident_core::{
    RESIDENT_CONNECT_TIMEOUT, RESIDENT_TCP_CANDIDATE_ATTEMPT_DELAY,
    RESIDENT_TCP_CANDIDATE_MAX_IN_FLIGHT,
};
use dae_resident_model::{
    ResidentProtocolShape, ResidentProxyBinding, ResidentProxyPlan, ResidentRealityUnderlayPlan,
    ResidentUtlsFingerprintPlan, ResidentXhttpEndpointPlan,
};

mod types;
use self::types::*;
pub use self::types::{
    AsyncResidentTlsClient, AsyncVlessTlsClient, ResidentTlsConfigCacheClearReport,
    clear_resident_tls_config_caches,
};
pub(super) use dae_resident_model::{
    ResidentPeerVerificationPolicy, ResidentTlsFactorySelection, ResidentTlsPolicy,
    ResidentTlsProvider, ResidentTlsSessionPolicy,
};
mod boring_session;
use self::boring_session::*;
mod boring_tls_profile;
pub use self::boring_tls_profile::take_boring_tls_io_profile_snapshot;
use self::boring_tls_profile::{
    configure_boring_tls_profile, record_bio_read, record_bio_write, record_ssl_read,
    record_ssl_write,
};
mod async_client;
mod open_client;
use self::open_client::*;
pub use self::open_client::{
    open_async_resident_tls_client_with_binding,
    open_async_vless_tls_client_with_flow_at_candidates, open_async_xhttp_endpoint_tls_client,
    open_async_xhttp_endpoint_tls_client_at_candidates, open_proxy_tcp_stream_with_binding,
};
mod parent_transport;
use self::parent_transport::*;
mod config;
use self::config::*;
mod reality_boring;
use self::reality_boring::*;
mod reality_boring_cert;
use self::reality_boring_cert::*;
mod reality_boring_ffi;
use self::reality_boring_ffi::*;
mod utls_template_boring;
use self::utls_template_boring::*;
mod drive;
pub use self::drive::{async_resident_tls_underlay_name, async_tls_underlay_name};
mod tls_fragment;
use self::tls_fragment::*;
