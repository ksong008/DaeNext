use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, SslConnector, SslConnectorBuilder,
    SslMethod, SslRef, SslVerifyMode, SslVersion,
};
use boring::x509::{X509StoreContext, X509VerifyError};
use dae_outbound::shared_transport::{
    EchConfigList, Mldsa65VerifyKey, SystemCaIdentity, SystemCaSnapshot, TlsFragmentOptions,
    UTLS_ALPN_POLICY_RANDOMIZED_ALPN, UTLS_ALPN_POLICY_RANDOMIZED_NO_ALPN, UTLS_FAMILY_360,
    UTLS_FAMILY_ANDROID, UTLS_FAMILY_CHROME, UTLS_FAMILY_EDGE, UTLS_FAMILY_FIREFOX, UTLS_FAMILY_QQ,
    UTLS_FAMILY_RANDOM, system_ca_snapshot,
};
use rustls::client::RealityConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme,
    SupportedCipherSuite,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::time;

use super::direct::{DirectTcpConnection, open_direct_tcp_connection_async};
use super::plan::{
    ResidentProtocolShape, ResidentProxyBinding, ResidentProxyPlan, ResidentRealityUnderlayPlan,
    ResidentSecurityUnderlayPlan, ResidentUtlsFingerprintPlan, ResidentXhttpEndpointPlan,
};
use super::resolver::{
    TcpCandidateRacePolicy, authority_from_host_port, try_tcp_socket_addr_candidates,
};
use super::{
    RESIDENT_CONNECT_TIMEOUT, RESIDENT_TCP_CANDIDATE_ATTEMPT_DELAY,
    RESIDENT_TCP_CANDIDATE_MAX_IN_FLIGHT,
};

mod types;
pub(super) use self::types::*;
mod policy;
pub(super) use self::policy::*;
mod async_client;
mod open_client;
pub(super) use self::open_client::*;
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
pub(super) use self::drive::*;
mod tls_fragment;
use self::tls_fragment::*;
