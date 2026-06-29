use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use boring::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use dae_outbound::shared_transport::reality::REALITY_VERSION;
use dae_outbound::shared_transport::{
    TlsFragmentOptions, UTLS_ALPN_POLICY_RANDOMIZED_ALPN, UTLS_ALPN_POLICY_RANDOMIZED_NO_ALPN,
    UTLS_FAMILY_360, UTLS_FAMILY_ANDROID, UTLS_FAMILY_CHROME, UTLS_FAMILY_EDGE,
    UTLS_FAMILY_FIREFOX, UTLS_FAMILY_IOS, UTLS_FAMILY_QQ, UTLS_FAMILY_RANDOM, fragment_tls_write,
};
use dae_outbound::vless::contract::is_xtls_rprx_vision_flow;
use rustls::client::RealityConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme, SupportedCipherSuite,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::time;

use super::RESIDENT_CONNECT_TIMEOUT;
use super::direct::open_direct_tcp_connection_async;
use super::plan::{
    ResidentProxyPlan, ResidentRealityUnderlayPlan, ResidentUtlsFingerprintPlan,
    ResidentXhttpEndpointPlan,
};

mod types;
pub(super) use self::types::*;
mod async_client;
mod open_client;
pub(super) use self::open_client::*;
mod config;
use self::config::*;
mod drive;
pub(super) use self::drive::*;
mod tls_fragment;
use self::tls_fragment::*;
