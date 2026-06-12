use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use boring::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use dae_outbound::shared_transport::{TlsFragmentOptions, fragment_tls_write};
use rustls::client::RealityConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::time;

use super::RESIDENT_CONNECT_TIMEOUT;
use super::XTLS_RPRX_VISION;
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
