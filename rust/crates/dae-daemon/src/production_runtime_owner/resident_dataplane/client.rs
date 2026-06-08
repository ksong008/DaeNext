use std::collections::BTreeMap;
use std::io::{Cursor, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs};
use std::pin::Pin;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

use boring::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion};
use dae_datapath::{TcpDirectDialOptions, magic_tcp_connect};
use dae_outbound::shared_transport::{TlsFragmentOptions, fragment_tls_write};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::task;
use tokio::time;

use super::XTLS_RPRX_VISION;
use super::plan::{ResidentProxyPlan, ResidentUtlsFingerprintPlan};
use super::{
    RESIDENT_CONNECT_TIMEOUT, RESIDENT_IDLE_SLEEP, TLS_RECORD_HEADER_LEN,
    TLS_RECORD_MAX_PAYLOAD_LEN,
};

mod types;
pub(super) use self::types::*;
mod sync_client;
use self::sync_client::*;
mod async_client;
use self::async_client::*;
mod record_reader;
use self::record_reader::*;
mod open_client;
pub(super) use self::open_client::*;
mod config;
use self::config::*;
mod resolve;
use self::resolve::*;
mod drive;
pub(super) use self::drive::*;
mod tls_fragment;
use self::tls_fragment::*;
