use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use boring::ssl::{
    HandshakeError as BoringHandshakeError, Ssl, SslContext, SslContextBuilder, SslMethod, SslMode,
    SslOptions, SslVerifyMode,
};
use boring::x509::X509VerifyError;
use boring::x509::verify::X509CheckFlags;

use crate::SystemCaSnapshot;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsClientErrorKind {
    UnknownIssuer,
    HostnameMismatch,
    Expired,
    NotYetValid,
    Certificate,
    Protocol,
    Io,
}

#[derive(Debug)]
pub struct TlsClientError {
    kind: TlsClientErrorKind,
    detail: String,
}

impl TlsClientError {
    pub const fn kind(&self) -> TlsClientErrorKind {
        self.kind
    }
}

impl std::fmt::Display for TlsClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for TlsClientError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoringTlsVerification {
    SystemRoots,
    ExplicitInsecure,
}

pub fn build_boring_tls_context(
    verification: BoringTlsVerification,
) -> io::Result<Arc<SslContext>> {
    build_boring_tls_context_with_alpn(verification, &[])
}

pub fn build_boring_tls_context_with_alpn(
    verification: BoringTlsVerification,
    alpn: &[&[u8]],
) -> io::Result<Arc<SslContext>> {
    let snapshot = match verification {
        BoringTlsVerification::SystemRoots => Some(
            crate::system_ca_snapshot()
                .map_err(|error| io::Error::other(format!("load system CA bundle: {error}")))?,
        ),
        BoringTlsVerification::ExplicitInsecure => None,
    };
    build_boring_tls_context_with_alpn_and_snapshot(verification, alpn, snapshot.as_deref())
}

pub fn build_boring_tls_context_with_system_ca(
    snapshot: &SystemCaSnapshot,
    alpn: &[&[u8]],
) -> io::Result<Arc<SslContext>> {
    build_boring_tls_context_with_alpn_and_snapshot(
        BoringTlsVerification::SystemRoots,
        alpn,
        Some(snapshot),
    )
}

fn build_boring_tls_context_with_alpn_and_snapshot(
    verification: BoringTlsVerification,
    alpn: &[&[u8]],
    snapshot: Option<&SystemCaSnapshot>,
) -> io::Result<Arc<SslContext>> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .map_err(|error| tls_configuration_error("create BoringSSL context", error))?;

    let mut options = SslOptions::ALL
        | SslOptions::NO_COMPRESSION
        | SslOptions::NO_SSLV2
        | SslOptions::NO_SSLV3
        | SslOptions::SINGLE_DH_USE
        | SslOptions::SINGLE_ECDH_USE;
    options &= !SslOptions::DONT_INSERT_EMPTY_FRAGMENTS;
    builder.set_options(options);
    // F-13b: 显式拒绝 TLS 1.0/1.1（BoringSSL 默认允许旧版本协商）。
    builder
        .set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_2))
        .map_err(|error| tls_configuration_error("set minimum TLS version", error))?;
    builder.set_mode(
        SslMode::AUTO_RETRY
            | SslMode::ACCEPT_MOVING_WRITE_BUFFER
            | SslMode::ENABLE_PARTIAL_WRITE
            | SslMode::RELEASE_BUFFERS,
    );
    builder
        .set_cipher_list("DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK")
        .map_err(|error| tls_configuration_error("configure BoringSSL cipher list", error))?;
    if !alpn.is_empty() {
        let mut wire = Vec::new();
        for protocol in alpn {
            if protocol.is_empty() || protocol.len() > u8::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "BoringSSL ALPN item must contain 1..255 bytes",
                ));
            }
            wire.push(protocol.len() as u8);
            wire.extend_from_slice(protocol);
        }
        builder
            .set_alpn_protos(&wire)
            .map_err(|error| tls_configuration_error("configure BoringSSL ALPN", error))?;
    }

    match verification {
        BoringTlsVerification::SystemRoots => {
            let snapshot = snapshot.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "BoringSSL system-roots context requires a CA snapshot",
                )
            })?;
            snapshot.install_boring_builder(&mut builder);
            builder.set_verify(SslVerifyMode::PEER);
        }
        BoringTlsVerification::ExplicitInsecure => builder.set_verify(SslVerifyMode::NONE),
    }

    Ok(Arc::new(builder.build()))
}

pub fn configure_boring_tls_client(context: &SslContext, server_name: &str) -> io::Result<Ssl> {
    let mut ssl = Ssl::new(context)
        .map_err(|error| tls_configuration_error("create BoringSSL connection", error))?;
    if server_name.parse::<IpAddr>().is_err() {
        ssl.set_hostname(server_name)
            .map_err(|error| tls_configuration_error("set BoringSSL server name", error))?;
    }
    let params = ssl.param_mut();
    params.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
    if let Ok(ip) = server_name.parse::<IpAddr>() {
        params
            .set_ip(ip)
            .map_err(|error| tls_configuration_error("set BoringSSL IP verification", error))?;
    } else {
        params.set_host(server_name).map_err(|error| {
            tls_configuration_error("set BoringSSL hostname verification", error)
        })?;
    }
    Ok(ssl)
}

pub async fn connect_boring_tls_async<S>(
    context: &SslContext,
    server_name: &str,
    stream: S,
) -> io::Result<tokio_boring::SslStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let ssl = configure_boring_tls_client(context, server_name)?;
    tokio_boring::SslStreamBuilder::new(ssl, stream)
        .connect()
        .await
        .map_err(async_handshake_error)
}

pub fn connect_boring_tls_sync<S>(
    context: &SslContext,
    server_name: &str,
    stream: S,
) -> io::Result<boring::ssl::SslStream<S>>
where
    S: io::Read + io::Write,
{
    let ssl = configure_boring_tls_client(context, server_name)?;
    ssl.connect(stream).map_err(sync_handshake_error)
}

fn async_handshake_error<S>(error: tokio_boring::HandshakeError<S>) -> io::Error {
    let kind = error
        .ssl()
        .and_then(|ssl| ssl.verify_result().err())
        .map(classify_verify_error)
        .unwrap_or_else(|| {
            if error.as_io_error().is_some() {
                TlsClientErrorKind::Io
            } else {
                TlsClientErrorKind::Protocol
            }
        });
    let io_kind = error
        .as_io_error()
        .map(io::Error::kind)
        .unwrap_or(io::ErrorKind::InvalidData);
    io::Error::new(
        io_kind,
        TlsClientError {
            kind,
            detail: format!("BoringSSL TLS handshake: {error}"),
        },
    )
}

fn sync_handshake_error<S>(error: BoringHandshakeError<S>) -> io::Error {
    let (kind, io_kind) = match &error {
        BoringHandshakeError::SetupFailure(_) => {
            (TlsClientErrorKind::Protocol, io::ErrorKind::InvalidData)
        }
        BoringHandshakeError::Failure(stream) | BoringHandshakeError::WouldBlock(stream) => {
            let kind = stream
                .ssl()
                .verify_result()
                .err()
                .map(classify_verify_error)
                .unwrap_or_else(|| {
                    if stream.error().io_error().is_some() {
                        TlsClientErrorKind::Io
                    } else {
                        TlsClientErrorKind::Protocol
                    }
                });
            let io_kind = stream
                .error()
                .io_error()
                .map(io::Error::kind)
                .unwrap_or(io::ErrorKind::InvalidData);
            (kind, io_kind)
        }
    };
    io::Error::new(
        io_kind,
        TlsClientError {
            kind,
            detail: format!("BoringSSL TLS handshake: {error}"),
        },
    )
}

fn classify_verify_error(error: X509VerifyError) -> TlsClientErrorKind {
    if matches!(
        error,
        X509VerifyError::UNABLE_TO_GET_ISSUER_CERT
            | X509VerifyError::DEPTH_ZERO_SELF_SIGNED_CERT
            | X509VerifyError::SELF_SIGNED_CERT_IN_CHAIN
            | X509VerifyError::UNABLE_TO_GET_ISSUER_CERT_LOCALLY
            | X509VerifyError::UNABLE_TO_VERIFY_LEAF_SIGNATURE
            | X509VerifyError::CERT_UNTRUSTED
    ) {
        TlsClientErrorKind::UnknownIssuer
    } else if error == X509VerifyError::HOSTNAME_MISMATCH {
        TlsClientErrorKind::HostnameMismatch
    } else if error == X509VerifyError::CERT_HAS_EXPIRED {
        TlsClientErrorKind::Expired
    } else if error == X509VerifyError::CERT_NOT_YET_VALID {
        TlsClientErrorKind::NotYetValid
    } else {
        TlsClientErrorKind::Certificate
    }
}

fn tls_configuration_error(operation: &str, error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{operation}: {error}"))
}
