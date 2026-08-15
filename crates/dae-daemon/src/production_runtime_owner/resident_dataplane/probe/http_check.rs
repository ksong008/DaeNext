use std::time::Duration;

use crate::boring_tls::{
    BoringTlsVerification, build_boring_tls_context, connect_boring_tls_async,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidentTcpProbeHttpStage {
    Security,
    Write,
    Read,
}

#[derive(Debug)]
pub(crate) struct ResidentTcpProbeHttpError {
    pub(crate) stage: ResidentTcpProbeHttpStage,
    pub(crate) detail: String,
}

impl ResidentTcpProbeHttpError {
    fn new(stage: ResidentTcpProbeHttpStage, detail: impl Into<String>) -> Self {
        Self {
            stage,
            detail: detail.into(),
        }
    }
}

pub(crate) fn resident_tcp_probe_http_request(method: &str, path: &str, host: &str) -> Vec<u8> {
    let method = if method.is_empty() { "HEAD" } else { method };
    let path = if path.is_empty() { "/" } else { path };
    format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: dae-rust-resident-check\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

pub(crate) async fn read_resident_tcp_probe_https_response_over_stream_async<S>(
    stream: S,
    host: &str,
    path: &str,
    method: &str,
    deadline: dae_runtime_control::AbsoluteDeadline,
) -> Result<(), ResidentTcpProbeHttpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let context = build_boring_tls_context(BoringTlsVerification::SystemRoots).map_err(|err| {
        ResidentTcpProbeHttpError::new(
            ResidentTcpProbeHttpStage::Security,
            format!("resident TCP probe create BoringSSL context: {err}"),
        )
    })?;
    let mut tls = time::timeout(
        resident_http_probe_remaining(deadline, ResidentTcpProbeHttpStage::Security)?,
        connect_boring_tls_async(&context, host, stream),
    )
    .await
    .map_err(|_| {
        ResidentTcpProbeHttpError::new(
            ResidentTcpProbeHttpStage::Security,
            "resident TCP probe HTTPS handshake timeout",
        )
    })?
    .map_err(|err| {
        ResidentTcpProbeHttpError::new(
            ResidentTcpProbeHttpStage::Security,
            format!("resident TCP probe create BoringSSL HTTPS client: {err}"),
        )
    })?;
    exchange_resident_tcp_probe_https(&mut tls, host, path, method, deadline).await
}

async fn exchange_resident_tcp_probe_https<S>(
    tls: &mut S,
    host: &str,
    path: &str,
    method: &str,
    deadline: dae_runtime_control::AbsoluteDeadline,
) -> Result<(), ResidentTcpProbeHttpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = resident_tcp_probe_http_request(method, path, host);
    time::timeout(
        resident_http_probe_remaining(deadline, ResidentTcpProbeHttpStage::Write)?,
        tls.write_all(&request),
    )
    .await
    .map_err(|_| {
        ResidentTcpProbeHttpError::new(
            ResidentTcpProbeHttpStage::Write,
            "write resident HTTPS probe request: timeout",
        )
    })?
    .map_err(|err| {
        ResidentTcpProbeHttpError::new(
            ResidentTcpProbeHttpStage::Write,
            format!("write resident HTTPS probe request: {err}"),
        )
    })?;
    time::timeout(
        resident_http_probe_remaining(deadline, ResidentTcpProbeHttpStage::Write)?,
        tls.flush(),
    )
    .await
    .map_err(|_| {
        ResidentTcpProbeHttpError::new(
            ResidentTcpProbeHttpStage::Write,
            "flush resident HTTPS probe request: timeout",
        )
    })?
    .map_err(|err| {
        ResidentTcpProbeHttpError::new(
            ResidentTcpProbeHttpStage::Write,
            format!("flush resident HTTPS probe request: {err}"),
        )
    })?;
    read_resident_tcp_probe_response_async(tls, path, deadline).await
}

pub(crate) async fn read_resident_tcp_probe_response_async<S>(
    stream: &mut S,
    path: &str,
    deadline: dae_runtime_control::AbsoluteDeadline,
) -> Result<(), ResidentTcpProbeHttpError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut response = Vec::new();
    let mut buf = [0_u8; 256];
    while response.len() < 8192 {
        let read = time::timeout(
            resident_http_probe_remaining(deadline, ResidentTcpProbeHttpStage::Read)?,
            stream.read(&mut buf),
        )
        .await
        .map_err(|_| {
            ResidentTcpProbeHttpError::new(
                ResidentTcpProbeHttpStage::Read,
                "read resident TCP probe response: timeout",
            )
        })?
        .map_err(|err| {
            ResidentTcpProbeHttpError::new(
                ResidentTcpProbeHttpStage::Read,
                format!("read resident TCP probe response: {err}"),
            )
        })?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buf[..read]);
        if response.windows(2).any(|window| window == b"\r\n") && response.len() >= 12 {
            break;
        }
    }
    if response.is_empty() {
        return Err(ResidentTcpProbeHttpError::new(
            ResidentTcpProbeHttpStage::Read,
            "resident TCP probe got empty response",
        ));
    }
    let text = String::from_utf8_lossy(&response);
    let mut fields = text.split_whitespace();
    let version = fields.next().unwrap_or("");
    let status = fields
        .next()
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| {
            ResidentTcpProbeHttpError::new(
                ResidentTcpProbeHttpStage::Read,
                format!("resident TCP probe bad HTTP response: {text:?}"),
            )
        })?;
    if !version.starts_with("HTTP/") {
        return Err(ResidentTcpProbeHttpError::new(
            ResidentTcpProbeHttpStage::Read,
            format!("resident TCP probe non-HTTP response: {text:?}"),
        ));
    }
    if resident_tcp_probe_status_ok(path, status) {
        Ok(())
    } else {
        Err(ResidentTcpProbeHttpError::new(
            ResidentTcpProbeHttpStage::Read,
            format!("resident TCP probe bad HTTP status: {status}"),
        ))
    }
}

fn resident_http_probe_remaining(
    deadline: dae_runtime_control::AbsoluteDeadline,
    stage: ResidentTcpProbeHttpStage,
) -> Result<Duration, ResidentTcpProbeHttpError> {
    deadline
        .remaining_at(std::time::Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| ResidentTcpProbeHttpError::new(stage, "deadline elapsed"))
}

pub(crate) fn resident_tcp_probe_status_ok(path: &str, status: u16) -> bool {
    let page = path.rsplit('/').next().unwrap_or("");
    if let Some(expected) = page.strip_prefix("generate_")
        && let Ok(expected) = expected.parse::<u16>()
    {
        return status == expected;
    }
    (200..500).contains(&status)
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::Poll;

    use rcgen::generate_simple_self_signed;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
    use tokio::sync::oneshot;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls;
    use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

    /// Reproduces the handoff shape used by the native HTTPS probe: the inner
    /// TLS application read is polled before the peer has written its first
    /// application record, then the peer writes and the same read must wake.
    #[tokio::test(flavor = "current_thread")]
    async fn rustls_application_read_wakes_after_duplex_peer_write() {
        let certified = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let certificate = certified.cert.der().clone();
        let private_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let server_config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![certificate.clone()], private_key)
                .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (first_poll_tx, first_poll_rx) = oneshot::channel();

        let server = tokio::spawn(async move {
            let mut tls = acceptor.accept(server_io).await.unwrap();
            let mut request = [0_u8; 1];
            tls.read_exact(&mut request).await.unwrap();
            first_poll_rx.await.unwrap();
            tls.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            tls.flush().await.unwrap();
        });

        let server_name = ServerName::try_from("localhost".to_owned()).unwrap();
        let mut tls = connector.connect(server_name, client_io).await.unwrap();
        tls.write_all(b"x").await.unwrap();
        tls.flush().await.unwrap();

        let read_task = tokio::spawn(async move {
            let mut tls = tls;
            let mut buf = [0_u8; 32];
            let mut first_poll_tx = Some(first_poll_tx);
            std::future::poll_fn(move |cx| {
                // Signal only after the read future is actually polled. The
                // server is blocked on this signal and therefore cannot make
                // the first poll spuriously Ready.
                if let Some(tx) = first_poll_tx.take() {
                    let _ = tx.send(());
                }
                let mut read_buf = ReadBuf::new(&mut buf);
                match Pin::new(&mut tls).poll_read(cx, &mut read_buf) {
                    Poll::Ready(result) => Poll::Ready(result.map(|_| read_buf.filled().len())),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await
            .unwrap()
        });

        let read = tokio::time::timeout(std::time::Duration::from_secs(1), read_task)
            .await
            .unwrap()
            .unwrap();
        assert!(read > 0);
        server.await.unwrap();
    }
}
