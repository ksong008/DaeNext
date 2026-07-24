use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
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
    let config = resident_tcp_probe_tls_config();
    let server_name = ServerName::try_from(host.to_owned()).map_err(|err| {
        ResidentTcpProbeHttpError::new(
            ResidentTcpProbeHttpStage::Security,
            format!("resident TCP probe invalid HTTPS server name {host}: {err}"),
        )
    })?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let mut tls = time::timeout(
        resident_http_probe_remaining(deadline, ResidentTcpProbeHttpStage::Security)?,
        connector.connect(server_name, stream),
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
            format!("resident TCP probe create HTTPS client: {err}"),
        )
    })?;
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
    read_resident_tcp_probe_response_async(&mut tls, path, deadline).await
}

pub(crate) fn resident_tcp_probe_tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }))
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
