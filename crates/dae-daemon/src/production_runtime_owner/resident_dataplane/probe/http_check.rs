use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time;

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
    timeout: Duration,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let config = resident_tcp_probe_tls_config();
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|err| format!("resident TCP probe invalid HTTPS server name {host}: {err}"))?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let mut tls = time::timeout(timeout, connector.connect(server_name, stream))
        .await
        .map_err(|_| "resident TCP probe HTTPS handshake timeout".to_owned())?
        .map_err(|err| format!("resident TCP probe create HTTPS client: {err}"))?;
    let request = resident_tcp_probe_http_request(method, path, host);
    time::timeout(timeout, tls.write_all(&request))
        .await
        .map_err(|_| "write resident HTTPS probe request: timeout".to_owned())?
        .map_err(|err| format!("write resident HTTPS probe request: {err}"))?;
    time::timeout(timeout, tls.flush())
        .await
        .map_err(|_| "flush resident HTTPS probe request: timeout".to_owned())?
        .map_err(|err| format!("flush resident HTTPS probe request: {err}"))?;
    read_resident_tcp_probe_response_async(&mut tls, path, timeout).await
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
    timeout: Duration,
) -> Result<(), String>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut response = Vec::new();
    let mut buf = [0_u8; 256];
    while response.len() < 8192 {
        let read = time::timeout(timeout, stream.read(&mut buf))
            .await
            .map_err(|_| "read resident TCP probe response: timeout".to_owned())?
            .map_err(|err| format!("read resident TCP probe response: {err}"))?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buf[..read]);
        if response.windows(2).any(|window| window == b"\r\n") && response.len() >= 12 {
            break;
        }
    }
    if response.is_empty() {
        return Err("resident TCP probe got empty response".to_owned());
    }
    let text = String::from_utf8_lossy(&response);
    let mut fields = text.split_whitespace();
    let version = fields.next().unwrap_or("");
    let status = fields
        .next()
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| format!("resident TCP probe bad HTTP response: {text:?}"))?;
    if !version.starts_with("HTTP/") {
        return Err(format!("resident TCP probe non-HTTP response: {text:?}"));
    }
    if resident_tcp_probe_status_ok(path, status) {
        Ok(())
    } else {
        Err(format!("resident TCP probe bad HTTP status: {status}"))
    }
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
