use super::response::subscription_http_response_limit;
use super::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const SUBSCRIPTION_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SUBSCRIPTION_DNS_TIMEOUT: Duration = Duration::from_secs(10);
const SUBSCRIPTION_HTTP_IO_TIMEOUT: Duration = Duration::from_secs(20);
const SUBSCRIPTION_HTTP_CONTROL_TIMEOUT: Duration = Duration::from_secs(60);
const SUBSCRIPTION_HTTP_RESULT_GRACE: Duration = Duration::from_millis(100);

pub(super) fn exchange_direct_subscription_request(
    control_runtime: &ProductControlRuntime,
    url: &url::Url,
    request: &[u8],
) -> io::Result<Vec<u8>> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing host"))?
        .to_owned();
    let port = url.port_or_known_default().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "missing port for subscription")
    })?;
    let use_tls = url.scheme() == "https";
    let request = request.to_vec();
    control_runtime
        .execute(
            ProductControlTaskKind::DirectHttp,
            SUBSCRIPTION_HTTP_CONTROL_TIMEOUT.saturating_add(SUBSCRIPTION_HTTP_RESULT_GRACE),
            move |cancellation| async move {
                exchange_direct_subscription_request_async(
                    &host,
                    port,
                    use_tls,
                    &request,
                    cancellation,
                )
                .await
            },
        )
        .map_err(direct_subscription_control_error)?
}

async fn exchange_direct_subscription_request_async(
    host: &str,
    port: u16,
    use_tls: bool,
    request: &[u8],
    cancellation: ProductControlCancellation,
) -> io::Result<Vec<u8>> {
    let addrs = resolve_subscription_endpoint(host, port, &cancellation).await?;
    let stream = connect_subscription_endpoint(&addrs, &cancellation).await?;
    if use_tls {
        let server_name = ServerName::try_from(host.to_owned()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid tls server name: {error}"),
            )
        })?;
        let connector = tokio_rustls::TlsConnector::from(subscription_tls_client_config());
        let mut stream = wait_for_subscription_io(
            &cancellation,
            connector.connect(server_name, stream),
            "tls connect",
        )
        .await?
        .map_err(|error| io::Error::other(format!("tls connect: {error}")))?;
        write_subscription_request(&mut stream, request, &cancellation).await?;
        read_subscription_response(&mut stream, &cancellation).await
    } else {
        let mut stream = stream;
        write_subscription_request(&mut stream, request, &cancellation).await?;
        read_subscription_response(&mut stream, &cancellation).await
    }
}

async fn resolve_subscription_endpoint(
    host: &str,
    port: u16,
    cancellation: &ProductControlCancellation,
) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let resolved = tokio::select! {
        _ = cancellation.cancelled() => return Err(subscription_cancelled()),
        resolved = tokio::time::timeout(
            SUBSCRIPTION_DNS_TIMEOUT,
            tokio::net::lookup_host((host, port)),
        ) => resolved,
    }
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "resolve tcp endpoint"))??;
    let addrs = resolved.collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "tcp endpoint resolved to no socket addresses",
        ));
    }
    Ok(addrs)
}

async fn connect_subscription_endpoint(
    addrs: &[SocketAddr],
    cancellation: &ProductControlCancellation,
) -> io::Result<tokio::net::TcpStream> {
    let mut last_error = None;
    for addr in addrs {
        let connected = tokio::select! {
            _ = cancellation.cancelled() => return Err(subscription_cancelled()),
            connected = tokio::time::timeout(
                SUBSCRIPTION_TCP_CONNECT_TIMEOUT,
                tokio::net::TcpStream::connect(addr),
            ) => connected,
        };
        match connected {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => {
                last_error = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "connect subscription endpoint",
                ));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "tcp endpoint resolved to no socket addresses",
        )
    }))
}

async fn write_subscription_request<S>(
    stream: &mut S,
    request: &[u8],
    cancellation: &ProductControlCancellation,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    wait_for_subscription_io(
        cancellation,
        stream.write_all(request),
        "write subscription request",
    )
    .await??;
    wait_for_subscription_io(cancellation, stream.flush(), "flush subscription request").await??;
    Ok(())
}

async fn read_subscription_response<S>(
    stream: &mut S,
    cancellation: &ProductControlCancellation,
) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let response_limit = subscription_http_response_limit(subscription_http_body_limit())?;
    let mut response = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = wait_for_subscription_io(
            cancellation,
            stream.read(&mut buffer),
            "read subscription response",
        )
        .await??;
        if read == 0 {
            return Ok(response);
        }
        let next_len = response.len().checked_add(read).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "subscription response size overflow",
            )
        })?;
        if next_len > response_limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("subscription response exceeds {response_limit} bytes"),
            ));
        }
        response.extend_from_slice(&buffer[..read]);
    }
}

async fn wait_for_subscription_io<F>(
    cancellation: &ProductControlCancellation,
    future: F,
    operation: &'static str,
) -> io::Result<F::Output>
where
    F: std::future::Future,
{
    tokio::select! {
        _ = cancellation.cancelled() => Err(subscription_cancelled()),
        result = tokio::time::timeout(SUBSCRIPTION_HTTP_IO_TIMEOUT, future) => {
            result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, operation))
        }
    }
}

fn subscription_tls_client_config() -> Arc<ClientConfig> {
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

fn direct_subscription_control_error(error: ProductControlExecutionError) -> io::Error {
    match error {
        ProductControlExecutionError::Busy => {
            io::Error::new(io::ErrorKind::WouldBlock, error.to_string())
        }
        ProductControlExecutionError::Unavailable => {
            io::Error::new(io::ErrorKind::NotConnected, error.to_string())
        }
        ProductControlExecutionError::TimedOut => io::Error::new(
            io::ErrorKind::TimedOut,
            "subscription fetch operation timed out",
        ),
    }
}

fn subscription_cancelled() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "subscription fetch operation cancelled",
    )
}

#[cfg(test)]
pub(crate) fn subscription_tls_alpn_protocols() -> Vec<Vec<u8>> {
    subscription_tls_client_config().alpn_protocols.clone()
}
