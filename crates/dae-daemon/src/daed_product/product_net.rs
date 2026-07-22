use super::*;

const PRODUCT_CONTROL_RESULT_GRACE: Duration = Duration::from_millis(100);
const PRODUCT_PROXY_FETCH_TIMEOUT: Duration = Duration::from_secs(60);

pub(super) fn resolve_tcp_addrs_on_control(
    control_runtime: &ProductControlRuntime,
    host: &str,
    port: u16,
    timeout: Duration,
) -> io::Result<Vec<SocketAddr>> {
    let host = host.trim().to_owned();
    if host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tcp endpoint host is empty",
        ));
    }
    if let Ok(ip) = host.parse() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let wait_timeout = timeout.saturating_add(PRODUCT_CONTROL_RESULT_GRACE);
    control_runtime
        .execute(
            ProductControlTaskKind::Dns,
            wait_timeout,
            move |cancellation| async move {
                tokio::select! {
                    _ = cancellation.cancelled() => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "resolve tcp endpoint",
                    )),
                    resolved = tokio::time::timeout(
                        timeout,
                        tokio::net::lookup_host((host.as_str(), port)),
                    ) => {
                        let resolved = resolved
                            .map_err(|_| io::Error::new(
                                io::ErrorKind::TimedOut,
                                "resolve tcp endpoint",
                            ))??;
                        let addrs = resolved.collect::<Vec<_>>();
                        if addrs.is_empty() {
                            return Err(io::Error::new(
                                io::ErrorKind::AddrNotAvailable,
                                "tcp endpoint resolved to no socket addresses",
                            ));
                        }
                        Ok(addrs)
                    }
                }
            },
        )
        .map_err(product_control_resolver_error)?
}

pub(super) fn connect_tcp_endpoint_on_control(
    control_runtime: &ProductControlRuntime,
    host: &str,
    port: u16,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let mut last_err = None;
    for addr in resolve_tcp_addrs_on_control(control_runtime, host, port, timeout)? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "tcp endpoint resolved to no socket addresses",
        )
    }))
}

fn product_control_resolver_error(error: ProductControlExecutionError) -> io::Error {
    match error {
        ProductControlExecutionError::Busy => {
            io::Error::new(io::ErrorKind::WouldBlock, error.to_string())
        }
        ProductControlExecutionError::Unavailable => {
            io::Error::new(io::ErrorKind::NotConnected, error.to_string())
        }
        ProductControlExecutionError::TimedOut => {
            io::Error::new(io::ErrorKind::TimedOut, "resolve tcp endpoint")
        }
    }
}

pub(super) fn fetch_http_url_via_default_proxy_on_control(
    control_runtime: &ProductControlRuntime,
    config: &Config,
    url: &url::Url,
    tls: bool,
    request: &[u8],
    response_limit: usize,
) -> Result<Vec<u8>, String> {
    let config = config.clone();
    let url = url.clone();
    let request = request.to_vec();
    control_runtime
        .execute(
            ProductControlTaskKind::ProxyHttp,
            PRODUCT_PROXY_FETCH_TIMEOUT.saturating_add(PRODUCT_CONTROL_RESULT_GRACE),
            move |cancellation| async move {
                crate::production_runtime_owner::fetch_http_url_via_default_proxy_async(
                    &config,
                    &url,
                    tls,
                    &request,
                    response_limit,
                    cancellation.cancelled(),
                )
                .await
            },
        )
        .map_err(|error| error.to_string())?
}

pub(super) fn product_default_proxy_config(state: &Path) -> io::Result<Config> {
    let preview = materialize_runtime(state, None, true)?;
    let content = preview
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("runtime materializer did not return content"))?;
    build_runtime_config_from_content(content)
        .map_err(|err| io::Error::other(format!("build default proxy config: {err}")))
}
