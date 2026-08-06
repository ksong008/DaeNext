use super::*;

const PRODUCT_CONTROL_RESULT_GRACE: Duration = Duration::from_millis(100);
const PRODUCT_PROXY_FETCH_TIMEOUT: Duration = Duration::from_secs(60);
const PRODUCT_CONTROL_HELPER_SO_MARK_ENV: &str = "DAED_CONTROL_HELPER_SO_MARK";

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
        match connect_product_control_tcp_addr(addr, timeout) {
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

fn connect_product_control_tcp_addr(addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    let Some(mark) = product_control_helper_so_mark()? else {
        return TcpStream::connect_timeout(&addr, timeout);
    };
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_mark(mark)?;
    socket.connect_timeout(&addr.into(), timeout)?;
    Ok(socket.into())
}

pub(super) fn product_control_helper_so_mark() -> io::Result<Option<u32>> {
    let Some(raw) = std::env::var_os(PRODUCT_CONTROL_HELPER_SO_MARK_ENV) else {
        return Ok(None);
    };
    let raw = raw.into_string().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{PRODUCT_CONTROL_HELPER_SO_MARK_ENV} is not UTF-8"),
        )
    })?;
    let mark = raw.parse::<u32>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("parse {PRODUCT_CONTROL_HELPER_SO_MARK_ENV}: {error}"),
        )
    })?;
    if mark == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{PRODUCT_CONTROL_HELPER_SO_MARK_ENV} must not be zero"),
        ));
    }
    Ok(Some(mark))
}

#[cfg(target_os = "linux")]
pub(super) fn apply_product_control_helper_socket_mark(
    socket: &impl std::os::fd::AsRawFd,
) -> io::Result<()> {
    let Some(mark) = product_control_helper_so_mark()? else {
        return Ok(());
    };
    let mark = mark as libc::c_uint;
    let status = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            std::ptr::addr_of!(mark).cast::<libc::c_void>(),
            std::mem::size_of_val(&mark) as libc::socklen_t,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(super) fn apply_product_control_helper_socket_mark<T>(_socket: &T) -> io::Result<()> {
    if product_control_helper_so_mark()?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "control helper SO_MARK is only supported on Linux",
        ));
    }
    Ok(())
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
