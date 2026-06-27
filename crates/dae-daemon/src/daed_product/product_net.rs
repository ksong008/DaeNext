use super::*;

pub(super) fn resolve_tcp_addrs(
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
    let resolver = thread::Builder::new()
        .name("product-tcp-resolver".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .map_err(|err| io::Error::other(format!("build tcp resolver runtime: {err}")))?;
            let result = runtime.block_on(async {
                let resolved =
                    tokio::time::timeout(timeout, tokio::net::lookup_host((host.as_str(), port)))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "resolve tcp endpoint")
                        })??;
                let addrs = resolved.collect::<Vec<_>>();
                if addrs.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "tcp endpoint resolved to no socket addresses",
                    ));
                }
                Ok(addrs)
            });
            runtime.shutdown_timeout(Duration::from_millis(100));
            result
        })
        .map_err(|err| io::Error::other(format!("spawn tcp resolver: {err}")))?;
    resolver
        .join()
        .map_err(|_| io::Error::other("tcp resolver thread panicked"))?
}

pub(super) fn connect_tcp_endpoint(
    host: &str,
    port: u16,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let mut last_err = None;
    for addr in resolve_tcp_addrs(host, port, timeout)? {
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

pub(super) fn product_default_proxy_config(state: &Path) -> io::Result<Config> {
    let preview = materialize_runtime(state, None, true)?;
    let content = preview
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("runtime materializer did not return content"))?;
    build_runtime_config_from_content(content)
        .map_err(|err| io::Error::other(format!("build default proxy config: {err}")))
}
