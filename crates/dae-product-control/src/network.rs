use super::*;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

const PRODUCT_CONTROL_RESULT_GRACE: Duration = Duration::from_millis(100);
const PRODUCT_CONTROL_HELPER_SO_MARK_ENV: &str = "DAED_CONTROL_HELPER_SO_MARK";

pub fn resolve_tcp_addrs_on_control(
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
                        let resolved = resolved.map_err(|_| io::Error::new(
                            io::ErrorKind::TimedOut,
                            "resolve tcp endpoint",
                        ))??;
                        let addresses = resolved.collect::<Vec<_>>();
                        if addresses.is_empty() {
                            return Err(io::Error::new(
                                io::ErrorKind::AddrNotAvailable,
                                "tcp endpoint resolved to no socket addresses",
                            ));
                        }
                        Ok(addresses)
                    }
                }
            },
        )
        .map_err(product_control_resolver_error)?
}

pub fn connect_tcp_endpoint_on_control(
    control_runtime: &ProductControlRuntime,
    host: &str,
    port: u16,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let mut last_error = None;
    for address in resolve_tcp_addrs_on_control(control_runtime, host, port, timeout)? {
        match connect_product_control_tcp_addr(address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "tcp endpoint resolved to no socket addresses",
        )
    }))
}

fn connect_product_control_tcp_addr(
    address: SocketAddr,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let Some(mark) = product_control_helper_so_mark()? else {
        return TcpStream::connect_timeout(&address, timeout);
    };
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_mark(mark)?;
    socket.connect_timeout(&address.into(), timeout)?;
    Ok(socket.into())
}

pub fn product_control_helper_so_mark() -> io::Result<Option<u32>> {
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
pub fn apply_product_control_helper_socket_mark(
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
pub fn apply_product_control_helper_socket_mark<T>(_socket: &T) -> io::Result<()> {
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
