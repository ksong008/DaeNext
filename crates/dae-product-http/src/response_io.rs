use super::{HttpRequest, HttpResponse, socket_timeout_until, status_reason};
use std::io::{self, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub const PRODUCT_HTTP_RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
pub const PRODUCT_HTTP_REJECT_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

pub fn write_http_response(
    stream: &mut TcpStream,
    response: &HttpResponse,
    head_only: bool,
) -> io::Result<()> {
    write_http_response_with_origin_and_timeout(
        stream,
        None,
        response,
        head_only,
        PRODUCT_HTTP_RESPONSE_WRITE_TIMEOUT,
    )
}

pub fn write_http_response_with_timeout(
    stream: &mut TcpStream,
    response: &HttpResponse,
    head_only: bool,
    timeout: Duration,
) -> io::Result<()> {
    write_http_response_with_origin_and_timeout(stream, None, response, head_only, timeout)
}

pub fn write_http_response_for_request(
    stream: &mut TcpStream,
    request: &HttpRequest,
    response: &HttpResponse,
    head_only: bool,
) -> io::Result<()> {
    write_http_response_with_origin_and_timeout(
        stream,
        request.headers.get("origin").map(String::as_str),
        response,
        head_only,
        PRODUCT_HTTP_RESPONSE_WRITE_TIMEOUT,
    )
}

fn write_http_response_with_origin_and_timeout(
    stream: &mut TcpStream,
    origin: Option<&str>,
    response: &HttpResponse,
    head_only: bool,
    timeout: Duration,
) -> io::Result<()> {
    let mut head = Vec::with_capacity(512);
    let reason = status_reason(response.status);
    write!(
        head,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        reason,
        response.content_type,
        response.body.len()
    )?;
    if let Some(origin) = origin.and_then(allowed_cors_origin_value) {
        write!(
            head,
            "Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\nAccess-Control-Allow-Headers: Authorization, Content-Type, X-Daed-Page-Id\r\nAccess-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD\r\nAccess-Control-Max-Age: 300\r\n",
        )?;
    }
    for (key, value) in &response.extra_headers {
        write!(head, "{key}: {value}\r\n")?;
    }
    write!(head, "\r\n")?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    write_all_with_deadline(stream, &head, deadline)?;
    if !head_only {
        write_all_with_deadline(stream, &response.body, deadline)?;
    }
    stream.set_write_timeout(Some(socket_timeout_until(
        deadline,
        "HTTP response write deadline exceeded",
    )?))?;
    stream.flush()
}

pub fn allowed_cors_origin(request: &HttpRequest) -> Option<&str> {
    request
        .headers
        .get("origin")
        .and_then(|origin| allowed_cors_origin_value(origin))
}

pub fn allowed_cors_origin_value(origin: &str) -> Option<&str> {
    let origin = origin.trim();
    if origin.is_empty() || origin.bytes().any(|byte| byte == b'\r' || byte == b'\n') {
        return None;
    }
    let parsed = url::Url::parse(origin).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed.host_str()?.trim_matches(['[', ']']);
    if is_local_origin_host(host) {
        Some(origin)
    } else {
        None
    }
}

fn is_local_origin_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        return false;
    };
    ip.is_loopback() || local_interface_ips().contains(&ip)
}

struct IfAddrs {
    head: *mut libc::ifaddrs,
}

impl IfAddrs {
    fn load() -> io::Result<Self> {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        let status = unsafe { libc::getifaddrs(&mut head) };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { head })
    }
}

impl Drop for IfAddrs {
    fn drop(&mut self) {
        if !self.head.is_null() {
            unsafe { libc::freeifaddrs(self.head) };
        }
    }
}

fn local_interface_ips() -> Vec<std::net::IpAddr> {
    let mut addrs = Vec::new();
    let Ok(ifaddrs) = IfAddrs::load() else {
        return addrs;
    };
    let mut cursor = ifaddrs.head;
    while !cursor.is_null() {
        let addr = unsafe { (*cursor).ifa_addr };
        if !addr.is_null() {
            match unsafe { (*addr).sa_family as i32 } {
                libc::AF_INET => {
                    let sockaddr = unsafe { *(addr.cast::<libc::sockaddr_in>()) };
                    addrs.push(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                        sockaddr.sin_addr.s_addr.to_ne_bytes(),
                    )));
                }
                libc::AF_INET6 => {
                    let sockaddr = unsafe { *(addr.cast::<libc::sockaddr_in6>()) };
                    addrs.push(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                        sockaddr.sin6_addr.s6_addr,
                    )));
                }
                _ => {}
            }
        }
        cursor = unsafe { (*cursor).ifa_next };
    }
    addrs
}

pub(crate) fn write_all_with_deadline(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(socket_timeout_until(
            deadline,
            "HTTP response write deadline exceeded",
        )?))?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write HTTP response",
                ));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if super::is_socket_timeout(&error) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTP response write deadline exceeded",
                ));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
