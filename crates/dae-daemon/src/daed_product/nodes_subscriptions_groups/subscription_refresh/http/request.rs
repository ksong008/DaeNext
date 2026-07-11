use super::*;

pub(crate) fn subscription_http_request(url: &url::Url) -> io::Result<String> {
    let authority = subscription_http_authority(url)?;
    let mut path = url.path().to_owned();
    if path.is_empty() {
        path = "/".to_owned();
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let user_agent = subscription_user_agent();
    Ok(format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: {user_agent}\r\nAccept: text/plain, application/octet-stream, */*\r\nAccept-Encoding: gzip, br\r\nConnection: close\r\n\r\n"
    ))
}

fn subscription_http_authority(url: &url::Url) -> io::Result<String> {
    let host = match url.host() {
        Some(url::Host::Ipv6(address)) => format!("[{address}]"),
        Some(url::Host::Ipv4(address)) => address.to_string(),
        Some(url::Host::Domain(domain)) => domain.to_owned(),
        None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "missing host")),
    };
    let Some(port) = url.port() else {
        return Ok(host);
    };
    let default_port = match url.scheme() {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    };
    if Some(port) == default_port {
        Ok(host)
    } else {
        Ok(format!("{host}:{port}"))
    }
}

fn subscription_user_agent() -> String {
    format!(
        "dae/{} (like v2rayA/1.0 WebRequestHelper) (like v2rayN/1.0 WebRequestHelper)",
        env!("CARGO_PKG_VERSION")
    )
}
