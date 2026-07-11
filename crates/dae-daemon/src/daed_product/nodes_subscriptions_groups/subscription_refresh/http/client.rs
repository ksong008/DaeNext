use super::request::subscription_http_request;
use super::response::{
    first_header, is_subscription_redirect, parse_subscription_http_response,
    read_subscription_http_response, subscription_http_response_limit,
};
use super::*;

pub(crate) fn fetch_http_url_with_proxy_config(
    url: &url::Url,
    _tls: bool,
    proxy_config: Option<&Config>,
) -> io::Result<String> {
    let mut current = url.clone();
    let mut visited = HashSet::new();
    for redirect_count in 0..=SUBSCRIPTION_HTTP_REDIRECT_LIMIT {
        validate_redirect_scheme(&current)?;
        if !visited.insert(current.as_str().to_owned()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "subscription redirect loop detected",
            ));
        }
        let request = subscription_http_request(&current)?;
        let raw = exchange_subscription_request(&current, &request, proxy_config)?;
        let response = parse_subscription_http_response(&raw, subscription_http_body_limit())?;
        if is_subscription_redirect(response.status) {
            if redirect_count == SUBSCRIPTION_HTTP_REDIRECT_LIMIT {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "subscription redirect limit exceeded ({SUBSCRIPTION_HTTP_REDIRECT_LIMIT})"
                    ),
                ));
            }
            current = redirect_target(&current, &response)?;
            continue;
        }
        if !(200..300).contains(&response.status) {
            return Err(io::Error::other(format!(
                "subscription fetch returned HTTP {}",
                response.status
            )));
        }
        return String::from_utf8(response.body).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("subscription response is not UTF-8: {err}"),
            )
        });
    }
    unreachable!("bounded subscription redirect loop")
}

fn validate_redirect_scheme(url: &url::Url) -> io::Result<()> {
    if matches!(url.scheme(), "http" | "https") {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("unsupported subscription redirect scheme: {}", url.scheme()),
    ))
}

fn exchange_subscription_request(
    url: &url::Url,
    request: &str,
    proxy_config: Option<&Config>,
) -> io::Result<Vec<u8>> {
    if let Some(config) = proxy_config {
        return crate::production_runtime_owner::fetch_http_url_via_default_proxy(
            config,
            url,
            url.scheme() == "https",
            request.as_bytes(),
            subscription_http_response_limit(subscription_http_body_limit())?,
        )
        .map_err(|err| io::Error::other(format!("subscription proxy fetch: {err}")));
    }
    fetch_http_response(url, request)
}

fn redirect_target(
    current: &url::Url,
    response: &super::response::SubscriptionHttpResponse,
) -> io::Result<url::Url> {
    let location = first_header(&response.headers, "location").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "subscription redirect HTTP {} has no Location",
                response.status
            ),
        )
    })?;
    let next = current.join(location).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid subscription redirect Location: {err}"),
        )
    })?;
    if current.scheme() == "https" && next.scheme() != "https" {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "subscription redirect from HTTPS to a non-HTTPS URL is not allowed",
        ));
    }
    Ok(next)
}

fn fetch_http_response(url: &url::Url, request: &str) -> io::Result<Vec<u8>> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing host"))?;
    let port = url.port_or_known_default().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "missing port for subscription")
    })?;
    let stream = connect_tcp_endpoint(host, port, Duration::from_secs(10))?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;
    if url.scheme() == "https" {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let server_name = ServerName::try_from(host.to_owned()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid tls server name: {err}"),
            )
        })?;
        let conn = ClientConnection::new(config, server_name)
            .map_err(|err| io::Error::other(format!("tls connect: {err}")))?;
        let mut tls_stream = rustls::StreamOwned::new(conn, stream);
        tls_stream.write_all(request.as_bytes())?;
        tls_stream.flush()?;
        read_subscription_http_response(&mut tls_stream)
    } else {
        let mut stream = stream;
        stream.write_all(request.as_bytes())?;
        stream.flush()?;
        read_subscription_http_response(&mut stream)
    }
}
