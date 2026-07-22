use super::request::subscription_http_request;
use super::response::{
    first_header, is_subscription_redirect, parse_subscription_http_response,
    subscription_http_response_limit,
};
use super::*;

pub(crate) fn fetch_http_url_with_proxy_config(
    control_runtime: &ProductControlRuntime,
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
        let raw = exchange_subscription_request(control_runtime, &current, &request, proxy_config)?;
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
    control_runtime: &ProductControlRuntime,
    url: &url::Url,
    request: &str,
    proxy_config: Option<&Config>,
) -> io::Result<Vec<u8>> {
    if let Some(config) = proxy_config {
        return fetch_http_url_via_default_proxy_on_control(
            control_runtime,
            config,
            url,
            url.scheme() == "https",
            request.as_bytes(),
            subscription_http_response_limit(subscription_http_body_limit())?,
        )
        .map_err(|err| io::Error::other(format!("subscription proxy fetch: {err}")));
    }
    super::direct_exchange::exchange_direct_subscription_request(
        control_runtime,
        url,
        request.as_bytes(),
    )
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
