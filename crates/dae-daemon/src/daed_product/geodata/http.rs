use super::*;
use super::{GEODATA_REDIRECT_LIMIT, GeodataFileDownload, GeodataKind, GeodataRelease};

use dae_product_control::geodata::{
    GeodataHttpFileResult, GeodataHttpResult, geodata_http_body, geodata_http_request,
    geodata_http_response_limit, geodata_http_response_to_file_from_bytes,
    parse_geodata_latest_release, read_geodata_http_response, read_geodata_http_response_to_file,
};
use dae_tls::{BoringTlsVerification, build_boring_tls_context, connect_boring_tls_sync};

pub(super) fn fetch_geodata_url(
    control_runtime: &ProductControlRuntime,
    url: &url::Url,
) -> io::Result<Vec<u8>> {
    let mut current = url.clone();
    for _ in 0..=GEODATA_REDIRECT_LIMIT {
        match fetch_geodata_url_once(control_runtime, &current)? {
            GeodataHttpResult::Body(body) => return Ok(body),
            GeodataHttpResult::Redirect(next) => current = next,
        }
    }
    Err(io::Error::other("geodata fetch exceeded redirect limit"))
}

pub(super) fn fetch_geodata_url_to_file(
    control_runtime: &ProductControlRuntime,
    url: &url::Url,
    output_path: &Path,
    proxy_config: Option<&Config>,
) -> io::Result<GeodataFileDownload> {
    if let Some(config) = proxy_config {
        return fetch_geodata_url_to_file_via_default_proxy(
            control_runtime,
            url,
            output_path,
            config,
        );
    }
    let mut current = url.clone();
    for _ in 0..=GEODATA_REDIRECT_LIMIT {
        match fetch_geodata_url_to_file_once(control_runtime, &current, output_path)? {
            GeodataHttpFileResult::Body(download) => return Ok(download),
            GeodataHttpFileResult::Redirect(next) => current = next,
        }
    }
    Err(io::Error::other("geodata fetch exceeded redirect limit"))
}

pub(super) fn fetch_geodata_latest_release(
    control_runtime: &ProductControlRuntime,
    kind: GeodataKind,
    api_url: &url::Url,
    proxy_config: Option<&Config>,
) -> io::Result<GeodataRelease> {
    let body = fetch_geodata_url_with_proxy_config(control_runtime, api_url, proxy_config)?;
    parse_geodata_latest_release(kind, &body)
}

fn fetch_geodata_url_with_proxy_config(
    control_runtime: &ProductControlRuntime,
    url: &url::Url,
    proxy_config: Option<&Config>,
) -> io::Result<Vec<u8>> {
    if let Some(config) = proxy_config {
        return fetch_geodata_url_via_default_proxy(control_runtime, url, config);
    }
    fetch_geodata_url(control_runtime, url)
}

fn fetch_geodata_url_via_default_proxy(
    control_runtime: &ProductControlRuntime,
    url: &url::Url,
    config: &Config,
) -> io::Result<Vec<u8>> {
    let mut current = url.clone();
    for _ in 0..=GEODATA_REDIRECT_LIMIT {
        match fetch_geodata_url_once_via_default_proxy(control_runtime, &current, config)? {
            GeodataHttpResult::Body(body) => return Ok(body),
            GeodataHttpResult::Redirect(next) => current = next,
        }
    }
    Err(io::Error::other("geodata fetch exceeded redirect limit"))
}

fn fetch_geodata_url_to_file_via_default_proxy(
    control_runtime: &ProductControlRuntime,
    url: &url::Url,
    output_path: &Path,
    config: &Config,
) -> io::Result<GeodataFileDownload> {
    let mut current = url.clone();
    for _ in 0..=GEODATA_REDIRECT_LIMIT {
        match fetch_geodata_url_to_file_once_via_default_proxy(
            control_runtime,
            &current,
            output_path,
            config,
        )? {
            GeodataHttpFileResult::Body(download) => return Ok(download),
            GeodataHttpFileResult::Redirect(next) => current = next,
        }
    }
    Err(io::Error::other("geodata fetch exceeded redirect limit"))
}

fn fetch_geodata_url_once(
    control_runtime: &ProductControlRuntime,
    url: &url::Url,
) -> io::Result<GeodataHttpResult> {
    let tls = match url.scheme() {
        "https" => true,
        "http" => false,
        scheme => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported geodata url scheme: {scheme}"),
            ));
        }
    };
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing geodata url host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing geodata url port"))?;
    let request = geodata_http_request(url)?;
    let stream =
        connect_tcp_endpoint_on_control(control_runtime, host, port, Duration::from_secs(10))
            .map_err(|err| {
                io::Error::new(err.kind(), format!("connect geodata {host}:{port}: {err}"))
            })?;
    stream.set_read_timeout(Some(Duration::from_secs(90)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    let response = if tls {
        let context = build_boring_tls_context(BoringTlsVerification::SystemRoots)?;
        let mut tls_stream = connect_boring_tls_sync(&context, host, stream)?;
        tls_stream.write_all(request.as_bytes())?;
        tls_stream.flush()?;
        read_geodata_http_response(&mut tls_stream)?
    } else {
        let mut stream = stream;
        stream.write_all(request.as_bytes())?;
        stream.flush()?;
        read_geodata_http_response(&mut stream)?
    };

    geodata_http_body(url, response)
}

fn fetch_geodata_url_once_via_default_proxy(
    control_runtime: &ProductControlRuntime,
    url: &url::Url,
    config: &Config,
) -> io::Result<GeodataHttpResult> {
    let request = geodata_http_request(url)?;
    let response = fetch_geodata_http_response_via_default_proxy(
        control_runtime,
        url,
        config,
        request.as_bytes(),
    )?;
    geodata_http_body(url, response)
}

fn fetch_geodata_url_to_file_once(
    control_runtime: &ProductControlRuntime,
    url: &url::Url,
    output_path: &Path,
) -> io::Result<GeodataHttpFileResult> {
    let tls = match url.scheme() {
        "https" => true,
        "http" => false,
        scheme => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported geodata url scheme: {scheme}"),
            ));
        }
    };
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing geodata url host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing geodata url port"))?;
    let request = geodata_http_request(url)?;
    let stream =
        connect_tcp_endpoint_on_control(control_runtime, host, port, Duration::from_secs(10))
            .map_err(|err| {
                io::Error::new(err.kind(), format!("connect geodata {host}:{port}: {err}"))
            })?;
    stream.set_read_timeout(Some(Duration::from_secs(90)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    if tls {
        let context = build_boring_tls_context(BoringTlsVerification::SystemRoots)?;
        let mut tls_stream = connect_boring_tls_sync(&context, host, stream)?;
        tls_stream.write_all(request.as_bytes())?;
        tls_stream.flush()?;
        read_geodata_http_response_to_file(url, &mut tls_stream, output_path)
    } else {
        let mut stream = stream;
        stream.write_all(request.as_bytes())?;
        stream.flush()?;
        read_geodata_http_response_to_file(url, &mut stream, output_path)
    }
}

fn fetch_geodata_url_to_file_once_via_default_proxy(
    control_runtime: &ProductControlRuntime,
    url: &url::Url,
    output_path: &Path,
    config: &Config,
) -> io::Result<GeodataHttpFileResult> {
    let request = geodata_http_request(url)?;
    let response = fetch_geodata_http_response_via_default_proxy(
        control_runtime,
        url,
        config,
        request.as_bytes(),
    )?;
    geodata_http_response_to_file_from_bytes(url, response, output_path)
}

fn fetch_geodata_http_response_via_default_proxy(
    control_runtime: &ProductControlRuntime,
    url: &url::Url,
    config: &Config,
    request: &[u8],
) -> io::Result<Vec<u8>> {
    let tls = match url.scheme() {
        "https" => true,
        "http" => false,
        scheme => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported geodata url scheme: {scheme}"),
            ));
        }
    };
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing geodata url host"))?;
    fetch_http_url_via_default_proxy_on_control(
        control_runtime,
        config,
        url,
        tls,
        request,
        geodata_http_response_limit()?,
    )
    .map_err(|err| io::Error::other(format!("geodata proxy fetch {host}: {err}")))
}
