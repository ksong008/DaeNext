use super::*;
use base64::{Engine as _, engine::general_purpose};
use tokio::io::{AsyncWrite, AsyncWriteExt};

pub(crate) fn xhttp_h2_request(
    method: http::Method,
    endpoint: &impl ResidentXhttpEndpointView,
    path_suffix: &str,
    has_body: bool,
) -> Result<http::Request<()>, String> {
    let meta = XhttpRequestMeta::from_path_suffix(path_suffix);
    let method = xhttp_effective_method(method, endpoint.xhttp_settings(), has_body)?;
    xhttp_h2_request_with_parts(method, endpoint, meta, has_body, Vec::new(), Vec::new())
}

pub(crate) fn xhttp_h1_request_bytes(
    method: http::Method,
    endpoint: &impl ResidentXhttpEndpointView,
    path_suffix: &str,
    body: Option<&Bytes>,
) -> Vec<u8> {
    let meta = XhttpRequestMeta::from_path_suffix(path_suffix);
    let method = xhttp_effective_method(method.clone(), endpoint.xhttp_settings(), body.is_some())
        .unwrap_or(method);
    let mut bytes = xhttp_h1_request_bytes_with_parts(
        method,
        endpoint,
        meta,
        body.is_some(),
        body.map(|body| body.len()),
        Vec::new(),
        Vec::new(),
    );
    if let Some(body) = body {
        bytes.extend_from_slice(body);
    }
    bytes
}

pub(super) fn xhttp_h1_packet_up_request_bytes(
    endpoint: &impl ResidentXhttpEndpointView,
    session_id: &str,
    seq: u64,
    payload: Bytes,
) -> Result<Vec<u8>, String> {
    let plan = xhttp_packet_payload_plan(endpoint.xhttp_settings(), payload)?;
    let method = xhttp_method_from_settings(endpoint.xhttp_settings())?;
    let mut bytes = xhttp_h1_request_bytes_with_parts(
        method,
        endpoint,
        XhttpRequestMeta::new(Some(session_id), Some(seq.to_string())),
        false,
        plan.body.as_ref().map(Bytes::len),
        plan.headers,
        plan.cookies,
    );
    if let Some(body) = plan.body {
        bytes.extend_from_slice(&body);
    }
    Ok(bytes)
}

pub(super) fn xhttp_h2_packet_up_request(
    endpoint: &impl ResidentXhttpEndpointView,
    session_id: &str,
    seq: u64,
    payload: Bytes,
) -> Result<(http::Request<()>, Option<Bytes>), String> {
    let plan = xhttp_packet_payload_plan(endpoint.xhttp_settings(), payload)?;
    let method = xhttp_method_from_settings(endpoint.xhttp_settings())?;
    let request = xhttp_h2_request_with_parts(
        method,
        endpoint,
        XhttpRequestMeta::new(Some(session_id), Some(seq.to_string())),
        plan.body.is_some(),
        plan.headers,
        plan.cookies,
    )?;
    Ok((request, plan.body))
}

pub(super) fn xhttp_h3_packet_up_request(
    endpoint: &impl ResidentXhttpEndpointView,
    session_id: &str,
    seq: u64,
    payload: Bytes,
) -> Result<(http::Request<()>, Option<Bytes>), String> {
    let plan = xhttp_packet_payload_plan(endpoint.xhttp_settings(), payload)?;
    let method = xhttp_method_from_settings(endpoint.xhttp_settings())?;
    let request = xhttp_h3_request_with_parts(
        method,
        endpoint,
        XhttpRequestMeta::new(Some(session_id), Some(seq.to_string())),
        plan.body.is_some(),
        plan.headers,
        plan.cookies,
    )?;
    Ok((request, plan.body))
}

pub(super) async fn write_xhttp_h1_chunked_request_head<W>(
    writer: &mut W,
    endpoint: &impl ResidentXhttpEndpointView,
    path_suffix: &str,
    context: &str,
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    let method = xhttp_method_from_settings(endpoint.xhttp_settings())?;
    let mut request = xhttp_h1_request_head_string(
        method,
        endpoint,
        XhttpRequestMeta::from_path_suffix(path_suffix),
        true,
        None,
        Vec::new(),
        Vec::new(),
    );
    request.push_str("Transfer-Encoding: chunked\r\n\r\n");
    time::timeout(
        RESIDENT_CONNECT_TIMEOUT,
        writer.write_all(request.as_bytes()),
    )
    .await
    .map_err(|_| format!("xHTTP HTTP/1.1 {context} request headers timeout"))?
    .map_err(|err| format!("write xHTTP HTTP/1.1 {context} request headers: {err}"))?;
    time::timeout(RESIDENT_CONNECT_TIMEOUT, writer.flush())
        .await
        .map_err(|_| format!("flush xHTTP HTTP/1.1 {context} request headers timeout"))?
        .map_err(|err| format!("flush xHTTP HTTP/1.1 {context} request headers: {err}"))
}

pub(super) async fn write_xhttp_h1_chunk<W>(
    writer: &mut W,
    payload: &Bytes,
    end_stream: bool,
    context: &str,
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    if !payload.is_empty() {
        let prefix = format!("{:x}\r\n", payload.len());
        time::timeout(
            RESIDENT_CONNECT_TIMEOUT,
            writer.write_all(prefix.as_bytes()),
        )
        .await
        .map_err(|_| format!("xHTTP HTTP/1.1 {context} chunk prefix timeout"))?
        .map_err(|err| format!("write xHTTP HTTP/1.1 {context} chunk prefix: {err}"))?;
        time::timeout(RESIDENT_CONNECT_TIMEOUT, writer.write_all(payload))
            .await
            .map_err(|_| format!("xHTTP HTTP/1.1 {context} chunk body timeout"))?
            .map_err(|err| format!("write xHTTP HTTP/1.1 {context} chunk body: {err}"))?;
        time::timeout(RESIDENT_CONNECT_TIMEOUT, writer.write_all(b"\r\n"))
            .await
            .map_err(|_| format!("xHTTP HTTP/1.1 {context} chunk suffix timeout"))?
            .map_err(|err| format!("write xHTTP HTTP/1.1 {context} chunk suffix: {err}"))?;
    }
    if end_stream {
        time::timeout(RESIDENT_CONNECT_TIMEOUT, writer.write_all(b"0\r\n\r\n"))
            .await
            .map_err(|_| format!("xHTTP HTTP/1.1 {context} final chunk timeout"))?
            .map_err(|err| format!("write xHTTP HTTP/1.1 {context} final chunk: {err}"))?;
    }
    time::timeout(RESIDENT_CONNECT_TIMEOUT, writer.flush())
        .await
        .map_err(|_| format!("flush xHTTP HTTP/1.1 {context} chunk timeout"))?
        .map_err(|err| format!("flush xHTTP HTTP/1.1 {context} chunk: {err}"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct XhttpRequestMeta {
    session_id: Option<String>,
    seq: Option<String>,
}

impl XhttpRequestMeta {
    fn new(session_id: Option<&str>, seq: Option<String>) -> Self {
        Self {
            session_id: session_id.map(str::to_owned),
            seq,
        }
    }

    fn from_path_suffix(path_suffix: &str) -> Self {
        let suffix = path_suffix.trim_matches('/');
        if suffix.is_empty() {
            return Self {
                session_id: None,
                seq: None,
            };
        }
        match suffix.split_once('/') {
            Some((session_id, seq)) => Self {
                session_id: Some(session_id.to_owned()),
                seq: Some(seq.to_owned()),
            },
            None => Self {
                session_id: Some(suffix.to_owned()),
                seq: None,
            },
        }
    }
}

struct XhttpPacketPayloadPlan {
    body: Option<Bytes>,
    headers: Vec<(String, String)>,
    cookies: Vec<(String, String)>,
}

fn xhttp_packet_payload_plan(
    settings: &ResidentXhttpSettingsPlan,
    payload: Bytes,
) -> Result<XhttpPacketPayloadPlan, String> {
    match settings.uplink_data_placement {
        ResidentXhttpUplinkDataPlacement::Auto | ResidentXhttpUplinkDataPlacement::Body => {
            Ok(XhttpPacketPayloadPlan {
                body: Some(payload),
                headers: Vec::new(),
                cookies: Vec::new(),
            })
        }
        ResidentXhttpUplinkDataPlacement::Header => Ok(XhttpPacketPayloadPlan {
            body: None,
            headers: xhttp_encoded_payload_chunks(
                settings.normalized_uplink_data_key(),
                '-',
                settings,
                &payload,
            ),
            cookies: Vec::new(),
        }),
        ResidentXhttpUplinkDataPlacement::Cookie => Ok(XhttpPacketPayloadPlan {
            body: None,
            headers: Vec::new(),
            cookies: xhttp_encoded_payload_chunks(
                settings.normalized_uplink_data_key(),
                '_',
                settings,
                &payload,
            ),
        }),
    }
}

fn xhttp_encoded_payload_chunks(
    key: &str,
    separator: char,
    settings: &ResidentXhttpSettingsPlan,
    payload: &Bytes,
) -> Vec<(String, String)> {
    if payload.is_empty() || key.is_empty() {
        return Vec::new();
    }
    let encoded = general_purpose::URL_SAFE_NO_PAD.encode(payload);
    let chunk_size =
        ResidentXhttpSettingsPlan::sample_range(settings.normalized_uplink_chunk_size()).max(1)
            as usize;
    encoded
        .as_bytes()
        .chunks(chunk_size)
        .enumerate()
        .map(|(index, chunk)| {
            (
                format!("{key}{separator}{index}"),
                String::from_utf8_lossy(chunk).into_owned(),
            )
        })
        .collect()
}

struct XhttpPreparedRequestParts {
    uri: String,
    path_and_query: String,
    headers: Vec<(String, String)>,
}

fn xhttp_h2_request_with_parts(
    method: http::Method,
    endpoint: &impl ResidentXhttpEndpointView,
    meta: XhttpRequestMeta,
    grpc_body_header: bool,
    extra_headers: Vec<(String, String)>,
    extra_cookies: Vec<(String, String)>,
) -> Result<http::Request<()>, String> {
    let prepared = xhttp_prepare_request_parts(
        endpoint,
        meta,
        grpc_body_header,
        extra_headers,
        extra_cookies,
    );
    let mut builder = http::Request::builder().method(method).uri(prepared.uri);
    for (name, value) in prepared.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder
        .body(())
        .map_err(|err| format!("build xHTTP HTTP/2 request: {err}"))
}

fn xhttp_h3_request_with_parts(
    method: http::Method,
    endpoint: &impl ResidentXhttpEndpointView,
    meta: XhttpRequestMeta,
    grpc_body_header: bool,
    extra_headers: Vec<(String, String)>,
    extra_cookies: Vec<(String, String)>,
) -> Result<http::Request<()>, String> {
    let prepared = xhttp_prepare_request_parts(
        endpoint,
        meta,
        grpc_body_header,
        extra_headers,
        extra_cookies,
    );
    let mut builder = http::Request::builder().method(method).uri(prepared.uri);
    for (name, value) in prepared.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder
        .body(())
        .map_err(|err| format!("build xHTTP H3 request: {err}"))
}

fn xhttp_h1_request_bytes_with_parts(
    method: http::Method,
    endpoint: &impl ResidentXhttpEndpointView,
    meta: XhttpRequestMeta,
    grpc_body_header: bool,
    content_length: Option<usize>,
    extra_headers: Vec<(String, String)>,
    extra_cookies: Vec<(String, String)>,
) -> Vec<u8> {
    let mut request = xhttp_h1_request_head_string(
        method,
        endpoint,
        meta,
        grpc_body_header,
        content_length,
        extra_headers,
        extra_cookies,
    );
    request.push_str("\r\n");
    request.into_bytes()
}

fn xhttp_h1_request_head_string(
    method: http::Method,
    endpoint: &impl ResidentXhttpEndpointView,
    meta: XhttpRequestMeta,
    grpc_body_header: bool,
    content_length: Option<usize>,
    extra_headers: Vec<(String, String)>,
    extra_cookies: Vec<(String, String)>,
) -> String {
    let prepared = xhttp_prepare_request_parts(
        endpoint,
        meta,
        grpc_body_header,
        extra_headers,
        extra_cookies,
    );
    let mut request = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\n",
        prepared.path_and_query,
        xhttp_authority(endpoint)
    );
    for (name, value) in prepared.headers {
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        request.push_str(&name);
        request.push_str(": ");
        request.push_str(&value);
        request.push_str("\r\n");
    }
    request.push_str("Connection: close\r\n");
    if let Some(content_length) = content_length {
        request.push_str(&format!("Content-Length: {content_length}\r\n"));
    }
    request
}

fn xhttp_prepare_request_parts(
    endpoint: &impl ResidentXhttpEndpointView,
    meta: XhttpRequestMeta,
    grpc_body_header: bool,
    extra_headers: Vec<(String, String)>,
    extra_cookies: Vec<(String, String)>,
) -> XhttpPreparedRequestParts {
    let settings = endpoint.xhttp_settings();
    let mut headers = xhttp_default_headers(settings);
    for (name, value) in extra_headers {
        xhttp_set_header(&mut headers, name, value);
    }
    let mut cookies = extra_cookies;
    let mut query = Vec::new();
    xhttp_apply_padding(endpoint, &mut headers, &mut cookies, &mut query);
    xhttp_apply_meta(settings, &meta, &mut headers, &mut cookies, &mut query);
    if grpc_body_header && !settings.no_grpc_header {
        xhttp_set_header(
            &mut headers,
            http::header::CONTENT_TYPE.as_str().to_owned(),
            "application/grpc".to_owned(),
        );
    }
    xhttp_apply_cookie_header(&mut headers, cookies);
    let path_and_query = xhttp_path_and_query_with_meta(endpoint, &meta, &query);
    let uri = format!("https://{}{}", xhttp_authority(endpoint), path_and_query);
    XhttpPreparedRequestParts {
        uri,
        path_and_query,
        headers,
    }
}

fn xhttp_default_headers(settings: &ResidentXhttpSettingsPlan) -> Vec<(String, String)> {
    let mut headers = settings
        .headers
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<Vec<_>>();
    xhttp_push_default_header(
        &mut headers,
        http::header::USER_AGENT.as_str(),
        "Mozilla/5.0",
    );
    xhttp_push_default_header(&mut headers, http::header::ACCEPT.as_str(), "*/*");
    xhttp_push_default_header(
        &mut headers,
        http::header::ACCEPT_LANGUAGE.as_str(),
        "en-US,en;q=0.9",
    );
    xhttp_push_default_header(
        &mut headers,
        http::header::CACHE_CONTROL.as_str(),
        "no-cache",
    );
    xhttp_push_default_header(&mut headers, "pragma", "no-cache");
    headers
}

fn xhttp_push_default_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    if !headers
        .iter()
        .any(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
    {
        headers.push((name.to_owned(), value.to_owned()));
    }
}

fn xhttp_set_header(headers: &mut Vec<(String, String)>, name: String, value: String) {
    headers.retain(|(candidate, _)| !candidate.eq_ignore_ascii_case(&name));
    headers.push((name, value));
}

fn xhttp_apply_cookie_header(headers: &mut Vec<(String, String)>, cookies: Vec<(String, String)>) {
    if cookies.is_empty() {
        return;
    }
    let cookie_value = cookies
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    if let Some((_, existing)) = headers
        .iter_mut()
        .find(|(name, _)| name.eq_ignore_ascii_case(http::header::COOKIE.as_str()))
    {
        if !existing.is_empty() {
            existing.push_str("; ");
        }
        existing.push_str(&cookie_value);
    } else {
        headers.push((http::header::COOKIE.as_str().to_owned(), cookie_value));
    }
}

fn xhttp_apply_meta(
    settings: &ResidentXhttpSettingsPlan,
    meta: &XhttpRequestMeta,
    headers: &mut Vec<(String, String)>,
    cookies: &mut Vec<(String, String)>,
    query: &mut Vec<(String, String)>,
) {
    if let Some(session_id) = meta.session_id.as_deref() {
        match settings.session_id_placement {
            ResidentXhttpMetaPlacement::Path => {}
            ResidentXhttpMetaPlacement::Query => {
                query.push((
                    settings.normalized_session_key().to_owned(),
                    session_id.to_owned(),
                ));
            }
            ResidentXhttpMetaPlacement::Header => xhttp_set_header(
                headers,
                settings.normalized_session_key().to_owned(),
                session_id.to_owned(),
            ),
            ResidentXhttpMetaPlacement::Cookie => {
                cookies.push((
                    settings.normalized_session_key().to_owned(),
                    session_id.to_owned(),
                ));
            }
        }
    }
    if let Some(seq) = meta.seq.as_deref() {
        match settings.seq_placement {
            ResidentXhttpMetaPlacement::Path => {}
            ResidentXhttpMetaPlacement::Query => {
                query.push((settings.normalized_seq_key().to_owned(), seq.to_owned()));
            }
            ResidentXhttpMetaPlacement::Header => {
                xhttp_set_header(
                    headers,
                    settings.normalized_seq_key().to_owned(),
                    seq.to_owned(),
                );
            }
            ResidentXhttpMetaPlacement::Cookie => {
                cookies.push((settings.normalized_seq_key().to_owned(), seq.to_owned()));
            }
        }
    }
}

fn xhttp_apply_padding(
    endpoint: &impl ResidentXhttpEndpointView,
    headers: &mut Vec<(String, String)>,
    cookies: &mut Vec<(String, String)>,
    query: &mut Vec<(String, String)>,
) {
    let settings = endpoint.xhttp_settings();
    let padding_len = ResidentXhttpSettingsPlan::sample_range(settings.normalized_x_padding_bytes())
        .max(0) as usize;
    let padding = xhttp_generate_padding(settings.x_padding_method, padding_len);
    if !settings.x_padding_obfs_mode {
        xhttp_set_header(
            headers,
            http::header::REFERER.as_str().to_owned(),
            xhttp_padding_referer(&xhttp_uri(endpoint, ""), &padding),
        );
        return;
    }
    match settings.x_padding_placement {
        ResidentXhttpPaddingPlacement::Header => {
            xhttp_set_header(headers, settings.x_padding_header.clone(), padding);
        }
        ResidentXhttpPaddingPlacement::QueryInHeader => {
            xhttp_set_header(
                headers,
                settings.x_padding_header.clone(),
                xhttp_query_in_header_padding(
                    &xhttp_uri(endpoint, ""),
                    &settings.x_padding_key,
                    &padding,
                ),
            );
        }
        ResidentXhttpPaddingPlacement::Query => {
            query.push((settings.x_padding_key.clone(), padding));
        }
        ResidentXhttpPaddingPlacement::Cookie => {
            cookies.push((settings.x_padding_key.clone(), padding));
        }
    }
}

fn xhttp_generate_padding(method: ResidentXhttpPaddingMethod, len: usize) -> String {
    if len == 0 {
        return String::new();
    }
    match method {
        ResidentXhttpPaddingMethod::RepeatX => "X".repeat(len),
        ResidentXhttpPaddingMethod::Tokenish => {
            const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            let token_len = ((len as f64) / 0.8).ceil().max(1.0) as usize;
            (0..token_len)
                .map(|_| BASE62[fastrand::usize(..BASE62.len())] as char)
                .collect()
        }
    }
}

fn xhttp_query_in_header_padding(base_uri: &str, key: &str, padding: &str) -> String {
    let base_without_query = base_uri.split_once('?').map_or(base_uri, |(base, _)| base);
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair(key, padding);
    let query = serializer.finish();
    format!("{base_without_query}?{query}")
}

fn xhttp_method_from_settings(
    settings: &ResidentXhttpSettingsPlan,
) -> Result<http::Method, String> {
    settings
        .uplink_http_method
        .parse::<http::Method>()
        .map_err(|err| format!("parse xHTTP uplinkHTTPMethod: {err}"))
}

fn xhttp_effective_method(
    method: http::Method,
    settings: &ResidentXhttpSettingsPlan,
    has_body: bool,
) -> Result<http::Method, String> {
    if has_body {
        xhttp_method_from_settings(settings)
    } else {
        Ok(method)
    }
}

pub(crate) fn xhttp_uri(endpoint: &impl ResidentXhttpEndpointView, path_suffix: &str) -> String {
    let path_and_query = xhttp_path_and_query_with_meta(
        endpoint,
        &XhttpRequestMeta::from_path_suffix(path_suffix),
        &[],
    );
    format!("https://{}{}", xhttp_authority(endpoint), path_and_query)
}

fn xhttp_path_and_query_with_meta(
    endpoint: &impl ResidentXhttpEndpointView,
    meta: &XhttpRequestMeta,
    extra_query: &[(String, String)],
) -> String {
    let normalized = ir::normalize_xhttp_path_and_query(endpoint.stream_path());
    let mut path = normalized.path;
    let settings = endpoint.xhttp_settings();
    if settings.session_id_placement == ResidentXhttpMetaPlacement::Path
        && let Some(session_id) = meta.session_id.as_deref()
    {
        append_xhttp_path_segment(&mut path, session_id);
    }
    if settings.seq_placement == ResidentXhttpMetaPlacement::Path
        && let Some(seq) = meta.seq.as_deref()
    {
        append_xhttp_path_segment(&mut path, seq);
    }
    let query = xhttp_join_query(&normalized.query, extra_query);
    if !query.is_empty() {
        path.push('?');
        path.push_str(&query);
    }
    path
}

fn append_xhttp_path_segment(path: &mut String, value: &str) {
    if !path.ends_with('/') {
        path.push('/');
    }
    path.push_str(value);
}

fn xhttp_join_query(existing: &str, extra_query: &[(String, String)]) -> String {
    if extra_query.is_empty() {
        return existing.to_owned();
    }
    let mut encoded = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in extra_query {
        encoded.append_pair(key, value);
    }
    let encoded = encoded.finish();
    if existing.is_empty() {
        encoded
    } else if encoded.is_empty() {
        existing.to_owned()
    } else {
        format!("{existing}&{encoded}")
    }
}

pub(crate) fn xhttp_padding_referer(base_uri: &str, padding: &str) -> String {
    let base_without_query = base_uri.split_once('?').map_or(base_uri, |(base, _)| base);
    xhttp_query_in_header_padding(base_without_query, "x_padding", padding)
}

pub(crate) fn xhttp_authority(endpoint: &impl ResidentXhttpEndpointView) -> String {
    if endpoint.stream_host().is_empty() {
        endpoint.server_name().to_owned()
    } else {
        endpoint.stream_host().to_owned()
    }
}

pub(crate) fn xhttp_session_path_suffix(session_id: &str, seq: Option<u64>) -> String {
    match seq {
        Some(seq) => format!("{session_id}/{seq}"),
        None => session_id.to_owned(),
    }
}

pub(crate) fn new_xhttp_session_id_for(settings: &ResidentXhttpSettingsPlan) -> String {
    if !settings.session_id_table.is_empty()
        && let Some((from, to)) = settings.session_id_length
        && from > 0
        && to >= from
    {
        let len = ResidentXhttpSettingsPlan::sample_range((from, to)) as usize;
        let table = settings.session_id_table.as_bytes();
        if !table.is_empty() {
            return (0..len)
                .map(|_| table[fastrand::usize(..table.len())] as char)
                .collect();
        }
    }
    new_xhttp_uuid_session_id()
}

fn new_xhttp_uuid_session_id() -> String {
    let high = fastrand::u64(..);
    let low = fastrand::u64(..);
    let value = ((high as u128) << 64) | low as u128;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (value >> 96) as u32,
        ((value >> 80) & 0xffff) as u16,
        ((value >> 64) & 0xffff) as u16,
        ((value >> 48) & 0xffff) as u16,
        value & 0xffff_ffff_ffff
    )
}

pub(super) fn xhttp_h3_request(
    method: http::Method,
    endpoint: &impl ResidentXhttpEndpointView,
    path_suffix: &str,
    has_body: bool,
) -> Result<http::Request<()>, String> {
    let meta = XhttpRequestMeta::from_path_suffix(path_suffix);
    let method = xhttp_effective_method(method, endpoint.xhttp_settings(), has_body)?;
    xhttp_h3_request_with_parts(method, endpoint, meta, has_body, Vec::new(), Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_xhttp_endpoint(settings: ResidentXhttpSettingsPlan) -> ResidentXhttpEndpointPlan {
        ResidentXhttpEndpointPlan {
            server_host: "server.invalid".to_owned(),
            server_port: 443,
            server_name: "server.invalid".to_owned(),
            alpn: vec!["h2".to_owned()],
            stream_host: "stream.invalid".to_owned(),
            stream_path: "/x?ed=2048".to_owned(),
            mode: ResidentXhttpMode::PacketUp,
            settings,
            xmux: None,
            allow_insecure: false,
            tls_fragment: None,
            reality: None,
        }
    }

    #[test]
    fn xhttp_packet_up_request_applies_header_query_extended_settings() {
        let mut settings = ResidentXhttpSettingsPlan::official_default();
        settings
            .headers
            .insert("X-Test".to_owned(), "alpha".to_owned());
        settings.x_padding_bytes = Some((4, 4));
        settings.x_padding_obfs_mode = true;
        settings.x_padding_key = "pad".to_owned();
        settings.x_padding_placement = ResidentXhttpPaddingPlacement::Query;
        settings.session_id_placement = ResidentXhttpMetaPlacement::Header;
        settings.session_id_key = "X-Sid".to_owned();
        settings.seq_placement = ResidentXhttpMetaPlacement::Query;
        settings.seq_key = "seq".to_owned();
        settings.uplink_data_placement = ResidentXhttpUplinkDataPlacement::Header;
        settings.uplink_data_key = "X-Body".to_owned();
        settings.uplink_chunk_size = Some((64, 64));
        let endpoint = test_xhttp_endpoint(settings);

        let (request, body) =
            xhttp_h2_packet_up_request(&endpoint, "sid-1", 7, Bytes::from_static(b"hello"))
                .unwrap();

        assert!(body.is_none());
        assert_eq!(
            request.uri().path_and_query().unwrap().as_str(),
            "/x/?ed=2048&pad=XXXX&seq=7"
        );
        assert_eq!(request.headers()["X-Test"], "alpha");
        assert_eq!(request.headers()["X-Sid"], "sid-1");
        assert_eq!(request.headers()["X-Body-0"], "aGVsbG8");
        assert!(!request.headers().contains_key(http::header::CONTENT_TYPE));
    }

    #[test]
    fn xhttp_packet_up_request_applies_cookie_extended_settings() {
        let mut settings = ResidentXhttpSettingsPlan::official_default();
        settings.x_padding_bytes = Some((3, 3));
        settings.x_padding_obfs_mode = true;
        settings.x_padding_placement = ResidentXhttpPaddingPlacement::Cookie;
        settings.session_id_placement = ResidentXhttpMetaPlacement::Cookie;
        settings.session_id_key = "x_session".to_owned();
        settings.seq_placement = ResidentXhttpMetaPlacement::Cookie;
        settings.seq_key = "x_seq".to_owned();
        settings.uplink_data_placement = ResidentXhttpUplinkDataPlacement::Cookie;
        settings.uplink_data_key = "x_data".to_owned();
        settings.uplink_chunk_size = Some((64, 64));
        let endpoint = test_xhttp_endpoint(settings);

        let bytes =
            xhttp_h1_packet_up_request_bytes(&endpoint, "sid-2", 5, Bytes::from_static(b"hi"))
                .unwrap();
        let request = String::from_utf8(bytes).unwrap();

        assert!(request.starts_with("POST /x/?ed=2048 HTTP/1.1\r\n"));
        assert!(
            request.contains("cookie: x_data_0=aGk; x_padding=XXX; x_session=sid-2; x_seq=5\r\n")
        );
        assert!(!request.contains("Content-Type: application/grpc\r\n"));
        assert!(!request.contains("Content-Length:"));
    }
}
