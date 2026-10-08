use super::*;
use base64::{Engine as _, engine::general_purpose};
use tokio::io::{AsyncWrite, AsyncWriteExt};

mod browser;

pub fn xhttp_h2_request(
    method: http::Method,
    endpoint: &impl ResidentXhttpEndpointView,
    path_suffix: &str,
    has_body: bool,
) -> Result<http::Request<()>, String> {
    let meta = XhttpRequestMeta::from_path_suffix(path_suffix);
    let method = xhttp_effective_method(method, endpoint.xhttp_settings(), has_body)?;
    xhttp_h2_request_with_parts(method, endpoint, meta, has_body, Vec::new(), Vec::new())
}

pub fn xhttp_h1_request_bytes(
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

pub fn xhttp_h1_packet_up_request_bytes(
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

pub fn xhttp_h2_packet_up_request(
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
        false,
        plan.headers,
        plan.cookies,
    )?;
    Ok((request, plan.body))
}

pub fn xhttp_h3_packet_up_request(
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
        false,
        plan.headers,
        plan.cookies,
    )?;
    Ok((request, plan.body))
}

pub async fn write_xhttp_h1_chunked_request_head<W>(
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

pub async fn write_xhttp_h1_chunk<W>(
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
    let mut remaining = encoded.as_str();
    let mut chunks = Vec::new();
    while !remaining.is_empty() {
        let size = ResidentXhttpSettingsPlan::sample_range(settings.normalized_uplink_chunk_size())
            .max(1) as usize;
        let (chunk, rest) = remaining.split_at(size.min(remaining.len()));
        chunks.push((
            format!("{key}{separator}{}", chunks.len()),
            chunk.to_owned(),
        ));
        remaining = rest;
    }
    chunks
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
        ResidentXhttpHttpVersion::H2,
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
        ResidentXhttpHttpVersion::H3,
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
    let packet_up = meta.seq.is_some();
    let prepared = xhttp_prepare_request_parts(
        endpoint,
        ResidentXhttpHttpVersion::H1,
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
    let has_connection = prepared
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("connection"));
    for (name, value) in prepared.headers {
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        request.push_str(&name);
        request.push_str(": ");
        request.push_str(&value);
        request.push_str("\r\n");
    }
    if !has_connection {
        request.push_str(if packet_up {
            "Connection: keep-alive\r\n"
        } else {
            "Connection: close\r\n"
        });
    }
    if let Some(content_length) = content_length {
        request.push_str(&format!("Content-Length: {content_length}\r\n"));
    }
    request
}

fn xhttp_prepare_request_parts(
    endpoint: &impl ResidentXhttpEndpointView,
    http_version: ResidentXhttpHttpVersion,
    meta: XhttpRequestMeta,
    grpc_body_header: bool,
    extra_headers: Vec<(String, String)>,
    extra_cookies: Vec<(String, String)>,
) -> XhttpPreparedRequestParts {
    let settings = endpoint.xhttp_settings();
    let mut headers = browser::request_headers(settings, http_version);
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
            let mut token = random_ascii(BASE62, token_len);
            // Xray sizes tokenish padding against the HTTP/2 HPACK or HTTP/3
            // QPACK Huffman representation, not the raw character count.
            // Correct the estimate so the encoded value stays within two
            // bytes of the requested target.
            for adjustment in 0..150 {
                let encoded_len = hpack_huffman_len(token.as_bytes());
                if encoded_len.abs_diff(len) <= 2 {
                    break;
                }
                if encoded_len < len {
                    token.push(if adjustment % 2 == 0 { 'X' } else { 'Z' });
                } else if token.len() > 1 {
                    token.pop();
                } else {
                    break;
                }
            }
            token
        }
    }
}

fn hpack_huffman_len(input: &[u8]) -> usize {
    // RFC 7541 Appendix B code lengths for the base62 alphabet, in the same
    // order as BASE62 above. The wire length is the byte-rounded bit count.
    const LENGTHS: [u8; 62] = [
        5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 8, 7, 8, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7,
        7, 7,
    ];
    let bits: usize = input
        .iter()
        .map(|byte| match byte {
            b'0'..=b'9' => LENGTHS[(byte - b'0') as usize],
            b'A'..=b'Z' => LENGTHS[10 + (byte - b'A') as usize],
            b'a'..=b'z' => LENGTHS[36 + (byte - b'a') as usize],
            _ => 8,
        } as usize)
        .sum();
    bits.div_ceil(8)
}

fn random_ascii(table: &[u8], len: usize) -> String {
    debug_assert!(!table.is_empty() && table.len() <= 128 && table.is_ascii());
    let limit = 256 - 256 % table.len();
    let mut output = String::with_capacity(len);
    let mut random = [0_u8; 256];
    while output.len() < len {
        if getrandom::fill(&mut random).is_err() {
            // Preserve the existing availability fallback on entropy failure.
            fastrand::fill(&mut random);
        }
        for byte in random {
            if usize::from(byte) < limit {
                output.push(table[usize::from(byte) % table.len()] as char);
                if output.len() == len {
                    break;
                }
            }
        }
    }
    output
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

pub fn xhttp_uri(endpoint: &impl ResidentXhttpEndpointView, path_suffix: &str) -> String {
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
    let normalized = ir::normalize_xhttp_path_and_query_for_placement(
        endpoint.stream_path(),
        endpoint.xhttp_settings().uses_path_metadata(),
    );
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
    for (index, (key, value)) in extra_query.iter().enumerate() {
        // Padding is applied before session/sequence metadata, as in the
        // server's URL query setters: the last generated value wins.
        if extra_query[index + 1..]
            .iter()
            .any(|(later, _)| later == key)
        {
            continue;
        }
        encoded.append_pair(key, value);
    }
    let encoded = encoded.finish();
    let mut query = String::with_capacity(existing.len() + encoded.len() + 1);
    for pair in existing.split('&').filter(|pair| !pair.is_empty()) {
        let replaced = url::form_urlencoded::parse(pair.as_bytes())
            .next()
            .is_some_and(|(key, _)| extra_query.iter().any(|(new, _)| new == key.as_ref()));
        if !replaced {
            if !query.is_empty() {
                query.push('&');
            }
            // Preserve the encoding of unrelated configured parameters.
            query.push_str(pair);
        }
    }
    if !query.is_empty() && !encoded.is_empty() {
        query.push('&');
    }
    query.push_str(&encoded);
    query
}

pub fn xhttp_padding_referer(base_uri: &str, padding: &str) -> String {
    let base_without_query = base_uri.split_once('?').map_or(base_uri, |(base, _)| base);
    xhttp_query_in_header_padding(base_without_query, "x_padding", padding)
}

pub fn xhttp_authority(endpoint: &impl ResidentXhttpEndpointView) -> String {
    if endpoint.stream_host().is_empty() {
        endpoint.server_name().to_owned()
    } else {
        endpoint.stream_host().to_owned()
    }
}

pub fn xhttp_session_path_suffix(session_id: &str, seq: Option<u64>) -> String {
    match seq {
        Some(seq) => format!("{session_id}/{seq}"),
        None => session_id.to_owned(),
    }
}

pub fn new_xhttp_session_id_for(settings: &ResidentXhttpSettingsPlan) -> String {
    if !settings.session_id_table.is_empty()
        && let Some((from, to)) = settings.session_id_length
        && from > 0
        && to >= from
    {
        let len = ResidentXhttpSettingsPlan::sample_range((from, to)) as usize;
        let table = settings.session_id_table.as_bytes();
        if !table.is_empty() {
            return random_ascii(table, len);
        }
    }
    new_xhttp_uuid_session_id()
}

fn new_xhttp_uuid_session_id() -> String {
    // Session ids are exposed in the request path and must not be
    // predictable from the process PRNG state (anti-tracking). Read 16
    // bytes from the OS CSPRNG; a failed entropy source falls back to the
    // process PRNG for availability, mirroring `random_ascii`.
    let mut bytes = [0_u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        for chunk in bytes.chunks_exact_mut(8) {
            let value = fastrand::u64(..).to_ne_bytes();
            chunk.copy_from_slice(&value);
        }
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let value = u128::from_be_bytes(bytes);
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (value >> 96) as u32,
        ((value >> 80) & 0xffff) as u16,
        ((value >> 64) & 0xffff) as u16,
        ((value >> 48) & 0xffff) as u16,
        value & 0xffff_ffff_ffff
    )
}

pub fn xhttp_h3_request(
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
    use std::collections::BTreeMap;

    #[test]
    fn xhttp_browser_aliases_reach_each_request_encoder() {
        for alias in [
            None,
            Some("chrome"),
            Some("edge"),
            Some("firefox"),
            Some("safari"),
            Some("curl"),
            Some("golang"),
            Some("Custom-UA/1"),
            Some("Chrome"),
            Some(""),
        ] {
            let mut settings = ResidentXhttpSettingsPlan::official_default();
            if let Some(ua) = alias {
                settings.headers.insert("uSeR-aGeNt".into(), ua.into());
                settings
                    .headers
                    .insert("user-agent".into(), "shadowed-ua".into());
            }
            settings
                .headers
                .insert("Accept".into(), "application/test".into());
            settings.headers.insert("priority".into(), "u=7".into());
            settings
                .headers
                .insert("Accept-Language".into(), "custom-language".into());
            let endpoint = test_xhttp_endpoint(settings);
            let payload = Bytes::from_static(b"payload");
            let raw = xhttp_h1_packet_up_request_bytes(&endpoint, "s", 0, payload.clone()).unwrap();
            let end = raw.windows(4).position(|v| v == b"\r\n\r\n").unwrap();
            assert_eq!(&raw[end + 4..], b"payload");
            assert_eq!(
                std::str::from_utf8(&raw[..end])
                    .unwrap()
                    .lines()
                    .filter(|line| line.to_ascii_lowercase().starts_with("user-agent:"))
                    .count(),
                usize::from(alias != Some(""))
            );
            let h1 = std::str::from_utf8(&raw[..end])
                .unwrap()
                .lines()
                .skip(1)
                .map(|line| {
                    let (key, value) = line.split_once(':').unwrap();
                    (key.to_ascii_lowercase(), value.trim().to_owned())
                })
                .collect::<BTreeMap<_, _>>();
            let (h2, body2) =
                xhttp_h2_packet_up_request(&endpoint, "s", 0, payload.clone()).unwrap();
            let (h3, body3) =
                xhttp_h3_packet_up_request(&endpoint, "s", 0, payload.clone()).unwrap();
            assert_eq!(body2, Some(payload.clone()));
            assert_eq!(body3, Some(payload));
            for headers in [h2.headers(), h3.headers()] {
                assert_eq!(
                    headers.get_all("user-agent").iter().count(),
                    usize::from(alias != Some(""))
                );
            }
            let maps = [
                h1,
                h2.headers()
                    .iter()
                    .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap().to_owned()))
                    .collect(),
                h3.headers()
                    .iter()
                    .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap().to_owned()))
                    .collect(),
            ];
            for (version, headers) in maps.iter().enumerate() {
                let ua = headers
                    .get("user-agent")
                    .map(String::as_str)
                    .unwrap_or_default();
                let browser = alias.unwrap_or("chrome");
                assert_eq!(headers.contains_key("user-agent"), alias != Some(""));
                match browser {
                    "chrome" | "edge" => {
                        assert!(ua.contains("Chrome/"));
                        assert_eq!(ua.contains("Edg/"), browser == "edge");
                        let major = ua
                            .split("Chrome/")
                            .nth(1)
                            .unwrap()
                            .split('.')
                            .next()
                            .unwrap();
                        assert!(headers["sec-ch-ua"].contains(&format!("v=\"{major}\"")));
                        assert_eq!(headers["sec-ch-ua-platform"], "\"Windows\"");
                    }
                    "firefox" => {
                        assert!(ua.contains("Firefox/"));
                        assert_eq!(headers["accept-language"], "en-US,en;q=0.5");
                    }
                    "safari" => assert!(
                        ua.contains("Version/")
                            && ua.contains("Safari/")
                            && !ua.contains("Chrome/")
                    ),
                    "curl" => assert!(ua.starts_with("curl/8.")),
                    "golang" => assert_eq!(
                        ua,
                        ["Go-http-client/1.1", "Go-http-client/2.0", "quic-go HTTP/3"][version]
                    ),
                    custom => assert_eq!(ua, custom),
                }
                let masqueraded = matches!(browser, "chrome" | "edge" | "firefox" | "safari");
                assert_eq!(
                    headers.get("sec-fetch-mode").map(String::as_str),
                    masqueraded.then_some("cors")
                );
                assert_eq!(headers["accept"], "application/test");
                assert_eq!(headers["priority"], "u=7");
                assert!(!headers.contains_key("content-type"));
                assert!(headers.contains_key("referer"));
                if browser != "golang" {
                    assert_eq!(headers.get("user-agent"), maps[0].get("user-agent"));
                }
            }
        }
    }

    #[test]
    fn xhttp_h1_packet_reuse_respects_explicit_connection_policy() {
        let mut endpoint = test_xhttp_endpoint(ResidentXhttpSettingsPlan::official_default());
        let request = String::from_utf8(
            xhttp_h1_packet_up_request_bytes(&endpoint, "s", 0, Bytes::new()).unwrap(),
        )
        .unwrap();
        assert!(request.contains("Connection: keep-alive\r\n"));
        assert!(!request.contains("Connection: close"));
        endpoint
            .settings
            .headers
            .insert("connection".into(), "close".into());
        let request = String::from_utf8(
            xhttp_h1_packet_up_request_bytes(&endpoint, "s", 0, Bytes::new()).unwrap(),
        )
        .unwrap();
        assert!(request.contains("connection: close\r\n"));
        assert!(!request.contains("Connection: keep-alive"));
    }

    #[test]
    fn xhttp_default_session_is_uuid_v4() {
        for _ in 0..32 {
            let id = new_xhttp_uuid_session_id();
            assert_eq!(id.len(), 36);
            assert_eq!(&id[14..15], "4");
            assert!(matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
        }
    }

    #[test]
    fn xhttp_payload_chunks_sample_each_boundary_and_reassemble() {
        let mut settings = ResidentXhttpSettingsPlan::official_default();
        settings.uplink_chunk_size = Some((64, 128));
        let payload = Bytes::from(vec![42; 8192]);
        let chunks = xhttp_encoded_payload_chunks("X-Data", '-', &settings, &payload);
        assert!(
            chunks
                .iter()
                .take(chunks.len() - 1)
                .all(|(_, v)| (64..=128).contains(&v.len()))
        );
        assert!(chunks.windows(2).any(|c| c[0].1.len() != c[1].1.len()));
        let encoded = chunks.iter().map(|(_, v)| v.as_str()).collect::<String>();
        assert_eq!(
            general_purpose::URL_SAFE_NO_PAD.decode(encoded).unwrap(),
            payload
        );
        assert!(
            random_ascii(b"abc", 4096)
                .bytes()
                .all(|b| b"abc".contains(&b))
        );
    }

    #[test]
    fn packet_up_content_type_is_consistent_across_http_versions() {
        for configured in [None, Some("application/octet-stream")] {
            let mut settings = ResidentXhttpSettingsPlan::official_default();
            if let Some(value) = configured {
                settings
                    .headers
                    .insert("Content-Type".to_owned(), value.to_owned());
            }
            let endpoint = test_xhttp_endpoint(settings);
            let payload = Bytes::from_static(b"packet");
            let h1 = String::from_utf8(
                xhttp_h1_packet_up_request_bytes(&endpoint, "session", 0, payload.clone()).unwrap(),
            )
            .unwrap();
            let (h2, h2_body) =
                xhttp_h2_packet_up_request(&endpoint, "session", 0, payload.clone()).unwrap();
            let (h3, h3_body) =
                xhttp_h3_packet_up_request(&endpoint, "session", 0, payload.clone()).unwrap();
            assert_eq!(
                h1.to_ascii_lowercase().contains("content-type:"),
                configured.is_some()
            );
            for request in [h2, h3] {
                assert_eq!(
                    request
                        .headers()
                        .get(http::header::CONTENT_TYPE)
                        .map(|value| value.to_str().unwrap()),
                    configured
                );
            }
            assert_eq!(h2_body, Some(payload.clone()));
            assert_eq!(h3_body, Some(payload));
        }
    }

    #[test]
    fn stream_upload_grpc_header_remains_optional() {
        for no_grpc_header in [false, true] {
            let mut settings = ResidentXhttpSettingsPlan::official_default();
            settings.no_grpc_header = no_grpc_header;
            let endpoint = test_xhttp_endpoint(settings);
            let request = xhttp_h2_request(http::Method::POST, &endpoint, "", true).unwrap();
            assert_eq!(
                request
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .map(|value| value.to_str().unwrap()),
                (!no_grpc_header).then_some("application/grpc")
            );
        }
    }

    #[test]
    fn generated_metadata_replaces_existing_query_values() {
        let mut settings = ResidentXhttpSettingsPlan::official_default();
        settings.session_id_placement = ResidentXhttpMetaPlacement::Query;
        settings.seq_placement = ResidentXhttpMetaPlacement::Query;
        settings.x_padding_obfs_mode = true;
        settings.x_padding_placement = ResidentXhttpPaddingPlacement::Query;
        settings.x_padding_bytes = Some((4, 4));
        let mut endpoint = test_xhttp_endpoint(settings);
        endpoint.stream_path =
            "/xhttp?token=a%20b&x_session=old&x%5Fsession=older&x_seq=99&x_padding=old".to_owned();
        let (request, _) =
            xhttp_h2_packet_up_request(&endpoint, "current", 7, Bytes::new()).unwrap();
        let query = request.uri().query().unwrap();
        assert!(query.starts_with("token=a%20b&"));
        let pairs = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
        for (key, expected) in [
            ("x_session", "current"),
            ("x_seq", "7"),
            ("x_padding", "XXXX"),
        ] {
            let values = pairs
                .iter()
                .filter(|(name, _)| name == key)
                .map(|(_, value)| value.as_ref())
                .collect::<Vec<_>>();
            assert_eq!(values, [expected]);
        }
        assert_eq!(
            xhttp_join_query(
                "same=old",
                &[
                    ("same".to_owned(), "padding".to_owned()),
                    ("same".to_owned(), "session".to_owned())
                ]
            ),
            "same=session"
        );
    }

    #[test]
    fn tokenish_padding_tracks_hpack_target_within_two_bytes() {
        for target in [1, 2, 7, 32, 127, 900] {
            let padding = xhttp_generate_padding(ResidentXhttpPaddingMethod::Tokenish, target);
            assert!(!padding.is_empty());
            assert!(hpack_huffman_len(padding.as_bytes()).abs_diff(target) <= 2);
        }
    }

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
            utls_fingerprint: None,
            ech: None,
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
            "/x?ed=2048&pad=XXXX&seq=7"
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

        assert!(request.starts_with("POST /x?ed=2048 HTTP/1.1\r\n"));
        assert!(
            request.contains("cookie: x_data_0=aGk; x_padding=XXX; x_session=sid-2; x_seq=5\r\n")
        );
        assert!(!request.contains("Content-Type: application/grpc\r\n"));
        assert!(!request.contains("Content-Length:"));
    }
}
