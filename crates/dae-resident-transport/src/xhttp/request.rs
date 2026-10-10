use super::*;
use base64::{Engine as _, engine::general_purpose};
use tokio::io::{AsyncWrite, AsyncWriteExt};

mod browser;
mod buffer;
pub(super) use buffer::RequestBuffer;
type HeaderList = Vec<(Arc<str>, Arc<str>)>;

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
        let mut prefix = [0_u8; 2 * std::mem::size_of::<usize>() + 2];
        let mut start = prefix.len() - 2;
        prefix[start..].copy_from_slice(b"\r\n");
        let mut length = payload.len();
        while length != 0 {
            start -= 1;
            prefix[start] = b"0123456789abcdef"[length & 15];
            length >>= 4;
        }
        let suffix: &[u8] = if end_stream {
            b"\r\n0\r\n\r\n"
        } else {
            b"\r\n"
        };
        let mut parts = [
            std::io::IoSlice::new(&prefix[start..]),
            std::io::IoSlice::new(payload),
            std::io::IoSlice::new(suffix),
        ];
        time::timeout(
            RESIDENT_CONNECT_TIMEOUT,
            write_chunk_parts(writer, &mut parts),
        )
        .await
        .map_err(|_| format!("xHTTP HTTP/1.1 {context} chunk timeout"))?
        .map_err(|err| format!("write xHTTP HTTP/1.1 {context} chunk: {err}"))?;
    } else if end_stream {
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

async fn write_chunk_parts(
    writer: &mut (impl AsyncWrite + Unpin),
    parts: &mut [std::io::IoSlice<'_>],
) -> std::io::Result<()> {
    let mut pending = parts;
    while !pending.is_empty() {
        match writer.write_vectored(pending).await {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(written) => std::io::IoSlice::advance_slices(&mut pending, written),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
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
    thread_local! { static ENCODED: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) }; }
    ENCODED.with(|buffer| {
        let mut encoded = buffer.borrow_mut();
        encoded.clear();
        general_purpose::URL_SAFE_NO_PAD.encode_string(payload, &mut encoded);
        let mut remaining = encoded.as_str();
        let mut chunks = Vec::new();
        while !remaining.is_empty() {
            let size =
                ResidentXhttpSettingsPlan::sample_range(settings.normalized_uplink_chunk_size())
                    .max(1) as usize;
            let (chunk, rest) = remaining.split_at(size.min(remaining.len()));
            chunks.push((
                format!("{key}{separator}{}", chunks.len()),
                chunk.to_owned(),
            ));
            remaining = rest;
        }
        if encoded.capacity() > 128 * 1024 {
            *encoded = String::new();
        }
        chunks
    })
}

struct XhttpPreparedRequestParts {
    uri: String,
    path_and_query: String,
    headers: HeaderList,
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
        builder = builder.header(name.as_ref(), value.as_ref());
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
        builder = builder.header(name.as_ref(), value.as_ref());
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
    use std::fmt::Write as _;
    let mut request = buffer::take_head();
    let _ = write!(
        request,
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
        let _ = write!(request, "Content-Length: {content_length}\r\n");
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

fn xhttp_set_header(headers: &mut HeaderList, name: String, value: String) {
    headers.retain(|(candidate, _)| !candidate.eq_ignore_ascii_case(&name));
    headers.push((name.into(), value.into()));
}

fn xhttp_apply_cookie_header(headers: &mut HeaderList, cookies: Vec<(String, String)>) {
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
            let mut merged = existing.to_string();
            merged.push_str("; ");
            merged.push_str(&cookie_value);
            *existing = merged.into();
        } else {
            *existing = cookie_value.into();
        }
    } else {
        headers.push((http::header::COOKIE.as_str().into(), cookie_value.into()));
    }
}

fn xhttp_apply_meta(
    settings: &ResidentXhttpSettingsPlan,
    meta: &XhttpRequestMeta,
    headers: &mut HeaderList,
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
    headers: &mut HeaderList,
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

// Nonsecret length padding only: entropy failure may fall back to fastrand.
// Session IDs must use secure_random_ascii and propagate entropy errors.
fn random_ascii(table: &[u8], len: usize) -> String {
    debug_assert!(!table.is_empty() && table.len() <= 128 && table.is_ascii());
    let limit = 256 - 256 % table.len();
    let mut output = String::with_capacity(len);
    let mut random = [0_u8; 256];
    while output.len() < len {
        if getrandom::fill(&mut random).is_err() {
            // Padding carries no key, nonce or session identity.
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

fn secure_random_ascii(table: &[u8], len: usize) -> Result<String, String> {
    debug_assert!(!table.is_empty() && table.len() <= 128 && table.is_ascii());
    let limit = 256 - 256 % table.len();
    let mut output = String::with_capacity(len);
    let mut random = [0_u8; 256];
    while output.len() < len {
        dae_resident_core::fill_wire_random_pooled(&mut random)
            .map_err(|error| format!("generate XHTTP session ID: {error}"))?;
        for byte in random {
            if usize::from(byte) < limit {
                output.push(table[usize::from(byte) % table.len()] as char);
                if output.len() == len {
                    break;
                }
            }
        }
    }
    Ok(output)
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

pub fn new_xhttp_session_id_for(settings: &ResidentXhttpSettingsPlan) -> Result<String, String> {
    if !settings.session_id_table.is_empty()
        && let Some((from, to)) = settings.session_id_length
        && from > 0
        && to >= from
    {
        let len = ResidentXhttpSettingsPlan::sample_range((from, to)) as usize;
        let table = settings.session_id_table.as_bytes();
        if !table.is_empty() {
            return secure_random_ascii(table, len);
        }
    }
    new_xhttp_uuid_session_id()
}

fn new_xhttp_uuid_session_id() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    dae_resident_core::fill_wire_random_pooled(&mut bytes)
        .map_err(|error| format!("generate XHTTP session ID: {error}"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let value = u128::from_be_bytes(bytes);
    Ok(format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (value >> 96) as u32,
        ((value >> 80) & 0xffff) as u16,
        ((value >> 64) & 0xffff) as u16,
        ((value >> 48) & 0xffff) as u16,
        value & 0xffff_ffff_ffff
    ))
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
#[path = "request/tests.rs"]
mod tests;
