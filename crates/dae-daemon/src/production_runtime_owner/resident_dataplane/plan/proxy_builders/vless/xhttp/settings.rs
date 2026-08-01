use super::parsing::{
    optional_bool, optional_i32, optional_i64, optional_string, optional_xhttp_range,
    reject_unknown_object_fields,
};
use super::*;

pub(super) struct ResidentXhttpParsedSettings {
    pub(super) settings: ResidentXhttpSettingsPlan,
    pub(super) xmux: Option<ResidentXhttpXmuxPlan>,
}

pub(super) fn resident_xhttp_settings_and_xmux_plan(
    object: &serde_json::Map<String, Value>,
    field: &str,
    node_tag: &str,
) -> Result<ResidentXhttpParsedSettings, String> {
    let headers = resident_xhttp_headers_plan(object.get("headers"), field, node_tag)?;
    let x_padding_bytes = optional_xhttp_range(
        object.get("xPaddingBytes"),
        &format!("{field}.xPaddingBytes"),
        node_tag,
    )?;
    if let Some((from, to)) = x_padding_bytes
        && (from, to) != (0, 0)
        && (from <= 0 || to <= 0)
    {
        return Err(format!(
            "resident dataplane vless xHTTP {field}.xPaddingBytes cannot be disabled for node {node_tag}"
        ));
    }
    let x_padding_placement = resident_xhttp_padding_placement(
        optional_string(
            object.get("xPaddingPlacement"),
            &format!("{field}.xPaddingPlacement"),
            node_tag,
        )?
        .as_deref(),
        field,
        node_tag,
    )?;
    let x_padding_method = resident_xhttp_padding_method(
        optional_string(
            object.get("xPaddingMethod"),
            &format!("{field}.xPaddingMethod"),
            node_tag,
        )?
        .as_deref(),
        field,
        node_tag,
    )?;
    let uplink_http_method = optional_string(
        object.get("uplinkHTTPMethod"),
        &format!("{field}.uplinkHTTPMethod"),
        node_tag,
    )?
    .filter(|value| !value.is_empty())
    .map(|value| value.to_ascii_uppercase())
    .unwrap_or_else(|| "POST".to_owned());
    let session_id_placement = resident_xhttp_meta_placement(
        optional_string(
            object.get("sessionIDPlacement"),
            &format!("{field}.sessionIDPlacement"),
            node_tag,
        )?
        .as_deref(),
        ResidentXhttpMetaPlacement::Path,
        "session",
        field,
        node_tag,
    )?;
    let seq_placement = resident_xhttp_meta_placement(
        optional_string(
            object.get("seqPlacement"),
            &format!("{field}.seqPlacement"),
            node_tag,
        )?
        .as_deref(),
        ResidentXhttpMetaPlacement::Path,
        "seq",
        field,
        node_tag,
    )?;
    let uplink_data_placement = resident_xhttp_uplink_data_placement(
        optional_string(
            object.get("uplinkDataPlacement"),
            &format!("{field}.uplinkDataPlacement"),
            node_tag,
        )?
        .as_deref(),
        field,
        node_tag,
    )?;
    let mut settings = ResidentXhttpSettingsPlan {
        headers,
        x_padding_bytes,
        x_padding_obfs_mode: optional_bool(
            object.get("xPaddingObfsMode"),
            &format!("{field}.xPaddingObfsMode"),
            node_tag,
        )?
        .unwrap_or(false),
        x_padding_key: optional_string(
            object.get("xPaddingKey"),
            &format!("{field}.xPaddingKey"),
            node_tag,
        )?
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "x_padding".to_owned()),
        x_padding_header: optional_string(
            object.get("xPaddingHeader"),
            &format!("{field}.xPaddingHeader"),
            node_tag,
        )?
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "X-Padding".to_owned()),
        x_padding_placement,
        x_padding_method,
        uplink_http_method,
        session_id_placement,
        session_id_key: optional_string(
            object.get("sessionIDKey"),
            &format!("{field}.sessionIDKey"),
            node_tag,
        )?
        .unwrap_or_default(),
        session_id_table: optional_string(
            object.get("sessionIDTable"),
            &format!("{field}.sessionIDTable"),
            node_tag,
        )?
        .map(|value| resident_xhttp_predefined_session_table(&value).unwrap_or(value))
        .unwrap_or_default(),
        session_id_length: optional_xhttp_range(
            object.get("sessionIDLength"),
            &format!("{field}.sessionIDLength"),
            node_tag,
        )?,
        seq_placement,
        seq_key: optional_string(object.get("seqKey"), &format!("{field}.seqKey"), node_tag)?
            .unwrap_or_default(),
        uplink_data_placement,
        uplink_data_key: optional_string(
            object.get("uplinkDataKey"),
            &format!("{field}.uplinkDataKey"),
            node_tag,
        )?
        .unwrap_or_default(),
        uplink_chunk_size: optional_xhttp_range(
            object.get("uplinkChunkSize"),
            &format!("{field}.uplinkChunkSize"),
            node_tag,
        )?,
        no_grpc_header: optional_bool(
            object.get("noGRPCHeader"),
            &format!("{field}.noGRPCHeader"),
            node_tag,
        )?
        .unwrap_or(false),
        no_sse_header: optional_bool(
            object.get("noSSEHeader"),
            &format!("{field}.noSSEHeader"),
            node_tag,
        )?
        .unwrap_or(false),
        sc_max_each_post_bytes: optional_xhttp_range(
            object.get("scMaxEachPostBytes"),
            &format!("{field}.scMaxEachPostBytes"),
            node_tag,
        )?,
        sc_min_posts_interval_ms: optional_xhttp_range(
            object.get("scMinPostsIntervalMs"),
            &format!("{field}.scMinPostsIntervalMs"),
            node_tag,
        )?,
        sc_max_buffered_posts: optional_i64(
            object.get("scMaxBufferedPosts"),
            &format!("{field}.scMaxBufferedPosts"),
            node_tag,
        )?
        .unwrap_or(0),
        sc_stream_up_server_secs: optional_xhttp_range(
            object.get("scStreamUpServerSecs"),
            &format!("{field}.scStreamUpServerSecs"),
            node_tag,
        )?,
        server_max_header_bytes: optional_i32(
            object.get("serverMaxHeaderBytes"),
            &format!("{field}.serverMaxHeaderBytes"),
            node_tag,
        )?
        .unwrap_or(0),
    };
    normalize_resident_xhttp_setting_keys(&mut settings);
    validate_resident_xhttp_settings_static(&settings, field, node_tag)?;
    let xmux = resident_xhttp_xmux_plan(object.get("xmux"), &format!("{field}.xmux"), node_tag)?;
    Ok(ResidentXhttpParsedSettings { settings, xmux })
}

fn normalize_resident_xhttp_setting_keys(settings: &mut ResidentXhttpSettingsPlan) {
    if settings.session_id_placement != ResidentXhttpMetaPlacement::Path
        && settings.session_id_key.is_empty()
    {
        settings.session_id_key = match settings.session_id_placement {
            ResidentXhttpMetaPlacement::Header => "X-Session",
            ResidentXhttpMetaPlacement::Cookie | ResidentXhttpMetaPlacement::Query => "x_session",
            ResidentXhttpMetaPlacement::Path => "",
        }
        .to_owned();
    }
    if settings.seq_placement != ResidentXhttpMetaPlacement::Path && settings.seq_key.is_empty() {
        settings.seq_key = match settings.seq_placement {
            ResidentXhttpMetaPlacement::Header => "X-Seq",
            ResidentXhttpMetaPlacement::Cookie | ResidentXhttpMetaPlacement::Query => "x_seq",
            ResidentXhttpMetaPlacement::Path => "",
        }
        .to_owned();
    }
    if settings.uplink_data_placement != ResidentXhttpUplinkDataPlacement::Body
        && settings.uplink_data_key.is_empty()
    {
        settings.uplink_data_key = match settings.uplink_data_placement {
            ResidentXhttpUplinkDataPlacement::Cookie => "x_data",
            ResidentXhttpUplinkDataPlacement::Auto | ResidentXhttpUplinkDataPlacement::Header => {
                "X-Data"
            }
            ResidentXhttpUplinkDataPlacement::Body => "",
        }
        .to_owned();
    }
}

fn validate_resident_xhttp_settings_static(
    settings: &ResidentXhttpSettingsPlan,
    field: &str,
    node_tag: &str,
) -> Result<(), String> {
    if let Some((from, to)) = settings.sc_max_each_post_bytes
        && (from <= 0 || to <= 0)
    {
        return Err(format!(
            "resident dataplane vless xHTTP {field}.scMaxEachPostBytes must be greater than 0 for node {node_tag}"
        ));
    }
    if settings.sc_max_buffered_posts < 0 {
        return Err(format!(
            "resident dataplane vless xHTTP {field}.scMaxBufferedPosts rejects negative values for node {node_tag}"
        ));
    }
    if settings.server_max_header_bytes < 0 {
        return Err(format!(
            "resident dataplane vless xHTTP {field}.serverMaxHeaderBytes rejects negative values for node {node_tag}"
        ));
    }
    if settings.uplink_http_method != "GET" && settings.uplink_http_method != "POST" {
        return Err(format!(
            "resident dataplane vless xHTTP {field}.uplinkHTTPMethod admits GET or POST for node {node_tag}; got {}",
            settings.uplink_http_method
        ));
    }
    if !settings.session_id_table.is_empty() {
        validate_resident_xhttp_session_table(settings, field, node_tag)?;
    }
    Ok(())
}

pub(super) fn validate_resident_xhttp_settings_for_mode(
    settings: &ResidentXhttpSettingsPlan,
    mode: ResidentXhttpMode,
    field: &str,
    node_tag: &str,
) -> Result<(), String> {
    if settings.uplink_http_method == "GET" && mode != ResidentXhttpMode::PacketUp {
        return Err(format!(
            "resident dataplane vless xHTTP {field}.uplinkHTTPMethod can be GET only in packet-up mode for node {node_tag}"
        ));
    }
    if matches!(
        settings.uplink_data_placement,
        ResidentXhttpUplinkDataPlacement::Cookie | ResidentXhttpUplinkDataPlacement::Header
    ) && mode != ResidentXhttpMode::PacketUp
    {
        return Err(format!(
            "resident dataplane vless xHTTP {field}.uplinkDataPlacement={} is allowed only in packet-up mode for node {node_tag}",
            settings.uplink_data_placement.as_str()
        ));
    }
    Ok(())
}

fn validate_resident_xhttp_session_table(
    settings: &ResidentXhttpSettingsPlan,
    field: &str,
    node_tag: &str,
) -> Result<(), String> {
    if !settings.session_id_table.is_ascii() {
        return Err(format!(
            "resident dataplane vless xHTTP {field}.sessionIDTable must contain only ASCII characters for node {node_tag}"
        ));
    }
    let (from, to) = settings.session_id_length.unwrap_or((0, 0));
    if from <= 0 {
        return Err(format!(
            "resident dataplane vless xHTTP {field}.sessionIDLength.from must be greater than 0 for node {node_tag}"
        ));
    }
    let table_len = settings.session_id_table.len() as f64;
    let room = if table_len <= 0.0 {
        0.0
    } else {
        (from..=to.max(from))
            .map(|len| table_len.powi(len))
            .sum::<f64>()
    };
    if room < ((2_u64 << 30) as f64) {
        return Err(format!(
            "resident dataplane vless xHTTP {field}.sessionIDTable or sessionIDLength is too small for node {node_tag}"
        ));
    }
    Ok(())
}

fn resident_xhttp_predefined_session_table(name: &str) -> Option<String> {
    let table = match name {
        "ALPHABET" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Alphabet" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "BASE36" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Base62" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "HEX" => "0123456789ABCDEF",
        "alphabet" => "abcdefghijklmnopqrstuvwxyz",
        "base36" => "0123456789abcdefghijklmnopqrstuvwxyz",
        "hex" => "0123456789abcdef",
        "number" => "0123456789",
        _ => return None,
    };
    Some(table.to_owned())
}

fn resident_xhttp_headers_plan(
    value: Option<&Value>,
    field: &str,
    node_tag: &str,
) -> Result<BTreeMap<String, String>, String> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let Value::Object(object) = value else {
        if value.is_null() {
            return Ok(BTreeMap::new());
        }
        return Err(format!(
            "resident dataplane vless xHTTP {field}.headers must be a JSON object for node {node_tag}"
        ));
    };
    let mut headers = BTreeMap::new();
    for (name, value) in object {
        if name.eq_ignore_ascii_case("host") {
            return Err(format!(
                "resident dataplane vless xHTTP {field}.headers cannot contain host for node {node_tag}"
            ));
        }
        if name.trim().is_empty()
            || name
                .bytes()
                .any(|byte| matches!(byte, b'\r' | b'\n' | b':'))
        {
            return Err(format!(
                "resident dataplane vless xHTTP {field}.headers contains an invalid header name for node {node_tag}"
            ));
        }
        let Some(value) = value.as_str() else {
            return Err(format!(
                "resident dataplane vless xHTTP {field}.headers.{name} must be a string for node {node_tag}"
            ));
        };
        if value.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
            return Err(format!(
                "resident dataplane vless xHTTP {field}.headers.{name} contains invalid line breaks for node {node_tag}"
            ));
        }
        headers.insert(name.trim().to_owned(), value.trim().to_owned());
    }
    Ok(headers)
}

fn resident_xhttp_padding_placement(
    value: Option<&str>,
    field: &str,
    node_tag: &str,
) -> Result<ResidentXhttpPaddingPlacement, String> {
    match value.unwrap_or_default() {
        "" | "queryInHeader" => Ok(ResidentXhttpPaddingPlacement::QueryInHeader),
        "cookie" => Ok(ResidentXhttpPaddingPlacement::Cookie),
        "header" => Ok(ResidentXhttpPaddingPlacement::Header),
        "query" => Ok(ResidentXhttpPaddingPlacement::Query),
        other => Err(format!(
            "resident dataplane vless xHTTP {field}.xPaddingPlacement is unsupported for node {node_tag}: {other}"
        )),
    }
}

fn resident_xhttp_padding_method(
    value: Option<&str>,
    field: &str,
    node_tag: &str,
) -> Result<ResidentXhttpPaddingMethod, String> {
    match value.unwrap_or_default() {
        "" | "repeat-x" => Ok(ResidentXhttpPaddingMethod::RepeatX),
        "tokenish" => Ok(ResidentXhttpPaddingMethod::Tokenish),
        other => Err(format!(
            "resident dataplane vless xHTTP {field}.xPaddingMethod is unsupported for node {node_tag}: {other}"
        )),
    }
}

fn resident_xhttp_meta_placement(
    value: Option<&str>,
    default: ResidentXhttpMetaPlacement,
    label: &str,
    field: &str,
    node_tag: &str,
) -> Result<ResidentXhttpMetaPlacement, String> {
    match value.unwrap_or_default() {
        "" => Ok(default),
        "path" => Ok(ResidentXhttpMetaPlacement::Path),
        "cookie" => Ok(ResidentXhttpMetaPlacement::Cookie),
        "header" => Ok(ResidentXhttpMetaPlacement::Header),
        "query" => Ok(ResidentXhttpMetaPlacement::Query),
        other => Err(format!(
            "resident dataplane vless xHTTP {field}.{label} placement is unsupported for node {node_tag}: {other}"
        )),
    }
}

fn resident_xhttp_uplink_data_placement(
    value: Option<&str>,
    field: &str,
    node_tag: &str,
) -> Result<ResidentXhttpUplinkDataPlacement, String> {
    match value.unwrap_or_default() {
        "" | "auto" => Ok(ResidentXhttpUplinkDataPlacement::Auto),
        "body" => Ok(ResidentXhttpUplinkDataPlacement::Body),
        "cookie" => Ok(ResidentXhttpUplinkDataPlacement::Cookie),
        "header" => Ok(ResidentXhttpUplinkDataPlacement::Header),
        other => Err(format!(
            "resident dataplane vless xHTTP {field}.uplinkDataPlacement is unsupported for node {node_tag}: {other}"
        )),
    }
}

fn resident_xhttp_xmux_plan(
    value: Option<&Value>,
    field: &str,
    node_tag: &str,
) -> Result<Option<ResidentXhttpXmuxPlan>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Value::Object(object) = value else {
        if value.is_null() {
            return Ok(None);
        }
        return Err(format!(
            "resident dataplane vless xHTTP {field} must be a JSON object for node {node_tag}"
        ));
    };
    reject_unknown_object_fields(
        object,
        &[
            "maxConcurrency",
            "maxConnections",
            "cMaxReuseTimes",
            "hMaxRequestTimes",
            "hMaxReusableSecs",
            "hKeepAlivePeriod",
        ],
        &format!("resident dataplane vless xHTTP {field}"),
        node_tag,
    )?;
    let plan = ResidentXhttpXmuxPlan {
        runtime_generation: 0,
        physical_connection_limit: 0,
        max_concurrency: optional_xhttp_range(
            object.get("maxConcurrency"),
            &format!("{field}.maxConcurrency"),
            node_tag,
        )?,
        max_connections: optional_xhttp_range(
            object.get("maxConnections"),
            &format!("{field}.maxConnections"),
            node_tag,
        )?,
        c_max_reuse_times: optional_xhttp_range(
            object.get("cMaxReuseTimes"),
            &format!("{field}.cMaxReuseTimes"),
            node_tag,
        )?,
        h_max_request_times: optional_xhttp_range(
            object.get("hMaxRequestTimes"),
            &format!("{field}.hMaxRequestTimes"),
            node_tag,
        )?,
        h_max_reusable_secs: optional_xhttp_range(
            object.get("hMaxReusableSecs"),
            &format!("{field}.hMaxReusableSecs"),
            node_tag,
        )?,
        h_keep_alive_period: optional_i64(
            object.get("hKeepAlivePeriod"),
            &format!("{field}.hKeepAlivePeriod"),
            node_tag,
        )?
        .unwrap_or(0),
    }
    .official_normalized();
    plan.validate_official(field, node_tag)?;
    Ok(Some(plan))
}
