use super::*;
pub(crate) fn build_vless_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let vless =
        VLESSLink::parse(&link).map_err(|err| format!("parse VLESS node {node_tag}: {err}"))?;
    vless
        .validate_flow_client(true)
        .map_err(|err| format!("validate VLESS flow for {node_tag}: {err}"))?;
    vless
        .validate_transport_contract()
        .map_err(|err| format!("validate VLESS transport for {node_tag}: {err}"))?;
    let net = canonical_resident_vless_net(&vless.net);
    if vless.mux && net != "tcp" {
        return Err(format!(
            "resident dataplane vless mux transport admits tcp carrier only for node {node_tag}; got {net}"
        ));
    }
    match net.as_str() {
        "tcp" if vless.mux && vless.flow.is_empty() => {}
        "tcp" if !matches!(vless.flow.as_str(), "" | XTLS_RPRX_VISION) => {
            return Err(format!(
                "resident dataplane vless native tcp admits empty flow or flow={XTLS_RPRX_VISION}, got '{}' for node {node_tag}; resident shape remains fail-closed for this config",
                vless.flow
            ));
        }
        "websocket" | "httpupgrade" | "grpc" | "xhttp" | "meek" if !vless.flow.is_empty() => {
            return Err(format!(
                "resident dataplane vless wrapped-stream handler admits only empty flow, got '{}' for node {node_tag}; resident shape remains fail-closed for this config",
                vless.flow
            ));
        }
        "tcp" | "websocket" | "httpupgrade" | "grpc" | "xhttp" | "meek" => {}
        other => {
            return Err(format!(
                "resident dataplane vless handler currently supports tcp, websocket, httpupgrade, grpc, xhttp, and meek transports only, got {other} for node {node_tag}"
            ));
        }
    }
    if !matches!(vless.tls.as_str(), "tls" | "reality") {
        return Err(format!(
            "resident dataplane vless handler currently supports security=tls or security=reality only, got {} for node {node_tag}",
            vless.tls
        ));
    }
    if vless.mux && vless.tls != "tls" {
        return Err(format!(
            "resident dataplane vless mux transport admits standard tls underlay only for node {node_tag}; got {}",
            vless.tls
        ));
    }
    let requested_allow_insecure = vless.allow_insecure || config.global.allow_insecure;
    let meek_options = if net == "meek" {
        Some(
            MeekRoundTripOptions::from_https_url(&vless.path, Vec::new()).map_err(|err| {
                format!(
                    "resident dataplane vless Meek transport requires a standard https url for node {node_tag}: {err}"
                )
            })?,
        )
    } else {
        None
    };
    let reality = resident_reality_underlay_plan(&vless)
        .map_err(|err| format!("validate VLESS Reality for {node_tag}: {err}"))?;
    let allow_insecure = requested_allow_insecure;
    let tls_fragment = if reality.is_some() {
        None
    } else {
        resident_tls_fragment_plan(config)?
    };
    let utls_fingerprint = if reality.is_some() {
        None
    } else {
        resident_utls_fingerprint_plan(config, Some(&vless.fingerprint))?
    };
    let server_port = vless.port.parse::<u16>().map_err(|err| {
        format!(
            "invalid VLESS port {} for node {node_tag}: {err}",
            vless.port
        )
    })?;
    let key = password_to_key(&vless.id)
        .map_err(|err| format!("parse VLESS key for {node_tag}: {err}"))?;
    let server_name = if vless.sni.is_empty() {
        vless.add.clone()
    } else {
        vless.sni.clone()
    };
    let xhttp_extra = if net == "xhttp" {
        resident_xhttp_extra_plan(
            &vless.xhttp_extra,
            &server_name,
            config.global.allow_insecure,
            &node_tag,
        )?
    } else {
        ResidentXhttpExtraPlan::default()
    };
    let xhttp_mode = if net == "xhttp" {
        let mode = ir::normalize_xhttp_mode(
            &vless.xhttp_mode,
            "https",
            &vless.tls,
            xhttp_extra.download.is_some(),
        );
        if !mode.ok {
            return Err(format!(
                "resident dataplane vless xHTTP transport rejected mode for node {node_tag}: {}",
                mode.error_contains
            ));
        }
        let mode = resident_xhttp_mode_from_normalized(&mode.normalized, &node_tag)?;
        let alpn_result = ir::validate_xhttp_alpn(&vless.tls, &vless.alpn);
        if !alpn_result.ok {
            return Err(format!(
                "resident dataplane vless xHTTP transport rejected ALPN for node {node_tag}: {}",
                alpn_result.error_contains
            ));
        }
        validate_resident_xhttp_primary_alpn(&vless.alpn, &vless.tls, &node_tag)?;
        mode
    } else {
        ResidentXhttpMode::PacketUp
    };
    let alpn = if matches!(net.as_str(), "grpc" | "xhttp") && vless.alpn.is_empty() {
        vec!["h2".to_owned()]
    } else {
        split_alpn(&vless.alpn)
    };
    let stream_host = if let Some(meek_options) = &meek_options {
        meek_options.host.clone()
    } else if matches!(net.as_str(), "websocket" | "httpupgrade" | "grpc" | "xhttp") {
        resident_stream_host(&vless.host, &server_name)
    } else {
        String::new()
    };
    let stream_path = if net == "grpc" {
        resident_grpc_service_name(&vless.path)
    } else if let Some(meek_options) = &meek_options {
        meek_options.path.clone()
    } else if net == "xhttp" {
        resident_xhttp_stream_path(&vless.path)
    } else if matches!(net.as_str(), "websocket" | "httpupgrade") {
        resident_stream_path(&vless.path)
    } else {
        String::new()
    };
    let graph = resident_graph_identity(&link);
    let handler = if vless.mux {
        ResidentProxyProtocolPlan::VlessMuxTcpTls { key }
    } else {
        ResidentProxyProtocolPlan::VlessVisionTcpTls { key }
    };
    let xhttp_xmux = if net == "xhttp" {
        Some(
            xhttp_extra
                .xmux
                .unwrap_or_else(ResidentXhttpXmuxPlan::official_default)
                .official_normalized(),
        )
    } else {
        None
    };
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "vless".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: vless.add,
        server_port,
        server_name,
        alpn,
        flow: vless.flow,
        net,
        stream_host,
        stream_path,
        xhttp_download: xhttp_extra.download,
        xhttp_mode,
        xhttp_xmux,
        tls: vless.tls,
        allow_insecure,
        tls_fragment,
        utls_fingerprint,
        reality,
        handler,
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn resident_reality_underlay_plan(
    vless: &VLESSLink,
) -> Result<Option<ResidentRealityUnderlayPlan>, String> {
    if vless.tls != "reality" {
        return Ok(None);
    }
    if vless.public_key.is_empty() {
        return Err("Reality public key is required".to_owned());
    }
    let public_key = ir::reality_pbk_decode(&vless.public_key)
        .map_err(|err| err.to_string())?
        .try_into()
        .map_err(|_| "Reality public key must decode to 32 bytes".to_owned())?;
    let short_id = ir::reality_short_id_decode(&vless.short_id).map_err(|err| err.to_string())?;
    Ok(Some(ResidentRealityUnderlayPlan {
        public_key,
        short_id,
        spider_x: vless.spider_x.clone(),
    }))
}

#[derive(Default)]
struct ResidentXhttpExtraPlan {
    download: Option<ResidentXhttpEndpointPlan>,
    xmux: Option<ResidentXhttpXmuxPlan>,
}

fn resident_xhttp_mode_from_normalized(
    mode: &str,
    node_tag: &str,
) -> Result<ResidentXhttpMode, String> {
    match mode {
        "packet-up" => Ok(ResidentXhttpMode::PacketUp),
        "stream-up" => Ok(ResidentXhttpMode::StreamUp),
        "stream-one" => Ok(ResidentXhttpMode::StreamOne),
        other => Err(format!(
            "resident dataplane vless xHTTP transport normalized to unsupported mode {other} for node {node_tag}"
        )),
    }
}

fn resident_xhttp_extra_plan(
    extra: &str,
    primary_server_name: &str,
    global_allow_insecure: bool,
    node_tag: &str,
) -> Result<ResidentXhttpExtraPlan, String> {
    let extra = extra.trim();
    if extra.is_empty() {
        return Ok(ResidentXhttpExtraPlan::default());
    }
    let value = serde_json::from_str::<Value>(extra).map_err(|err| {
        format!("resident dataplane vless xHTTP extra must be JSON for node {node_tag}: {err}")
    })?;
    let object = value.as_object().ok_or_else(|| {
        format!("resident dataplane vless xHTTP extra must be a JSON object for node {node_tag}")
    })?;
    if object.is_empty() {
        return Ok(ResidentXhttpExtraPlan::default());
    }
    reject_unknown_object_fields(
        object,
        &["downloadSettings", "xmux"],
        "resident dataplane vless xHTTP extra",
        node_tag,
    )?;
    let xmux = resident_xhttp_xmux_plan(object.get("xmux"), "extra.xmux", node_tag)?;
    let Some(download) = object.get("downloadSettings") else {
        return Ok(ResidentXhttpExtraPlan {
            download: None,
            xmux,
        });
    };
    let download = download.as_object().ok_or_else(|| {
        format!(
            "resident dataplane vless xHTTP downloadSettings must be a JSON object for node {node_tag}"
        )
    })?;
    reject_unknown_object_fields(
        download,
        &[
            "address",
            "port",
            "network",
            "security",
            "tlsSettings",
            "xhttpSettings",
            "splithttpSettings",
        ],
        "resident dataplane vless xHTTP downloadSettings",
        node_tag,
    )?;
    let server_host = required_string(
        download.get("address"),
        "downloadSettings.address",
        node_tag,
    )?;
    let server_port = required_u16(download.get("port"), "downloadSettings.port", node_tag)?;
    let network = optional_string(
        download.get("network"),
        "downloadSettings.network",
        node_tag,
    )?
    .unwrap_or_default()
    .to_ascii_lowercase();
    if !matches!(network.as_str(), "xhttp" | "splithttp") {
        return Err(format!(
            "resident dataplane vless xHTTP downloadSettings requires network=xhttp or splithttp for node {node_tag}; got {network}"
        ));
    }
    let security = optional_string(
        download.get("security"),
        "downloadSettings.security",
        node_tag,
    )?
    .unwrap_or_default()
    .to_ascii_lowercase();
    if security != "tls" {
        return Err(format!(
            "resident dataplane vless xHTTP downloadSettings currently admits security=tls only for node {node_tag}; got {security}"
        ));
    }
    let tls_settings = optional_object(
        download.get("tlsSettings"),
        "downloadSettings.tlsSettings",
        node_tag,
    )?;
    let (server_name, alpn, allow_insecure) = resident_xhttp_download_tls_settings(
        tls_settings,
        &server_host,
        primary_server_name,
        global_allow_insecure,
        node_tag,
    )?;
    let xhttp_settings = resident_xhttp_download_transport_settings(download, node_tag)?;
    Ok(ResidentXhttpExtraPlan {
        download: Some(ResidentXhttpEndpointPlan {
            server_host,
            server_port,
            server_name,
            alpn,
            stream_host: xhttp_settings.host,
            stream_path: xhttp_settings.path,
            mode: ResidentXhttpMode::PacketUp,
            xmux: xhttp_settings.xmux,
            allow_insecure,
            tls_fragment: None,
        }),
        xmux,
    })
}

fn resident_xhttp_download_tls_settings(
    tls_settings: Option<&serde_json::Map<String, Value>>,
    server_host: &str,
    primary_server_name: &str,
    global_allow_insecure: bool,
    node_tag: &str,
) -> Result<(String, Vec<String>, bool), String> {
    let Some(tls_settings) = tls_settings else {
        return Ok((
            if primary_server_name.is_empty() {
                server_host.to_owned()
            } else {
                primary_server_name.to_owned()
            },
            vec!["h2".to_owned()],
            global_allow_insecure,
        ));
    };
    reject_unknown_object_fields(
        tls_settings,
        &["allowInsecure", "serverName", "alpn"],
        "resident dataplane vless xHTTP downloadSettings.tlsSettings",
        node_tag,
    )?;
    let server_name = optional_string(
        tls_settings.get("serverName"),
        "tlsSettings.serverName",
        node_tag,
    )?
    .filter(|value| !value.is_empty())
    .unwrap_or_else(|| {
        if primary_server_name.is_empty() {
            server_host.to_owned()
        } else {
            primary_server_name.to_owned()
        }
    });
    let alpn = optional_alpn(tls_settings.get("alpn"), "tlsSettings.alpn", node_tag)?
        .unwrap_or_else(|| vec!["h2".to_owned()]);
    validate_resident_xhttp_endpoint_alpn(&alpn, node_tag)?;
    let allow_insecure = global_allow_insecure
        || optional_bool(
            tls_settings.get("allowInsecure"),
            "tlsSettings.allowInsecure",
            node_tag,
        )?
        .unwrap_or(false);
    Ok((server_name, alpn, allow_insecure))
}

#[derive(Debug)]
struct ResidentXhttpTransportSettings {
    host: String,
    path: String,
    xmux: Option<ResidentXhttpXmuxPlan>,
}

fn resident_xhttp_download_transport_settings(
    download: &serde_json::Map<String, Value>,
    node_tag: &str,
) -> Result<ResidentXhttpTransportSettings, String> {
    let settings = optional_object(
        download
            .get("xhttpSettings")
            .or_else(|| download.get("splithttpSettings")),
        "downloadSettings.xhttpSettings",
        node_tag,
    )?
    .ok_or_else(|| {
        format!(
            "resident dataplane vless xHTTP downloadSettings requires xhttpSettings or splithttpSettings for node {node_tag}"
        )
    })?;
    reject_unknown_object_fields(
        settings,
        &["host", "path", "mode", "extra", "xmux"],
        "resident dataplane vless xHTTP downloadSettings.xhttpSettings",
        node_tag,
    )?;
    let mode =
        optional_string(settings.get("mode"), "xhttpSettings.mode", node_tag)?.unwrap_or_default();
    if !mode.is_empty() {
        let mode_result = ir::normalize_xhttp_mode(&mode, "https", "tls", false);
        if !mode_result.ok {
            return Err(format!(
                "resident dataplane vless xHTTP downloadSettings rejected mode for node {node_tag}: {}",
                mode_result.error_contains
            ));
        }
        if !matches!(
            mode_result.normalized.as_str(),
            "packet-up" | "stream-up" | "stream-one"
        ) {
            return Err(format!(
                "resident dataplane vless xHTTP downloadSettings admits official xHTTP modes only for node {node_tag}; got {}",
                mode_result.normalized
            ));
        }
    }
    let xmux = resident_xhttp_download_xmux_plan(settings, node_tag)?;
    let host =
        optional_string(settings.get("host"), "xhttpSettings.host", node_tag)?.unwrap_or_default();
    let path = optional_string(settings.get("path"), "xhttpSettings.path", node_tag)?
        .map(|value| resident_xhttp_stream_path(&value))
        .unwrap_or_else(|| resident_xhttp_stream_path(""));
    Ok(ResidentXhttpTransportSettings { host, path, xmux })
}

fn resident_xhttp_download_xmux_plan(
    settings: &serde_json::Map<String, Value>,
    node_tag: &str,
) -> Result<Option<ResidentXhttpXmuxPlan>, String> {
    let direct = resident_xhttp_xmux_plan(
        settings.get("xmux"),
        "downloadSettings.xhttpSettings.xmux",
        node_tag,
    )?;
    let nested = match settings.get("extra") {
        Some(extra) => resident_xhttp_nested_extra_xmux_plan(extra, node_tag)?,
        None => None,
    };
    if direct.is_some() && nested.is_some() {
        return Err(format!(
            "resident dataplane vless xHTTP downloadSettings.xhttpSettings must not contain xmux in both xmux and extra.xmux for node {node_tag}"
        ));
    }
    Ok(Some(
        direct
            .or(nested)
            .unwrap_or_else(ResidentXhttpXmuxPlan::official_default)
            .official_normalized(),
    ))
}

fn resident_xhttp_nested_extra_xmux_plan(
    extra: &Value,
    node_tag: &str,
) -> Result<Option<ResidentXhttpXmuxPlan>, String> {
    let parsed;
    let object = match extra {
        Value::Null => return Ok(None),
        Value::String(raw) if raw.trim().is_empty() => return Ok(None),
        Value::String(raw) => {
            parsed = serde_json::from_str::<Value>(raw).map_err(|err| {
                format!(
                    "resident dataplane vless xHTTP downloadSettings.xhttpSettings.extra must be JSON for node {node_tag}: {err}"
                )
            })?;
            parsed.as_object().ok_or_else(|| {
                format!(
                    "resident dataplane vless xHTTP downloadSettings.xhttpSettings.extra must be a JSON object for node {node_tag}"
                )
            })?
        }
        Value::Object(object) => object,
        _ => {
            return Err(format!(
                "resident dataplane vless xHTTP downloadSettings.xhttpSettings.extra must be a JSON object or JSON string for node {node_tag}"
            ));
        }
    };
    if object.is_empty() {
        return Ok(None);
    }
    reject_unknown_object_fields(
        object,
        &["xmux"],
        "resident dataplane vless xHTTP downloadSettings.xhttpSettings.extra",
        node_tag,
    )?;
    resident_xhttp_xmux_plan(
        object.get("xmux"),
        "downloadSettings.xhttpSettings.extra.xmux",
        node_tag,
    )
}

fn reject_unknown_object_fields(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    context: &str,
    node_tag: &str,
) -> Result<(), String> {
    let unsupported = object
        .keys()
        .filter(|key| !allowed.iter().any(|allowed| key.as_str() == *allowed))
        .cloned()
        .collect::<Vec<_>>();
    if unsupported.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{context} contains unsupported fields for node {node_tag}: {}",
        unsupported.join(",")
    ))
}

fn optional_object<'a>(
    value: Option<&'a Value>,
    field: &str,
    node_tag: &str,
) -> Result<Option<&'a serde_json::Map<String, Value>>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(object)) => Ok(Some(object)),
        Some(_) => Err(format!(
            "resident dataplane vless xHTTP {field} must be a JSON object for node {node_tag}"
        )),
    }
}

fn required_string(value: Option<&Value>, field: &str, node_tag: &str) -> Result<String, String> {
    optional_string(value, field, node_tag)?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!("resident dataplane vless xHTTP {field} is required for node {node_tag}")
        })
}

fn optional_string(
    value: Option<&Value>,
    field: &str,
    node_tag: &str,
) -> Result<Option<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.trim().to_owned())),
        Some(_) => Err(format!(
            "resident dataplane vless xHTTP {field} must be a string for node {node_tag}"
        )),
    }
}

fn required_u16(value: Option<&Value>, field: &str, node_tag: &str) -> Result<u16, String> {
    let Some(value) = value else {
        return Err(format!(
            "resident dataplane vless xHTTP {field} is required for node {node_tag}"
        ));
    };
    let port = value.as_u64().ok_or_else(|| {
        format!("resident dataplane vless xHTTP {field} must be an integer for node {node_tag}")
    })?;
    if port == 0 || port > u16::MAX as u64 {
        return Err(format!(
            "resident dataplane vless xHTTP {field} must be in 1..=65535 for node {node_tag}; got {port}"
        ));
    }
    Ok(port as u16)
}

fn optional_bool(
    value: Option<&Value>,
    field: &str,
    node_tag: &str,
) -> Result<Option<bool>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(format!(
            "resident dataplane vless xHTTP {field} must be a boolean for node {node_tag}"
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

fn optional_xhttp_range(
    value: Option<&Value>,
    field: &str,
    node_tag: &str,
) -> Result<Option<(i32, i32)>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let range = match value {
        Value::Number(number) => {
            let value = number.as_i64().ok_or_else(|| {
                format!(
                    "resident dataplane vless xHTTP {field} must be an integer for node {node_tag}"
                )
            })?;
            let value = i32::try_from(value).map_err(|_| {
                format!(
                    "resident dataplane vless xHTTP {field} is too large for node {node_tag}: {value}"
                )
            })?;
            (value, value)
        }
        Value::String(raw) => parse_xhttp_range_string(raw, field, node_tag)?,
        Value::Object(object) => {
            reject_unknown_object_fields(
                object,
                &["from", "to"],
                &format!("resident dataplane vless xHTTP {field}"),
                node_tag,
            )?;
            let from =
                optional_i32(object.get("from"), &format!("{field}.from"), node_tag)?.unwrap_or(0);
            let to = optional_i32(object.get("to"), &format!("{field}.to"), node_tag)?.unwrap_or(0);
            (from, to)
        }
        _ => {
            return Err(format!(
                "resident dataplane vless xHTTP {field} must be an integer, string range, or {{from,to}} object for node {node_tag}"
            ));
        }
    };
    Ok(Some(if range.0 <= range.1 {
        range
    } else {
        (range.1, range.0)
    }))
}

fn parse_xhttp_range_string(raw: &str, field: &str, node_tag: &str) -> Result<(i32, i32), String> {
    let raw = raw.trim();
    if let Ok(value) = raw.parse::<i32>() {
        return Ok((value, value));
    }
    if raw.is_empty() {
        return Ok((0, 0));
    }
    let (from, to) = if raw.starts_with('-') {
        let split_at = raw
            .match_indices('-')
            .nth(1)
            .map(|(index, _)| index)
            .ok_or_else(|| {
                format!(
                    "resident dataplane vless xHTTP {field} must be an integer range for node {node_tag}"
                )
            })?;
        (&raw[..split_at], &raw[split_at + 1..])
    } else {
        raw.split_once('-').ok_or_else(|| {
            format!(
                "resident dataplane vless xHTTP {field} must be an integer range for node {node_tag}"
            )
        })?
    };
    Ok((
        parse_xhttp_i32_str(from.trim(), &format!("{field}.from"), node_tag)?,
        parse_xhttp_i32_str(to.trim(), &format!("{field}.to"), node_tag)?,
    ))
}

fn optional_i32(value: Option<&Value>, field: &str, node_tag: &str) -> Result<Option<i32>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => {
            let value = number.as_i64().ok_or_else(|| {
                format!(
                    "resident dataplane vless xHTTP {field} must be an integer for node {node_tag}"
                )
            })?;
            i32::try_from(value).map(Some).map_err(|_| {
                format!(
                    "resident dataplane vless xHTTP {field} is too large for node {node_tag}: {value}"
                )
            })
        }
        Some(Value::String(raw)) => parse_xhttp_i32_str(raw, field, node_tag).map(Some),
        Some(_) => Err(format!(
            "resident dataplane vless xHTTP {field} must be an integer for node {node_tag}"
        )),
    }
}

fn optional_i64(value: Option<&Value>, field: &str, node_tag: &str) -> Result<Option<i64>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number.as_i64().map(Some).ok_or_else(|| {
            format!(
                "resident dataplane vless xHTTP {field} must be an integer for node {node_tag}"
            )
        }),
        Some(Value::String(raw)) => raw.trim().parse::<i64>().map(Some).map_err(|err| {
            format!(
                "resident dataplane vless xHTTP {field} must be an integer for node {node_tag}: {err}"
            )
        }),
        Some(_) => Err(format!(
            "resident dataplane vless xHTTP {field} must be an integer for node {node_tag}"
        )),
    }
}

fn parse_xhttp_i32_str(raw: &str, field: &str, node_tag: &str) -> Result<i32, String> {
    raw.trim().parse::<i32>().map_err(|err| {
        format!(
            "resident dataplane vless xHTTP {field} must be an integer for node {node_tag}: {err}"
        )
    })
}

fn optional_alpn(
    value: Option<&Value>,
    field: &str,
    node_tag: &str,
) -> Result<Option<Vec<String>>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(split_alpn(value))),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value.as_str().map(|value| value.trim().to_owned()).ok_or_else(|| {
                    format!(
                        "resident dataplane vless xHTTP {field} entries must be strings for node {node_tag}"
                    )
                })
            })
            .filter(|result| result.as_ref().map_or(true, |value| !value.is_empty()))
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(format!(
            "resident dataplane vless xHTTP {field} must be a string or string array for node {node_tag}"
        )),
    }
}

fn validate_resident_xhttp_endpoint_alpn(alpn: &[String], node_tag: &str) -> Result<(), String> {
    if resident_xhttp_tls_alpn_supported(alpn) {
        return Ok(());
    }
    Err(format!(
        "resident dataplane vless xHTTP endpoint admits empty, single http/1.1, h2-compatible, or single h3 ALPN for node {node_tag}; got {}",
        alpn.join(",")
    ))
}

fn validate_resident_xhttp_primary_alpn(
    raw_alpn: &str,
    security: &str,
    node_tag: &str,
) -> Result<(), String> {
    let alpn = if raw_alpn.trim().is_empty() {
        Vec::new()
    } else {
        split_alpn(raw_alpn)
    };
    let http_version = ResidentXhttpHttpVersion::from_tls_alpn(&alpn);
    if security.eq_ignore_ascii_case("reality") && http_version == ResidentXhttpHttpVersion::H1 {
        return Err(format!(
            "resident dataplane vless xHTTP Reality follows official HTTP/2 selection and does not admit single http/1.1 ALPN for node {node_tag}; got {}",
            alpn.join(",")
        ));
    }
    if resident_xhttp_tls_alpn_supported(&alpn) {
        return Ok(());
    }
    Err(format!(
        "resident dataplane vless xHTTP transport admits empty, single http/1.1, h2-compatible, or single h3 ALPN for node {node_tag}; got {}",
        alpn.join(",")
    ))
}

fn resident_xhttp_tls_alpn_supported(alpn: &[String]) -> bool {
    match ResidentXhttpHttpVersion::from_tls_alpn(alpn) {
        ResidentXhttpHttpVersion::H1 | ResidentXhttpHttpVersion::H3 => true,
        ResidentXhttpHttpVersion::H2 => {
            alpn.is_empty() || alpn.iter().any(|value| value.eq_ignore_ascii_case("h2"))
        }
    }
}
