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
        "tcp" if !(vless.flow.is_empty() || is_xtls_rprx_vision_flow(&vless.flow)) => {
            return Err(format!(
                "resident dataplane vless native tcp admits empty flow or official Vision flows, got '{}' for node {node_tag}; resident shape remains fail-closed for this config",
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
    if !matches!(vless.tls.as_str(), "none" | "tls" | "reality") {
        return Err(format!(
            "resident dataplane vless handler currently supports security=none, security=tls, or security=reality only, got {} for node {node_tag}",
            vless.tls
        ));
    }
    if vless.tls == "none" && (net != "tcp" || vless.mux || !vless.flow.is_empty()) {
        return Err(format!(
            "resident dataplane vless security=none currently admits native tcp empty-flow endpoints only for node {node_tag}; got net={net}, mux={}, flow='{}'",
            vless.mux, vless.flow
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
    let tls_fragment = if vless.tls == "tls" {
        resident_tls_fragment_plan(config)?
    } else {
        None
    };
    let utls_fingerprint = if vless.tls == "tls" {
        resident_utls_fingerprint_plan(config, Some(&vless.fingerprint))?
    } else {
        None
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
            reality.as_ref(),
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
    if net == "xhttp" {
        validate_resident_xhttp_settings_for_mode(
            &xhttp_extra.settings,
            xhttp_mode,
            "extra",
            &node_tag,
        )?;
    }
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
        xhttp_settings: xhttp_extra.settings,
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
    settings: ResidentXhttpSettingsPlan,
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

const XHTTP_SETTINGS_FIELDS: &[&str] = &[
    "host",
    "path",
    "mode",
    "headers",
    "xPaddingBytes",
    "xPaddingObfsMode",
    "xPaddingKey",
    "xPaddingHeader",
    "xPaddingPlacement",
    "xPaddingMethod",
    "uplinkHTTPMethod",
    "sessionIDPlacement",
    "sessionIDKey",
    "sessionIDTable",
    "sessionIDLength",
    "seqPlacement",
    "seqKey",
    "uplinkDataPlacement",
    "uplinkDataKey",
    "uplinkChunkSize",
    "noGRPCHeader",
    "noSSEHeader",
    "scMaxEachPostBytes",
    "scMinPostsIntervalMs",
    "scMaxBufferedPosts",
    "scStreamUpServerSecs",
    "serverMaxHeaderBytes",
    "xmux",
    "downloadSettings",
    "extra",
];

fn resident_xhttp_extra_plan(
    extra: &str,
    primary_server_name: &str,
    primary_reality: Option<&ResidentRealityUnderlayPlan>,
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
    let overlay = resident_xhttp_extra_overlay_object(
        object.get("extra"),
        "resident dataplane vless xHTTP extra.extra",
        node_tag,
    )?;
    let object = overlay
        .as_ref()
        .and_then(Value::as_object)
        .unwrap_or(object);
    reject_unknown_object_fields(
        object,
        XHTTP_SETTINGS_FIELDS,
        "resident dataplane vless xHTTP extra",
        node_tag,
    )?;
    let parsed_settings = resident_xhttp_settings_and_xmux_plan(object, "extra", node_tag)?;
    let xmux = parsed_settings.xmux;
    let Some(download) = object.get("downloadSettings") else {
        return Ok(ResidentXhttpExtraPlan {
            download: None,
            settings: parsed_settings.settings,
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
            "realitySettings",
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
    let (server_name, alpn, allow_insecure, reality) = match security.as_str() {
        "tls" => {
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
            (server_name, alpn, allow_insecure, None)
        }
        "reality" => resident_xhttp_download_reality_settings(
            optional_object(
                download.get("realitySettings"),
                "downloadSettings.realitySettings",
                node_tag,
            )?,
            &server_host,
            primary_server_name,
            primary_reality,
            global_allow_insecure,
            node_tag,
        )?,
        other => {
            return Err(format!(
                "resident dataplane vless xHTTP downloadSettings admits security=tls or security=reality for node {node_tag}; got {other}"
            ));
        }
    };
    let xhttp_settings = resident_xhttp_download_transport_settings(download, &security, node_tag)?;
    Ok(ResidentXhttpExtraPlan {
        download: Some(ResidentXhttpEndpointPlan {
            server_host,
            server_port,
            server_name,
            alpn,
            stream_host: xhttp_settings.host,
            stream_path: xhttp_settings.path,
            mode: xhttp_settings.mode,
            settings: xhttp_settings.settings,
            xmux: xhttp_settings.xmux,
            allow_insecure,
            tls_fragment: None,
            reality,
        }),
        settings: parsed_settings.settings,
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

fn resident_xhttp_download_reality_settings(
    reality_settings: Option<&serde_json::Map<String, Value>>,
    server_host: &str,
    primary_server_name: &str,
    primary_reality: Option<&ResidentRealityUnderlayPlan>,
    global_allow_insecure: bool,
    node_tag: &str,
) -> Result<
    (
        String,
        Vec<String>,
        bool,
        Option<ResidentRealityUnderlayPlan>,
    ),
    String,
> {
    let Some(reality_settings) = reality_settings else {
        let Some(primary_reality) = primary_reality else {
            return Err(format!(
                "resident dataplane vless xHTTP downloadSettings.security=reality requires realitySettings when the primary xHTTP underlay is not Reality for node {node_tag}"
            ));
        };
        return Ok((
            if primary_server_name.is_empty() {
                server_host.to_owned()
            } else {
                primary_server_name.to_owned()
            },
            vec!["h2".to_owned()],
            global_allow_insecure,
            Some(primary_reality.clone()),
        ));
    };
    reject_unknown_object_fields(
        reality_settings,
        &[
            "allowInsecure",
            "serverName",
            "alpn",
            "publicKey",
            "shortId",
            "spiderX",
        ],
        "resident dataplane vless xHTTP downloadSettings.realitySettings",
        node_tag,
    )?;
    let server_name = optional_string(
        reality_settings.get("serverName"),
        "realitySettings.serverName",
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
    let alpn = optional_alpn(
        reality_settings.get("alpn"),
        "realitySettings.alpn",
        node_tag,
    )?
    .unwrap_or_else(|| vec!["h2".to_owned()]);
    validate_resident_xhttp_endpoint_alpn(&alpn, node_tag)?;
    if ResidentXhttpHttpVersion::from_tls_alpn(&alpn) == ResidentXhttpHttpVersion::H1 {
        return Err(format!(
            "resident dataplane vless xHTTP downloadSettings.security=reality follows official HTTP/2 selection and does not admit single http/1.1 ALPN for node {node_tag}; got {}",
            alpn.join(",")
        ));
    }
    let allow_insecure = global_allow_insecure
        || optional_bool(
            reality_settings.get("allowInsecure"),
            "realitySettings.allowInsecure",
            node_tag,
        )?
        .unwrap_or(false);
    let public_key = optional_string(
        reality_settings.get("publicKey"),
        "realitySettings.publicKey",
        node_tag,
    )?
    .filter(|value| !value.is_empty())
    .map(|value| {
        ir::reality_pbk_decode(&value)
            .map_err(|err| err.to_string())?
            .try_into()
            .map_err(|_| "Reality publicKey must decode to 32 bytes".to_owned())
    })
    .transpose()?
    .or_else(|| primary_reality.map(|reality| reality.public_key))
    .ok_or_else(|| {
        format!(
            "resident dataplane vless xHTTP downloadSettings.security=reality requires realitySettings.publicKey for node {node_tag}"
        )
    })?;
    let short_id = optional_string(
        reality_settings.get("shortId"),
        "realitySettings.shortId",
        node_tag,
    )?
    .map(|value| ir::reality_short_id_decode(&value).map_err(|err| err.to_string()))
    .transpose()?
    .or_else(|| primary_reality.map(|reality| reality.short_id.clone()))
    .unwrap_or_default();
    let spider_x = optional_string(
        reality_settings.get("spiderX"),
        "realitySettings.spiderX",
        node_tag,
    )?
    .or_else(|| primary_reality.map(|reality| reality.spider_x.clone()))
    .unwrap_or_else(|| "/".to_owned());
    Ok((
        server_name,
        alpn,
        allow_insecure,
        Some(ResidentRealityUnderlayPlan {
            public_key,
            short_id,
            spider_x,
        }),
    ))
}

#[derive(Debug)]
struct ResidentXhttpTransportSettings {
    host: String,
    path: String,
    mode: ResidentXhttpMode,
    settings: ResidentXhttpSettingsPlan,
    xmux: Option<ResidentXhttpXmuxPlan>,
}

fn resident_xhttp_download_transport_settings(
    download: &serde_json::Map<String, Value>,
    security: &str,
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
    let overlay = resident_xhttp_extra_overlay_object(
        settings.get("extra"),
        "resident dataplane vless xHTTP downloadSettings.xhttpSettings.extra",
        node_tag,
    )?;
    let effective_settings = overlay
        .as_ref()
        .and_then(Value::as_object)
        .unwrap_or(settings);
    reject_unknown_object_fields(
        settings,
        XHTTP_SETTINGS_FIELDS,
        "resident dataplane vless xHTTP downloadSettings.xhttpSettings",
        node_tag,
    )?;
    reject_unknown_object_fields(
        effective_settings,
        XHTTP_SETTINGS_FIELDS,
        "resident dataplane vless xHTTP downloadSettings.xhttpSettings.extra",
        node_tag,
    )?;
    let mode =
        optional_string(settings.get("mode"), "xhttpSettings.mode", node_tag)?.unwrap_or_default();
    let mode_result = ir::normalize_xhttp_mode(&mode, "https", security, false);
    if !mode_result.ok {
        return Err(format!(
            "resident dataplane vless xHTTP downloadSettings rejected mode for node {node_tag}: {}",
            mode_result.error_contains
        ));
    }
    let mode = resident_xhttp_mode_from_normalized(&mode_result.normalized, node_tag)?;
    let parsed_settings = resident_xhttp_settings_and_xmux_plan(
        effective_settings,
        "downloadSettings.xhttpSettings",
        node_tag,
    )?;
    validate_resident_xhttp_settings_for_mode(
        &parsed_settings.settings,
        mode,
        "downloadSettings.xhttpSettings",
        node_tag,
    )?;
    let host =
        optional_string(settings.get("host"), "xhttpSettings.host", node_tag)?.unwrap_or_default();
    let path = optional_string(settings.get("path"), "xhttpSettings.path", node_tag)?
        .map(|value| resident_xhttp_stream_path(&value))
        .unwrap_or_else(|| resident_xhttp_stream_path(""));
    Ok(ResidentXhttpTransportSettings {
        host,
        path,
        mode,
        settings: parsed_settings.settings,
        xmux: Some(
            parsed_settings
                .xmux
                .unwrap_or_else(ResidentXhttpXmuxPlan::official_default)
                .official_normalized(),
        ),
    })
}

struct ResidentXhttpParsedSettings {
    settings: ResidentXhttpSettingsPlan,
    xmux: Option<ResidentXhttpXmuxPlan>,
}

fn resident_xhttp_extra_overlay_object(
    value: Option<&Value>,
    context: &str,
    node_tag: &str,
) -> Result<Option<Value>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) if raw.trim().is_empty() => Ok(None),
        Some(Value::String(raw)) => {
            let parsed = serde_json::from_str::<Value>(raw)
                .map_err(|err| format!("{context} must be JSON for node {node_tag}: {err}"))?;
            if parsed.is_object() {
                Ok(Some(parsed))
            } else {
                Err(format!(
                    "{context} must be a JSON object for node {node_tag}"
                ))
            }
        }
        Some(Value::Object(_)) => Ok(value.cloned()),
        Some(_) => Err(format!(
            "{context} must be a JSON object or JSON string for node {node_tag}"
        )),
    }
}

fn resident_xhttp_settings_and_xmux_plan(
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

fn validate_resident_xhttp_settings_for_mode(
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
