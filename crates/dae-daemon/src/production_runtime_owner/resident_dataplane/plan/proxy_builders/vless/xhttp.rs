use super::*;

mod parsing;
mod settings;
use self::parsing::{
    optional_alpn, optional_bool, optional_object, optional_string, reject_unknown_object_fields,
    required_string, required_u16, resident_xhttp_extra_overlay_object,
};
use self::settings::resident_xhttp_settings_and_xmux_plan;

#[derive(Default)]
pub(super) struct ResidentXhttpExtraPlan {
    pub(super) download: Option<ResidentXhttpEndpointPlan>,
    pub(super) settings: ResidentXhttpSettingsPlan,
    pub(super) xmux: Option<ResidentXhttpXmuxPlan>,
}

pub(super) fn resident_xhttp_mode_from_normalized(
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

pub(super) fn resident_xhttp_extra_plan(
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

pub(super) fn validate_resident_xhttp_settings_for_mode(
    settings: &ResidentXhttpSettingsPlan,
    mode: ResidentXhttpMode,
    field: &str,
    node_tag: &str,
) -> Result<(), String> {
    settings::validate_resident_xhttp_settings_for_mode(settings, mode, field, node_tag)
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

pub(super) fn validate_resident_xhttp_primary_alpn(
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
