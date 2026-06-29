use super::*;

mod xhttp;
use self::xhttp::{
    ResidentXhttpExtraPlan, resident_xhttp_extra_plan, resident_xhttp_mode_from_normalized,
    validate_resident_xhttp_primary_alpn, validate_resident_xhttp_settings_for_mode,
};
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
        "websocket" | "httpupgrade" | "grpc" | "h2" | "xhttp" | "meek"
            if !vless.flow.is_empty() =>
        {
            return Err(format!(
                "resident dataplane vless wrapped-stream handler admits only empty flow, got '{}' for node {node_tag}; resident shape remains fail-closed for this config",
                vless.flow
            ));
        }
        "tcp" | "websocket" | "httpupgrade" | "grpc" | "h2" | "xhttp" | "meek" => {}
        other => {
            return Err(format!(
                "resident dataplane vless handler currently supports tcp, websocket, httpupgrade, grpc, h2, xhttp, and meek transports only, got {other} for node {node_tag}"
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
    if net == "h2" && vless.tls != "tls" {
        return Err(format!(
            "resident dataplane vless h2 transport admits standard tls underlay only for node {node_tag}; got {}",
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
    let server_name = if net == "websocket" {
        resident_websocket_tls_server_name(&vless.sni, &vless.host, &vless.add)
    } else if vless.sni.is_empty() {
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
    let alpn = if matches!(net.as_str(), "grpc" | "h2" | "xhttp") && vless.alpn.is_empty() {
        vec!["h2".to_owned()]
    } else {
        split_alpn(&vless.alpn)
    };
    let stream_host = if let Some(meek_options) = &meek_options {
        meek_options.host.clone()
    } else if matches!(
        net.as_str(),
        "websocket" | "httpupgrade" | "grpc" | "h2" | "xhttp"
    ) {
        resident_stream_host(&vless.host, &server_name)
    } else {
        String::new()
    };
    let stream_path = if net == "grpc" {
        resident_grpc_service_name(&vless.path)
    } else if let Some(meek_options) = &meek_options {
        meek_options.path.clone()
    } else if net == "h2" {
        resident_stream_path(&vless.path)
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
