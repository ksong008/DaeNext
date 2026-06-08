fn build_vless_proxy_plan(
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
    match net.as_str() {
        "tcp" if vless.flow != XTLS_RPRX_VISION => {
            return Err(format!(
                "resident dataplane vless native experiment admits tcp flow={XTLS_RPRX_VISION}, got '{}' for node {node_tag}; resident shape remains fail-closed for this config",
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
    if vless.tls != "tls" {
        return Err(format!(
            "resident dataplane vless handler currently supports security=tls only, got {} for node {node_tag}",
            vless.tls
        ));
    }
    if vless.allow_insecure || config.global.allow_insecure {
        return Err(
            "resident dataplane vless TLS handler does not admit allow_insecure; resident shape remains fail-closed for this config"
                .to_owned(),
        );
    }
    if net == "xhttp" {
        let mode = ir::normalize_xhttp_mode(&vless.xhttp_mode, "https", &vless.tls, false);
        if !mode.ok {
            return Err(format!(
                "resident dataplane vless xHTTP transport rejected mode for node {node_tag}: {}",
                mode.error_contains
            ));
        }
        if mode.normalized != "packet-up" {
            return Err(format!(
                "resident dataplane vless xHTTP transport admits packet-up mode only, got {} for node {node_tag}; resident shape remains fail-closed for this config",
                mode.normalized
            ));
        }
        let alpn_result = ir::validate_xhttp_alpn(&vless.tls, &vless.alpn);
        if !alpn_result.ok {
            return Err(format!(
                "resident dataplane vless xHTTP transport rejected ALPN for node {node_tag}: {}",
                alpn_result.error_contains
            ));
        }
        if alpn_result.use_h3 {
            return Err(format!(
                "resident dataplane vless xHTTP transport admits HTTP/2 packet-up only, got h3 for node {node_tag}; resident shape remains fail-closed for this config"
            ));
        }
        if !resident_xhttp_extra_is_empty(&vless.xhttp_extra) {
            return Err(format!(
                "resident dataplane vless xHTTP transport admits default extra settings only for node {node_tag}; resident shape remains fail-closed for this config"
            ));
        }
    }
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
    let utls_fingerprint = resident_utls_fingerprint_plan(config, Some(&vless.fingerprint))?;
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
        tls: vless.tls,
        allow_insecure: false,
        utls_fingerprint,
        handler: ResidentProxyProtocolPlan::VlessVisionTcpTls { key },
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}
