use super::*;
pub(crate) fn build_vmess_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        VMessLink::parse(&link).map_err(|err| format!("parse VMess node {node_tag}: {err}"))?;
    parsed
        .validate_aead()
        .map_err(|err| format!("validate VMess AEAD for {node_tag}: {err}"))?;
    parsed
        .validate_transport()
        .map_err(|err| format!("validate VMess transport for {node_tag}: {err}"))?;
    let body_security = parsed
        .body_security()
        .map_err(|err| format!("validate VMess body security for {node_tag}: {err}"))?;
    let net = match (parsed.net.as_str(), parsed.r#type.as_str()) {
        ("" | "tcp", "" | "none") => "tcp".to_owned(),
        ("" | "tcp", "http") => "tcp-http-header".to_owned(),
        ("" | "tcp", other) => {
            return Err(format!(
                "resident dataplane VMess TCP handler does not admit header type {other} for node {node_tag}"
            ));
        }
        ("ws" | "websocket", _) => "websocket".to_owned(),
        ("http" | "h2", _) => "h2".to_owned(),
        ("httpupgrade", _) => "httpupgrade".to_owned(),
        ("grpc", _) => "grpc".to_owned(),
        (other, _) => other.to_owned(),
    };
    match net.as_str() {
        "tcp" | "tcp-http-header" | "websocket" | "httpupgrade" | "grpc" | "h2" => {}
        other => {
            return Err(format!(
                "resident dataplane generic AEAD TCP handler admits only VMess tcp, websocket, httpupgrade, grpc, and h2 endpoints for node {node_tag}; got {other}"
            ));
        }
    }
    if matches!(net.as_str(), "tcp" | "tcp-http-header")
        && !matches!(parsed.tls.as_str(), "" | "none" | "tls")
    {
        return Err(format!(
            "resident dataplane generic AEAD TCP handler admits plain or TLS VMess TCP endpoints for node {node_tag}; got tls={}",
            parsed.tls
        ));
    }
    if net == "websocket" && !matches!(parsed.tls.as_str(), "" | "none" | "tls") {
        return Err(format!(
            "resident dataplane VMess websocket handler admits only plain WebSocket or TLS WebSocket for node {node_tag}; got tls={}",
            parsed.tls
        ));
    }
    if net == "httpupgrade" && !matches!(parsed.tls.as_str(), "" | "none" | "tls") {
        return Err(format!(
            "resident dataplane VMess httpupgrade handler admits only plain HTTP Upgrade or TLS HTTP Upgrade for node {node_tag}; got tls={}",
            parsed.tls
        ));
    }
    if net == "grpc" && !matches!(parsed.tls.as_str(), "" | "none" | "tls") {
        return Err(format!(
            "resident dataplane VMess grpc handler admits plain h2c or TLS HTTP/2 endpoints for node {node_tag}; got tls={}",
            if parsed.tls.is_empty() {
                "none"
            } else {
                parsed.tls.as_str()
            }
        ));
    }
    if net == "h2" && parsed.tls != "tls" {
        return Err(format!(
            "resident dataplane VMess h2 handler admits TLS HTTP/2 endpoints only for node {node_tag}; got tls={}",
            if parsed.tls.is_empty() {
                "none"
            } else {
                parsed.tls.as_str()
            }
        ));
    }
    let server_port = parsed.port.parse::<u16>().map_err(|err| {
        format!(
            "invalid VMess port {} for node {node_tag}: {err}",
            parsed.port
        )
    })?;
    let stream_host = if net == "grpc" && !parsed.grpc_authority.is_empty() {
        parsed.grpc_authority.clone()
    } else if matches!(
        net.as_str(),
        "tcp-http-header" | "websocket" | "httpupgrade" | "grpc" | "h2"
    ) {
        resident_stream_host(&parsed.host, &parsed.add)
    } else {
        String::new()
    };
    let stream_path = if net == "grpc" {
        resident_grpc_service_name(&parsed.path)
    } else if matches!(
        net.as_str(),
        "tcp-http-header" | "h2" | "websocket" | "httpupgrade"
    ) {
        resident_stream_path(&parsed.path)
    } else {
        String::new()
    };
    let tls = if net == "h2"
        || (matches!(
            net.as_str(),
            "tcp" | "tcp-http-header" | "websocket" | "httpupgrade" | "grpc"
        ) && parsed.tls == "tls")
    {
        "tls"
    } else {
        "none"
    };
    if parsed.ech.is_some() && tls != "tls" {
        return Err(format!(
            "resident dataplane ECH requires TLS for VMess node {node_tag}"
        ));
    }
    let server_name = if tls == "tls" {
        if net == "websocket" {
            resident_websocket_tls_server_name(&parsed.sni, &parsed.host, &parsed.add)
        } else if parsed.sni.is_empty() {
            parsed.add.clone()
        } else {
            parsed.sni.clone()
        }
    } else {
        String::new()
    };
    let utls_fingerprint = if tls == "tls" {
        resident_utls_fingerprint_plan_for_boundary(
            config,
            Some(parsed.fingerprint.as_str()),
            matches!(net.as_str(), "tcp" | "tcp-http-header"),
        )?
    } else {
        None
    };
    let alpn = if tls == "tls" {
        resident_raw_tls_alpn(
            split_alpn(&parsed.alpn),
            net.as_str(),
            utls_fingerprint.as_ref(),
        )
    } else {
        Vec::new()
    };
    if tls == "tls" {
        validate_resident_h2_carrier_alpn(&alpn, &net, &node_tag)?;
    }
    let allow_insecure = tls == "tls" && (parsed.allow_insecure || config.global.allow_insecure);
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "vmess",
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.add,
        server_port,
        server_name,
        alpn,
        flow: String::new(),
        net,
        stream_host,
        stream_path,
        grpc_mode: parsed.grpc_mode,
        xhttp_download: None,
        xhttp_mode: ResidentXhttpMode::PacketUp,
        xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
        xhttp_xmux: None,
        tls: tls.to_owned(),
        allow_insecure,
        tls_fragment: if tls == "tls" {
            resident_tls_fragment_plan(config)?
        } else {
            None
        },
        utls_fingerprint,
        ech: parsed.ech.map(ResidentEchPlan::new),
        reality: None,
        handler: ResidentProxyProtocolPlan::VmessAeadTcp {
            id: parsed.id,
            body_security,
        },
        execution: None,
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}
