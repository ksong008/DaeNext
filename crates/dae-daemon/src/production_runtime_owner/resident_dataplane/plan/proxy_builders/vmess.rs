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
    let net = match parsed.net.as_str() {
        "" | "tcp" => "tcp".to_owned(),
        "ws" | "websocket" => "websocket".to_owned(),
        "http" | "h2" => "h2".to_owned(),
        "httpupgrade" => "httpupgrade".to_owned(),
        "grpc" => "grpc".to_owned(),
        other => other.to_owned(),
    };
    match net.as_str() {
        "tcp" | "websocket" | "httpupgrade" | "grpc" | "h2" => {}
        other => {
            return Err(format!(
                "resident dataplane generic AEAD TCP handler admits only VMess tcp, websocket, httpupgrade, grpc, and h2 endpoints for node {node_tag}; got {other}"
            ));
        }
    }
    if net == "tcp" && !matches!(parsed.tls.as_str(), "" | "none" | "tls") {
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
    if net == "grpc" && parsed.tls != "tls" {
        return Err(format!(
            "resident dataplane VMess grpc handler admits TLS HTTP/2 endpoints only for node {node_tag}; got tls={}",
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
    let stream_host = if matches!(net.as_str(), "websocket" | "httpupgrade" | "grpc" | "h2") {
        resident_stream_host(&parsed.host, &parsed.add)
    } else {
        String::new()
    };
    let stream_path = if net == "grpc" {
        resident_grpc_service_name(&parsed.path)
    } else if matches!(net.as_str(), "h2" | "websocket" | "httpupgrade") {
        resident_stream_path(&parsed.path)
    } else {
        String::new()
    };
    let tls = if (net == "tcp" && parsed.tls == "tls")
        || net == "grpc"
        || net == "h2"
        || (matches!(net.as_str(), "websocket" | "httpupgrade") && parsed.tls == "tls")
    {
        "tls"
    } else {
        "none"
    };
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
            net == "tcp",
        )?
    } else {
        None
    };
    let alpn = if matches!(net.as_str(), "grpc" | "h2") {
        vec!["h2".to_owned()]
    } else {
        Vec::new()
    };
    let allow_insecure = tls == "tls" && (parsed.allow_insecure || config.global.allow_insecure);
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "vmess".to_owned(),
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
        reality: None,
        handler: ResidentProxyProtocolPlan::VmessAeadTcp { id: parsed.id },
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}
