use super::*;
pub(crate) fn build_trojan_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        TrojanLink::parse(&link).map_err(|err| format!("parse Trojan node {node_tag}: {err}"))?;
    let transport_kind = parsed.transport_kind();
    let websocket = parsed.protocol == "trojan-go" && transport_kind == TrojanTransportType::Ws;
    let httpupgrade =
        parsed.protocol == "trojan-go" && transport_kind == TrojanTransportType::HttpUpgrade;
    let grpc = parsed.protocol == "trojan-go" && transport_kind == TrojanTransportType::Grpc;
    let plain = parsed.protocol == "trojan" && transport_kind == TrojanTransportType::None;
    if !plain && !websocket && !httpupgrade && !grpc {
        return Err(format!(
            "resident dataplane generic TLS/TCP handler admits only plain trojan, trojan-go websocket, trojan-go httpupgrade, and trojan-go grpc endpoints for node {node_tag}; transport={} protocol={}",
            parsed.transport_type, parsed.protocol
        ));
    }
    let inner_shadowsocks = parse_trojan_go_inner_shadowsocks(&parsed.encryption, &node_tag)?;
    if inner_shadowsocks.is_some() && !websocket {
        return Err(format!(
            "resident dataplane trojan inner Shadowsocks layer admits WebSocket transport only for node {node_tag}; resident shape remains fail-closed for this config"
        ));
    }
    if parsed.allow_insecure || config.global.allow_insecure {
        return Err(
            "resident dataplane generic TLS/TCP handler does not admit allow_insecure; resident shape remains fail-closed for this config"
                .to_owned(),
        );
    }
    let utls_fingerprint = resident_utls_fingerprint_plan(config, None)?;
    let net = if websocket {
        "websocket"
    } else if httpupgrade {
        "httpupgrade"
    } else if grpc {
        "grpc"
    } else {
        "tcp"
    }
    .to_owned();
    let stream_host = if websocket || httpupgrade || grpc {
        resident_stream_host(&parsed.host, &parsed.sni)
    } else {
        String::new()
    };
    let stream_path = if grpc {
        resident_grpc_service_name(&parsed.service_name)
    } else if websocket || httpupgrade {
        resident_stream_path(&parsed.path)
    } else {
        String::new()
    };
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "trojan".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name: parsed.sni,
        alpn: if grpc {
            vec!["h2".to_owned()]
        } else {
            Vec::new()
        },
        flow: String::new(),
        net,
        stream_host,
        stream_path,
        tls: "tls".to_owned(),
        allow_insecure: false,
        utls_fingerprint,
        handler: if let Some((inner_cipher, inner_password)) = inner_shadowsocks {
            ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls {
                password: parsed.password,
                inner_cipher,
                inner_password,
            }
        } else {
            ResidentProxyProtocolPlan::TrojanTcpTls {
                password: parsed.password,
            }
        },
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

pub(crate) fn parse_trojan_go_inner_shadowsocks(
    encryption: &str,
    node_tag: &str,
) -> Result<Option<(String, String)>, String> {
    if encryption.is_empty() {
        return Ok(None);
    }
    let mut fields = encryption.split(';');
    let Some(kind) = fields.next() else {
        return Ok(None);
    };
    if kind != "ss" {
        return Err(format!(
            "resident dataplane trojan inner encryption admits Shadowsocks only for node {node_tag}; got {kind}"
        ));
    }
    let Some(cipher_or_pair) = fields.next() else {
        return Err(format!(
            "resident dataplane trojan inner Shadowsocks encryption requires cipher for node {node_tag}"
        ));
    };
    let (cipher, password) = if let Some((cipher, password)) = cipher_or_pair.split_once(':') {
        (cipher.to_owned(), password.to_owned())
    } else {
        let Some(password) = fields.next() else {
            return Err(format!(
                "resident dataplane trojan inner Shadowsocks encryption requires password for node {node_tag}"
            ));
        };
        (cipher_or_pair.to_owned(), password.to_owned())
    };
    let spec = cipher_spec(&cipher).map_err(|err| {
        format!("admit Trojan-Go inner Shadowsocks cipher for node {node_tag}: {err}")
    })?;
    if password.is_empty() {
        return Err(format!(
            "resident dataplane trojan inner Shadowsocks encryption requires non-empty password for node {node_tag}"
        ));
    }
    Ok(Some((spec.cipher.to_owned(), password)))
}
