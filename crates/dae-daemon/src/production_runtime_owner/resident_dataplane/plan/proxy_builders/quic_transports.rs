use super::*;
pub(crate) fn build_tuic_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        TuicLink::parse(&link).map_err(|err| format!("parse TUIC node {node_tag}: {err}"))?;
    parsed
        .validate_uuid()
        .map_err(|err| format!("validate TUIC UUID for {node_tag}: {err}"))?;
    if parsed.password.is_empty() {
        return Err(format!(
            "resident dataplane generic QUIC handler requires TUIC password for node {node_tag}; resident shape remains fail-closed for this config"
        ));
    }
    let server_name = if parsed.sni.is_empty() {
        parsed.server.clone()
    } else {
        parsed.sni.clone()
    };
    let alpn = if parsed.alpn.is_empty() {
        vec!["h3".to_owned()]
    } else {
        parsed.alpn.clone()
    };
    let allow_insecure =
        parsed.allow_insecure || config.global.allow_insecure || parsed.disable_sni;
    let congestion =
        dae_outbound::tuic::TuicCongestionController::from_config(&parsed.congestion_control)
            .map_err(|err| format!("validate TUIC congestion controller for {node_tag}: {err}"))?;
    let udp_relay_mode = dae_outbound::tuic::TuicUdpRelayMode::from_config(&parsed.udp_relay_mode)
        .map_err(|err| format!("validate TUIC UDP relay mode for {node_tag}: {err}"))?;
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "tuic",
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name,
        alpn: alpn.clone(),
        flow: String::new(),
        net: "udp".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        xhttp_download: None,
        xhttp_mode: ResidentXhttpMode::PacketUp,
        xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
        xhttp_xmux: None,
        tls: "quic".to_owned(),
        allow_insecure,
        tls_fragment: None,
        utls_fingerprint: None,
        reality: None,
        handler: ResidentProxyProtocolPlan::TuicQuicTcp {
            uuid: parsed.user,
            password: parsed.password,
            alpn,
            allow_insecure,
            congestion,
            udp_relay_mode,
        },
        execution: None,
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

pub(crate) fn build_hysteria2_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed = Hysteria2Link::parse(&link)
        .map_err(|err| format!("parse Hysteria2 node {node_tag}: {err}"))?;
    let auth = if parsed.password.is_empty() {
        parsed.user.clone()
    } else {
        format!("{}:{}", parsed.user, parsed.password)
    };
    if auth.is_empty() {
        return Err(format!(
            "resident dataplane generic QUIC handler requires Hysteria2 auth for node {node_tag}; resident shape remains fail-closed for this config"
        ));
    }
    let obfs = resident_hysteria2_obfs_plan(&parsed.obfs, &parsed.obfs_password, &node_tag)?;
    let server = hysteria2_server_contract(&parsed.server);
    let port_hop_interval = if server.port_hopping {
        let nanos = u64::try_from(config.global.udphop_interval.as_nanos()).map_err(|_| {
            format!("Hysteria2 port hopping interval is negative for node {node_tag}")
        })?;
        Duration::from_nanos(nanos)
    } else {
        Duration::ZERO
    };
    let (server_port, port_hop_ports) = if server.port_hopping {
        if port_hop_interval < HYSTERIA2_MIN_PORT_HOP_INTERVAL {
            return Err(format!(
                "Hysteria2 port hopping interval for node {node_tag} must be at least {} ms",
                HYSTERIA2_MIN_PORT_HOP_INTERVAL.as_millis()
            ));
        }
        let interval_ms = u64::try_from(port_hop_interval.as_millis()).map_err(|_| {
            format!("Hysteria2 port hopping interval is too large for node {node_tag}")
        })?;
        let schedule = build_port_hop_schedule(&parsed.server, interval_ms, 1)
            .map_err(|err| format!("admit Hysteria2 port hopping for node {node_tag}: {err}"))?;
        let server_port = *schedule.selected_ports.first().ok_or_else(|| {
            format!("admit Hysteria2 port hopping for node {node_tag}: no selected port")
        })?;
        (server_port, schedule.normalized_ports)
    } else {
        let server_port = server.port.parse::<u16>().map_err(|err| {
            format!(
                "invalid Hysteria2 port {} for node {node_tag}: {err}",
                server.port
            )
        })?;
        (server_port, Vec::new())
    };
    let server_name = hysteria2_tls_server_name(&parsed.sni, &server.host);
    let tls_identity = dae_outbound::hysteria2::Hysteria2TlsIdentity::from_node_and_global(
        server_name.clone(),
        parsed.insecure,
        config.global.allow_insecure,
        &parsed.pin_sha256,
    )
    .map_err(|err| format!("build Hysteria2 TLS policy for node {node_tag}: {err}"))?;
    let global_max_tx = parse_hysteria2_bandwidth(&config.global.bandwidth_max_tx)
        .map_err(|err| format!("parse Hysteria2 MaxTx for node {node_tag}: {err}"))?;
    let global_max_rx = parse_hysteria2_bandwidth(&config.global.bandwidth_max_rx)
        .map_err(|err| format!("parse Hysteria2 MaxRx for node {node_tag}: {err}"))?;
    let max_tx = if parsed.max_tx_configured {
        parsed.max_tx
    } else {
        global_max_tx
    };
    let max_rx = if parsed.max_rx_configured {
        parsed.max_rx
    } else {
        global_max_rx
    };
    let congestion = parsed
        .congestion
        .validate_quinn()
        .map_err(|err| format!("admit Hysteria2 congestion for node {node_tag}: {err}"))?;
    let allow_insecure = tls_identity.policy().allow_insecure();
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "hysteria2",
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: server.host,
        server_port,
        server_name,
        alpn: vec!["h3".to_owned()],
        flow: String::new(),
        net: "udp".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        xhttp_download: None,
        xhttp_mode: ResidentXhttpMode::PacketUp,
        xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
        xhttp_xmux: None,
        tls: "quic".to_owned(),
        allow_insecure,
        tls_fragment: None,
        utls_fingerprint: None,
        reality: None,
        handler: ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            auth,
            tls_identity,
            max_tx,
            max_rx,
            congestion,
            obfs,
            port_hop_ports,
            port_hop_interval,
        },
        execution: None,
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn hysteria2_tls_server_name(explicit_sni: &str, authority_host: &str) -> String {
    if !explicit_sni.is_empty() {
        return explicit_sni.to_owned();
    }
    authority_host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .filter(|host| host.parse::<std::net::Ipv6Addr>().is_ok())
        .unwrap_or(authority_host)
        .to_owned()
}

fn resident_hysteria2_obfs_plan(
    mode: &str,
    password: &str,
    node_tag: &str,
) -> Result<ResidentHysteria2ObfsPlan, String> {
    let mode = mode.trim().to_ascii_lowercase();
    if mode.is_empty() {
        if !password.is_empty() {
            return Err(format!(
                "resident dataplane Hysteria2 obfs-password requires obfs=salamander for node {node_tag}; resident shape remains fail-closed for this config"
            ));
        }
        return Ok(ResidentHysteria2ObfsPlan::none());
    }
    if mode != "salamander" {
        return Err(format!(
            "resident dataplane Hysteria2 obfs admits official salamander only for node {node_tag}"
        ));
    }
    if password.is_empty() {
        return Err(format!(
            "resident dataplane Hysteria2 salamander obfs requires obfs-password for node {node_tag}; resident shape remains fail-closed for this config"
        ));
    }
    Ok(ResidentHysteria2ObfsPlan::salamander(password.to_owned()))
}

pub(crate) fn build_juicity_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        JuicityLink::parse(&link).map_err(|err| format!("parse Juicity node {node_tag}: {err}"))?;
    parsed
        .validate_uuid()
        .map_err(|err| format!("validate Juicity UUID for {node_tag}: {err}"))?;
    if parsed.password.is_empty() {
        return Err(format!(
            "resident dataplane generic QUIC handler requires Juicity password for node {node_tag}; resident shape remains fail-closed for this config"
        ));
    }
    let allow_insecure = parsed.allow_insecure || config.global.allow_insecure;
    let server_name = if parsed.sni.is_empty() {
        parsed.server.clone()
    } else {
        parsed.sni.clone()
    };
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "juicity",
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name,
        alpn: vec!["h3".to_owned()],
        flow: String::new(),
        net: "udp".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        xhttp_download: None,
        xhttp_mode: ResidentXhttpMode::PacketUp,
        xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
        xhttp_xmux: None,
        tls: "quic".to_owned(),
        allow_insecure,
        tls_fragment: None,
        utls_fingerprint: None,
        reality: None,
        handler: ResidentProxyProtocolPlan::JuicityQuicTcp {
            uuid: parsed.user,
            password: parsed.password,
            allow_insecure,
            pinned_certchain_sha256: parsed.pinned_certchain_sha256,
        },
        execution: None,
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}
