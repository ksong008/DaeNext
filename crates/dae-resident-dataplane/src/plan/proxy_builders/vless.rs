use super::*;

mod xhttp;
use self::xhttp::{
    ResidentXhttpExtraPlan, resident_xhttp_extra_plan, resident_xhttp_mode_from_normalized,
    validate_resident_xhttp_primary_alpn, validate_resident_xhttp_primary_quic_tls_features,
    validate_resident_xhttp_settings_for_mode,
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
    let encryption = VlessEncryptionClient::parse(&vless.encryption)
        .map_err(|err| format!("parse VLESS encryption for {node_tag}: {err}"))?;
    if encryption.is_some() && matches!(net.as_str(), "h2" | "meek") {
        return Err(format!(
            "resident dataplane keeps VLESS Encryption with legacy H2 and Meek policy-closed for node {node_tag}; neither is an admitted current-Xray transport"
        ));
    }
    let vision = is_xtls_rprx_vision_flow(&vless.flow);
    let encrypted_wrapper = encryption.is_some()
        && matches!(net.as_str(), "grpc" | "websocket" | "httpupgrade" | "xhttp");
    if vless.mux
        && !matches!(net.as_str(), "tcp" | "xdrive")
        && !(encrypted_wrapper && (vision || net == "xhttp"))
    {
        return Err(format!(
            "resident dataplane vless mux requires TCP or encrypted XHTTP, or an encrypted Vision carrier for node {node_tag}; got {net}"
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
            if !vless.flow.is_empty() && !encrypted_wrapper =>
        {
            return Err(format!(
                "resident dataplane vless wrapped-stream handler admits only empty flow, got '{}' for node {node_tag}; resident shape remains fail-closed for this config",
                vless.flow
            ));
        }
        "tcp" | "websocket" | "httpupgrade" | "grpc" | "h2" | "xhttp" | "meek" | "hysteria"
        | "mkcp" | "xdrive" => {}
        other => {
            return Err(format!(
                "unsupported resident VLESS transport {other} for node {node_tag}"
            ));
        }
    }
    if !matches!(vless.tls.as_str(), "none" | "tls" | "reality") {
        return Err(format!(
            "resident dataplane vless handler currently supports security=none, security=tls, or security=reality only, got {} for node {node_tag}",
            vless.tls
        ));
    }
    if vless.ech.is_some() && vless.tls != "tls" {
        return Err(format!(
            "resident dataplane ECH requires security=tls for VLESS node {node_tag}"
        ));
    }
    let encrypted_vision = encryption.is_some() && (net == "tcp" || encrypted_wrapper);
    if vless.tls == "none"
        && ((!encrypted_wrapper && !matches!(net.as_str(), "tcp" | "mkcp" | "xdrive"))
            || (vless.mux && encryption.is_none())
            || (!vless.flow.is_empty() && !encrypted_vision))
    {
        return Err(format!(
            "resident dataplane vless security=none requires native tcp or encrypted WS, HTTPUpgrade, gRPC, or xHTTP, and Vision and mux require Encryption for node {node_tag}; got net={net}, mux={}, flow='{}'",
            vless.mux, vless.flow
        ));
    }
    if net == "h2" && vless.tls != "tls" {
        return Err(format!(
            "resident dataplane vless h2 transport admits standard tls underlay only for node {node_tag}; got {}",
            vless.tls
        ));
    }
    let requested_allow_insecure = vless.allow_insecure.unwrap_or(config.global.allow_insecure);
    if net == "xdrive"
        && (vless.tls != "none"
            || !vless.flow.is_empty()
            || encryption.is_none()
            || !vless.mux
            || !vless.mux_options.tcp_enabled()
            || !vless.mux_options.xudp_enabled(true)
            || vless.mux_options.udp443
                == Some(dae_outbound_core::vless::mux::VlessUdp443Policy::Skip)
            || !std::path::Path::new(&vless.path).is_absolute())
    {
        return Err(format!(
            "VLESS XDrive local requires an absolute remoteFolder, security=none, Encryption, empty flow and TCP/XUDP mux for node {node_tag}"
        ));
    }
    let xhttp_primary_http_version = (net == "xhttp").then(|| {
        if vless.tls == "none" {
            return ResidentXhttpHttpVersion::H1;
        }
        let alpn = if vless.alpn.trim().is_empty() {
            Vec::new()
        } else {
            split_alpn(&vless.alpn)
        };
        ResidentXhttpHttpVersion::from_tls_alpn(&alpn)
    });
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
    let ech = vless.ech.clone().map(ResidentEchPlan::new);
    let allow_insecure = requested_allow_insecure;
    let tls_fragment =
        if vless.tls == "tls" && xhttp_primary_http_version != Some(ResidentXhttpHttpVersion::H3) {
            resident_tls_fragment_plan(config)?
        } else {
            None
        };
    let utls_fingerprint = match vless.tls.as_str() {
        "tls" => resident_utls_fingerprint_plan_for_boundary(
            config,
            Some(&vless.fingerprint),
            net == "tcp",
        )?,
        "reality" => resident_reality_utls_fingerprint_plan(&vless.fingerprint)?,
        _ => None,
    };
    if net == "mkcp"
        && (!matches!(vless.tls.as_str(), "none" | "tls")
            || !vless.flow.is_empty()
            || encryption.is_none()
            || vless.r#type != "none"
            || !vless.path.is_empty()
            || vless.ech.is_some()
            || utls_fingerprint.is_some()
            || tls_fragment.is_some())
    {
        return Err(format!(
            "VLESS mKCP requires Encryption, empty flow, default unmasked mKCP and optional standard TLS for node {node_tag}"
        ));
    }
    if let Some(http_version) = xhttp_primary_http_version {
        validate_resident_xhttp_primary_quic_tls_features(
            http_version,
            utls_fingerprint.as_ref(),
            &node_tag,
        )?;
    }
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
    let vless_hysteria = if net == "hysteria" {
        if vless.tls != "tls"
            || !vless.flow.is_empty()
            || encryption.is_none()
            || vless.hysteria_auth.is_empty()
            || vless.ech.is_some()
            || utls_fingerprint.is_some()
            || tls_fragment.is_some()
            || (!vless.alpn.is_empty() && vless.alpn != "h3")
        {
            return Err(format!(
                "VLESS Hysteria requires auth, TLS with H3, Encryption, and empty flow for node {node_tag}"
            ));
        }
        let tls = dae_outbound_core::hysteria2::Hysteria2TlsIdentity::from_node_and_global(
            server_name.clone(),
            vless.allow_insecure,
            config.global.allow_insecure,
            "",
        )
        .map_err(|error| format!("VLESS Hysteria TLS for node {node_tag}: {error}"))?;
        Some(ResidentVlessHysteriaPlan {
            auth: vless.hysteria_auth.clone(),
            tls,
        })
    } else {
        None
    };
    let xhttp_extra = if net == "xhttp" {
        resident_xhttp_extra_plan(
            &vless.xhttp_extra,
            &server_name,
            reality.as_ref(),
            utls_fingerprint.as_ref(),
            config.global.allow_insecure,
            &node_tag,
        )?
    } else {
        ResidentXhttpExtraPlan::default()
    };
    let xhttp_mode = if net == "xhttp" {
        let mode = ir::normalize_xhttp_mode(
            &vless.xhttp_mode,
            if vless.tls == "none" { "http" } else { "https" },
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
        if vless.tls != "none" {
            validate_resident_xhttp_primary_alpn(&vless.alpn, &vless.tls, &node_tag)?;
        }
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
    let alpn = resident_vless_alpn(&vless, &net, utls_fingerprint.as_ref());
    validate_resident_h2_carrier_alpn(&alpn, &net, &node_tag)?;
    validate_resident_meek_carrier_alpn(&alpn, &net, &node_tag)?;
    let stream_host = if net == "grpc" && !vless.grpc_authority.is_empty() {
        vless.grpc_authority.clone()
    } else if let Some(meek_options) = &meek_options {
        meek_options.host.clone()
    } else if matches!(
        net.as_str(),
        "websocket" | "httpupgrade" | "grpc" | "h2" | "xhttp"
    ) {
        resident_stream_host(&vless.host, &server_name)
    } else {
        String::new()
    };
    let stream_path = if net == "xdrive" || net == "grpc" {
        resident_grpc_service_name(&vless.path)
    } else if let Some(meek_options) = &meek_options {
        meek_options.path.clone()
    } else if net == "h2" {
        resident_stream_path(&vless.path)
    } else if net == "xhttp" {
        resident_xhttp_stream_path(&vless.path, &xhttp_extra.settings)
    } else if matches!(net.as_str(), "websocket" | "httpupgrade") {
        resident_stream_path(&vless.path)
    } else {
        String::new()
    };
    let graph = resident_graph_identity(&link);
    // Vision uses standalone TCP and XUDP. The mux option cannot send a TCP
    // substream under a Vision request.
    let tcp_mux = matches!(net.as_str(), "tcp" | "xdrive") && vless.mux_options.tcp_enabled();
    let handler = if vless.mux && !vision && (tcp_mux || vless.mux_options.xudp_enabled(tcp_mux)) {
        ResidentProxyProtocolPlan::VlessMuxTcpTls { key, encryption }
    } else {
        ResidentProxyProtocolPlan::VlessVisionTcpTls { key, encryption }
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
        protocol: "vless",
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
        grpc_mode: vless.grpc_mode,
        xhttp_download: xhttp_extra.download,
        xhttp_mode,
        xhttp_settings: xhttp_extra.settings,
        xhttp_xmux,
        vless_mux: vless.mux.then_some(vless.mux_options),
        vless_hysteria,
        tls: vless.tls,
        allow_insecure,
        tls_fragment,
        utls_fingerprint,
        ech,
        reality,
        handler,
        execution: None,
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn resident_reality_underlay_plan(
    vless: &VLESSLink,
) -> Result<Option<ResidentRealityUnderlayPlan>, String> {
    if vless.tls != "reality" {
        if vless.mldsa65_verify.is_some() {
            return Err("Reality pqv requires security=reality".to_owned());
        }
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
        mldsa65_verify: vless.mldsa65_verify.clone(),
    }))
}

fn resident_reality_utls_fingerprint_plan(
    link_fingerprint: &str,
) -> Result<Option<ResidentUtlsFingerprintPlan>, String> {
    let link_fingerprint = link_fingerprint.trim();
    if link_fingerprint.is_empty() || link_fingerprint.eq_ignore_ascii_case("unsafe") {
        return Ok(None);
    }
    resolve_optional_resident_utls_fingerprint("link fp", link_fingerprint)
}

fn resident_vless_alpn(
    vless: &VLESSLink,
    net: &str,
    fingerprint: Option<&ResidentUtlsFingerprintPlan>,
) -> Vec<String> {
    if net == "xhttp" && vless.tls == "none" {
        return Vec::new();
    }
    resident_raw_tls_alpn(split_alpn(&vless.alpn), net, fingerprint)
}
