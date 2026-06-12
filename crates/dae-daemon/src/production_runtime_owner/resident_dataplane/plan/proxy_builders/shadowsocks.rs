use super::*;
pub(crate) fn build_shadowsocks_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed = ShadowsocksLink::parse(&link)
        .map_err(|err| format!("parse Shadowsocks node {node_tag}: {err}"))?;
    let plugin = parsed.plugin.clone();
    if !resident_shadowsocks_plugin_supported(&plugin.name, &plugin.opts.obfs, &plugin.opts.tls) {
        return Err(format!(
            "resident dataplane Shadowsocks plugin wrapper admits simple-obfs http/tls and v2ray-plugin tls websocket only for node {node_tag}; got {}",
            resident_shadowsocks_plugin_display(&plugin.name, &plugin.opts.obfs, &plugin.opts.tls)
        ));
    }
    let cipher_info = classify_cipher(&parsed.cipher)
        .map_err(|err| format!("admit Shadowsocks cipher for node {node_tag}: {err}"))?;
    let (net, stream_host, stream_path, tls, handler) = match cipher_info.family {
        CipherFamily::Aead => {
            let spec = cipher_spec(&parsed.cipher)
                .map_err(|err| format!("admit Shadowsocks cipher for node {node_tag}: {err}"))?;
            if plugin.name == "simple-obfs" {
                let stream_host = if plugin.opts.host.is_empty() {
                    parsed.server.clone()
                } else {
                    plugin.opts.host.clone()
                };
                if plugin.opts.obfs == "tls" {
                    (
                        "simple-obfs-tls".to_owned(),
                        stream_host.clone(),
                        String::new(),
                        "aead".to_owned(),
                        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp {
                            cipher: spec.cipher.to_owned(),
                            password: parsed.password.clone(),
                            salt_len: spec.salt_len,
                            host: stream_host,
                        },
                    )
                } else {
                    let stream_path = if plugin.opts.path.is_empty() {
                        "/".to_owned()
                    } else {
                        plugin.opts.path.clone()
                    };
                    (
                        "simple-obfs-http".to_owned(),
                        stream_host.clone(),
                        stream_path.clone(),
                        "aead".to_owned(),
                        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp {
                            cipher: spec.cipher.to_owned(),
                            password: parsed.password.clone(),
                            salt_len: spec.salt_len,
                            host: stream_host,
                            path: stream_path,
                        },
                    )
                }
            } else if plugin.name == "v2ray-plugin" {
                let stream_host = if plugin.opts.host.is_empty() {
                    parsed.server.clone()
                } else {
                    plugin.opts.host.clone()
                };
                let stream_path = if plugin.opts.path.is_empty() {
                    "/".to_owned()
                } else {
                    plugin.opts.path.clone()
                };
                (
                    "v2ray-plugin-tls-websocket".to_owned(),
                    stream_host.clone(),
                    stream_path.clone(),
                    "tls".to_owned(),
                    ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp {
                        cipher: spec.cipher.to_owned(),
                        password: parsed.password.clone(),
                        salt_len: spec.salt_len,
                        host: stream_host,
                        path: stream_path,
                    },
                )
            } else {
                (
                    "tcp".to_owned(),
                    String::new(),
                    String::new(),
                    "aead".to_owned(),
                    ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
                        cipher: spec.cipher.to_owned(),
                        password: parsed.password.clone(),
                        salt_len: spec.salt_len,
                    },
                )
            }
        }
        CipherFamily::Aead2022 => {
            if !plugin.name.is_empty() {
                if !(plugin.name == "simple-obfs"
                    && plugin.opts.obfs == "http"
                    && plugin.opts.tls.is_empty())
                {
                    return Err(format!(
                        "resident dataplane Shadowsocks 2022 plugin wrapper admits simple-obfs http only for node {node_tag}; got {}",
                        resident_shadowsocks_plugin_display(
                            &plugin.name,
                            &plugin.opts.obfs,
                            &plugin.opts.tls
                        )
                    ));
                }
            }
            validate_psk_list(&cipher_info.cipher, &parsed.password)
                .map_err(|err| format!("admit Shadowsocks 2022 PSK for node {node_tag}: {err}"))?;
            let conf = cipher_conf(&cipher_info.cipher).ok_or_else(|| {
                format!(
                    "admit Shadowsocks 2022 cipher for node {node_tag}: unsupported shadowsocks 2022 cipher: {}",
                    cipher_info.cipher
                )
            })?;
            if plugin.name == "simple-obfs" {
                let stream_host = if plugin.opts.host.is_empty() {
                    parsed.server.clone()
                } else {
                    plugin.opts.host.clone()
                };
                let stream_path = if plugin.opts.path.is_empty() {
                    "/".to_owned()
                } else {
                    plugin.opts.path.clone()
                };
                (
                    "simple-obfs-http".to_owned(),
                    stream_host.clone(),
                    stream_path.clone(),
                    "aead-2022".to_owned(),
                    ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp {
                        cipher: conf.cipher.to_owned(),
                        password: parsed.password.clone(),
                        salt_len: conf.salt_len,
                        host: stream_host,
                        path: stream_path,
                    },
                )
            } else {
                (
                    "tcp".to_owned(),
                    String::new(),
                    String::new(),
                    "aead-2022".to_owned(),
                    ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
                        cipher: conf.cipher.to_owned(),
                        password: parsed.password.clone(),
                        salt_len: conf.salt_len,
                        packet_nonce_len: conf.packet_nonce_len,
                    },
                )
            }
        }
        CipherFamily::Stream => {
            return Err(format!(
                "admit Shadowsocks cipher for node {node_tag}: cipher family is not resident Shadowsocks packet-capable cipher: {}",
                cipher_info.cipher
            ));
        }
    };
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "shadowsocks".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name: if tls == "tls" {
            stream_host.clone()
        } else {
            String::new()
        },
        alpn: if tls == "tls" {
            vec!["http/1.1".to_owned()]
        } else {
            Vec::new()
        },
        flow: String::new(),
        net,
        stream_host,
        stream_path,
        xhttp_download: None,
        tls: tls.clone(),
        allow_insecure: false,
        tls_fragment: if tls == "tls" {
            resident_tls_fragment_plan(config)?
        } else {
            None
        },
        utls_fingerprint: None,
        reality: None,
        handler,
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

pub(crate) fn resident_shadowsocks_plugin_supported(name: &str, obfs: &str, tls: &str) -> bool {
    name.is_empty()
        || (name == "simple-obfs" && matches!(obfs, "http" | "tls") && tls.is_empty())
        || (name == "v2ray-plugin" && obfs.is_empty() && tls == "tls")
}

pub(crate) fn resident_shadowsocks_plugin_display(name: &str, obfs: &str, tls: &str) -> String {
    if name.is_empty() {
        return "none".to_owned();
    }
    let mut fields = vec![name.to_owned()];
    if !obfs.is_empty() {
        fields.push(format!("obfs={obfs}"));
    }
    if !tls.is_empty() {
        fields.push("tls".to_owned());
    }
    fields.join(";")
}
