use super::*;

fn config(global: bool) -> Config {
    parse_config(&format!(
        "global {{\nlan_interface: daerust0\nallow_insecure: {global}\nso_mark_from_dae: 1234\nmptcp: false\n}}\nrouting {{\nfallback: direct\n}}"
    ))
}

fn assert_policy(global: bool, expected: bool, raw: String) {
    let proxy = build_resident_proxy_plan_for_node(
        &config(global),
        "proxy".to_owned(),
        "tls-override".to_owned(),
        raw.clone(),
    )
    .unwrap();
    assert_eq!(
        proxy.allow_insecure, expected,
        "global={global}, link={raw}"
    );
    if let ResidentProxyProtocolPlan::TuicQuicTcp { allow_insecure, .. } = &proxy.handler {
        assert_eq!(*allow_insecure, expected, "global={global}, link={raw}");
    }
}

#[test]
fn every_tls_protocol_preserves_node_overrides_through_link_export() {
    for global in [false, true] {
        for node in [None, Some(false), Some(true)] {
            let expected = node.unwrap_or(global);
            for (scheme, key) in [
                ("https", "allowInsecure"),
                ("trojan", "allowInsecure"),
                ("trojan-go", "allow_insecure"),
                ("anytls", "insecure"),
                ("hysteria2", "insecure"),
                ("tuic", "allow_insecure"),
                ("juicity", "allow_insecure"),
                ("vless", "allowInsecure"),
            ] {
                let query = node
                    .map(|value| format!("&{key}={}", u8::from(value)))
                    .unwrap_or_default();
                let raw = format!(
                    "{scheme}://{}:secret@example.com:443?sni=example.com{query}",
                    fixture_client_id()
                );
                let raw = if scheme == "vless" {
                    format!(
                        "vless://{}@example.com:443?security=tls&type=tcp{query}",
                        fixture_client_id()
                    )
                } else if scheme == "trojan-go" {
                    format!("{raw}&type=ws&path=%2F")
                } else {
                    raw
                };
                let exported = match scheme {
                    "https" => HttpProxyLink::parse(&raw).unwrap().export_url(),
                    "trojan" | "trojan-go" => TrojanLink::parse(&raw).unwrap().export_url(),
                    "anytls" => AnyTLSLink::parse(&raw).unwrap().export_url(),
                    "hysteria2" => Hysteria2Link::parse(&raw).unwrap().export_url(),
                    "tuic" => TuicLink::parse(&raw).unwrap().export_url(),
                    "juicity" => JuicityLink::parse(&raw).unwrap().export_url(),
                    "vless" => VLESSLink::parse(&raw).unwrap().export_url(),
                    _ => unreachable!(),
                };
                assert_policy(global, expected, raw);
                assert_policy(global, expected, exported);
            }
            let mut vmess = VMessLink::parse(&vmess_fixture_url(
                "",
                "example.com",
                443,
                "tcp",
                "",
                "",
                "tls",
            ))
            .unwrap();
            vmess.allow_insecure = node;
            let exported = vmess.export_url();
            assert_eq!(VMessLink::parse(&exported).unwrap().allow_insecure, node);
            assert_policy(global, expected, exported);
        }
    }
}

#[test]
fn supported_query_aliases_cannot_erase_an_explicit_secure_override() {
    for scheme in [
        "https",
        "trojan",
        "trojan-go",
        "anytls",
        "tuic",
        "juicity",
        "vless",
    ] {
        for key in dae_outbound_core::tls_options::ALLOW_INSECURE_ALIASES {
            let auth = if scheme == "vless" {
                fixture_client_id()
            } else {
                format!("{}:secret", fixture_client_id())
            };
            let extra = if scheme == "vless" {
                "&security=tls&type=tcp"
            } else if scheme == "trojan-go" {
                "&type=ws&path=%2F"
            } else {
                ""
            };
            let raw = format!("{scheme}://{auth}@example.com:443?{key}=false{extra}");
            assert_policy(true, false, raw);
        }
    }
}

#[test]
fn tuic_disable_sni_overrides_node_and_global_certificate_policy() {
    for global in [false, true] {
        for node in [None, Some(false), Some(true)] {
            for disable_sni in [false, true] {
                let query = node
                    .map(|value| format!("&insecure={}", u8::from(value)))
                    .unwrap_or_default();
                let raw = format!(
                    "tuic://{}:secret@example.com:443?disable_sni={}{query}",
                    fixture_client_id(),
                    u8::from(disable_sni),
                );
                let expected = disable_sni || node.unwrap_or(global);
                let exported = TuicLink::parse(&raw).unwrap().export_url();
                assert_policy(global, expected, raw);
                assert_policy(global, expected, exported);
            }
        }
    }
}

#[test]
fn xhttp_download_certificate_override_is_independent_of_global_and_primary() {
    for global in [false, true] {
        for node in [None, Some(false), Some(true)] {
            for primary in [false, true] {
                let mut extra = serde_json::json!({
                    "downloadSettings": {
                        "address": "download.example.com", "port": 443,
                        "network": "xhttp", "security": "tls",
                        "tlsSettings": {"serverName": "download.example.com", "alpn": ["h2"]},
                        "xhttpSettings": {"path": "/down", "mode": "packet-up"}
                    }
                });
                if let Some(node) = node {
                    extra["downloadSettings"]["tlsSettings"]["allowInsecure"] = node.into();
                }
                let raw = vless_xhttp_parser_fixture_url("packet-up", "h2", &extra.to_string());
                let mut link = VLESSLink::parse(&raw).unwrap();
                link.allow_insecure = Some(primary);
                let proxy = build_resident_proxy_plan_for_node(
                    &config(global),
                    "proxy".to_owned(),
                    "xhttp-tls-override".to_owned(),
                    link.export_url(),
                )
                .unwrap();
                assert_eq!(proxy.allow_insecure, primary);
                assert_eq!(
                    proxy.xhttp_download.unwrap().allow_insecure,
                    node.unwrap_or(global)
                );
            }
        }
    }
}

#[test]
fn xhttp_reality_download_preserves_explicit_false() {
    let reality = VLESSLink::parse(&vless_reality_fixture_url()).unwrap();
    for global in [false, true] {
        for node in [None, Some(false), Some(true)] {
            let mut extra = serde_json::json!({
                "downloadSettings": {
                    "address": "download.example.com", "port": 443,
                    "network": "xhttp", "security": "reality",
                    "realitySettings": {"serverName": "download.example.com", "alpn": ["h2"], "publicKey": reality.public_key, "shortId": reality.short_id},
                    "xhttpSettings": {"path": "/down", "mode": "packet-up"}
                }
            });
            if let Some(node) = node {
                extra["downloadSettings"]["realitySettings"]["allowInsecure"] = node.into();
            }
            let proxy = build_resident_proxy_plan_for_node(
                &config(global),
                "proxy".to_owned(),
                "xhttp-reality-override".to_owned(),
                vless_xhttp_parser_fixture_url("packet-up", "h2", &extra.to_string()),
            )
            .unwrap();
            assert_eq!(
                proxy.xhttp_download.unwrap().allow_insecure,
                node.unwrap_or(global)
            );
        }
    }
}
