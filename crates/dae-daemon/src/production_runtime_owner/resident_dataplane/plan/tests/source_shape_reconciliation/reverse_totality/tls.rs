use super::*;
use dae_outbound::{TrojanLink, VLESSLink, VMessLink};

#[test]
fn vless_native_and_wrapped_tls_variants_have_exact_production_dispositions() {
    let primary = fixture_host(FixtureEndpoint::Primary);
    let authority = fixture_host(FixtureEndpoint::Authority);
    for profile in TlsProfile::ALL {
        let mut native = VLESSLink::parse(&vless_vision_without_flow_fixture_url(
            profile.link_fingerprint(),
        ))
        .unwrap();
        native.allow_insecure = profile.allow_insecure();
        assert_exact_tls_source(native.export_url(), profile, &["vless-native-tcp-endpoint"]);

        let mut vision =
            VLESSLink::parse(&vless_vision_fixture_url(profile.link_fingerprint())).unwrap();
        vision.allow_insecure = profile.allow_insecure();
        assert_exact_tls_source(
            vision.export_url(),
            profile,
            &["baseline-tls-vision-endpoint"],
        );

        for (net, path, expected_id) in [
            ("ws", "/ws", "stream-wrapper-websocket"),
            ("httpupgrade", "/upgrade", "stream-wrapper-httpupgrade"),
            ("grpc", "/grpc", "stream-wrapper-grpc"),
            ("h2", "/h2", "vless-h2-stream-wrapper"),
        ] {
            let mut link = VLESSLink::parse(&vless_fixture_url(
                "",
                &primary,
                fixture_port(4),
                net,
                &authority,
                path,
                &authority,
                "",
                profile.link_fingerprint(),
            ))
            .unwrap();
            link.allow_insecure = profile.allow_insecure();
            assert_exact_tls_source(link.export_url(), profile, &[expected_id]);
        }
    }
}

#[test]
fn vless_reality_variants_have_exact_native_vision_and_wrapper_dispositions() {
    for fingerprint in ["", "chrome"] {
        let expected = MaterializedTlsVariant::new(
            if fingerprint.is_empty() {
                MaterializedSecurity::RealityBoring
            } else {
                MaterializedSecurity::RealityFingerprint
            },
            if fingerprint.is_empty() {
                MaterializedTlsFeatures::NONE
            } else {
                MaterializedTlsFeatures::FINGERPRINT
            },
        );
        let mut vision = VLESSLink::parse(&vless_reality_fixture_url()).unwrap();
        vision.fingerprint = fingerprint.to_owned();
        let source = vision.export_url();
        let shape = assert_exact_source(&source, &fixture_config(), &["reality-security-underlay"]);
        assert_eq!(shape.tls_variant(), expected);

        let mut native = vision.clone();
        native.flow.clear();
        let source = native.export_url();
        let shape = assert_exact_source(&source, &fixture_config(), &["vless-native-tcp-endpoint"]);
        assert_eq!(shape.tls_variant(), expected);

        for (net, path, expected_id) in [
            ("ws", "/ws", "stream-wrapper-websocket"),
            ("httpupgrade", "/upgrade", "stream-wrapper-httpupgrade"),
            ("grpc", "/grpc", "stream-wrapper-grpc"),
        ] {
            let mut wrapped = native.clone();
            wrapped.net = net.to_owned();
            wrapped.host = fixture_host(FixtureEndpoint::Authority);
            wrapped.path = path.to_owned();
            let source = wrapped.export_url();
            let shape = assert_exact_source(&source, &fixture_config(), &[expected_id]);
            assert_eq!(shape.tls_variant(), expected);
        }
    }
}

#[test]
fn vmess_tls_variants_have_exact_transport_rows() {
    let primary = fixture_host(FixtureEndpoint::Primary);
    let authority = fixture_host(FixtureEndpoint::Authority);
    for profile in TlsProfile::ALL {
        for (net, path, expected_id) in [
            ("tcp", "", "baseline-aead-framed-endpoint"),
            ("ws", "/ws", "secure-websocket-framed-endpoint"),
            (
                "httpupgrade",
                "/upgrade",
                "secure-httpupgrade-framed-endpoint",
            ),
            ("grpc", "/grpc", "stream-wrapper-grpc"),
            ("h2", "/h2", "vmess-h2-stream-wrapper"),
        ] {
            let source = vmess_fixture_url_with_sni(
                &primary,
                fixture_port(4),
                net,
                &authority,
                path,
                "tls",
                &authority,
            );
            let mut link = VMessLink::parse(&source).unwrap();
            link.allow_insecure = profile.allow_insecure();
            link.fingerprint = profile.link_fingerprint().to_owned();
            assert_exact_tls_source(link.export_url(), profile, &[expected_id]);
        }
    }
}

#[test]
fn trojan_tls_variants_respect_plain_and_wrapped_fingerprint_boundaries() {
    let primary = fixture_host(FixtureEndpoint::Primary);
    for profile in TlsProfile::ALL {
        let mut plain =
            TrojanLink::parse(&trojan_fixture_url("", &primary, fixture_port(4))).unwrap();
        plain.allow_insecure = profile.allow_insecure();
        assert_exact_tls_source(plain.export_url(), profile, &["baseline-tls-auth-endpoint"]);
    }

    for profile in TlsProfile::WITHOUT_FINGERPRINT {
        for (source, expected_id) in [
            (
                trojan_websocket_fixture_url("", &primary, fixture_port(4)),
                "stream-wrapper-websocket",
            ),
            (
                trojan_httpupgrade_fixture_url("", &primary, fixture_port(4)),
                "stream-wrapper-httpupgrade",
            ),
            (
                trojan_grpc_fixture_url("", &primary, fixture_port(4)),
                "stream-wrapper-grpc",
            ),
            (
                trojan_inner_shadowsocks_fixture_url("aes-128-gcm"),
                "inner-encryption-stream-wrapper",
            ),
        ] {
            let mut link = TrojanLink::parse(&source).unwrap();
            link.allow_insecure = profile.allow_insecure();
            assert_exact_tls_source(link.export_url(), profile, &[expected_id]);
        }
    }
}

#[test]
fn anytls_https_and_https_transport_partition_every_reachable_tls_variant() {
    let primary = fixture_host(FixtureEndpoint::Primary);
    for profile in TlsProfile::ANYTLS {
        let source = if profile.allow_insecure() {
            anytls_insecure_fixture_url(&primary, fixture_port(4))
        } else {
            anytls_fixture_url(&primary, fixture_port(4))
        };
        let expected = if profile.allow_insecure() {
            "insecure-frame-stream-underlay"
        } else {
            "baseline-frame-stream-endpoint"
        };
        assert_exact_tls_source(source, profile, &[expected]);
    }

    for profile in TlsProfile::ALL {
        let expected = if profile.fingerprint() {
            "fingerprint-secure-endpoint-underlay"
        } else if profile.allow_insecure() {
            "insecure-secure-endpoint-underlay"
        } else {
            "secure-endpoint-capability"
        };
        assert_exact_tls_source(https_source(profile, false), profile, &[expected]);
        assert_exact_tls_source(
            https_source(profile, true),
            profile,
            &["proxy-transport-mode"],
        );
    }
}

fn https_source(profile: TlsProfile, transport: bool) -> String {
    let mut source = url::Url::parse(&https_proxy_fixture_url(
        &fixture_host(FixtureEndpoint::Primary),
        fixture_port(4),
    ))
    .unwrap();
    {
        let mut query = source.query_pairs_mut();
        if profile.allow_insecure() {
            query.append_pair("allowInsecure", "1");
        }
        if profile.fingerprint() {
            query
                .append_pair("tlsImplementation", "utls")
                .append_pair("utlsImitate", "chrome");
        }
        if transport {
            query
                .append_pair("transport", "1")
                .append_pair("host", &fixture_host(FixtureEndpoint::Authority));
        }
    }
    if transport {
        source.set_path("/transport");
    }
    source.to_string()
}

#[test]
fn plugin_fragment_and_xhttp_h3_fragment_normalization_are_exact() {
    let plugin = shadowsocks_v2ray_plugin_tls_fixture_url(
        "",
        &fixture_host(FixtureEndpoint::Primary),
        fixture_port(4),
    );
    for profile in [TlsProfile::Standard, TlsProfile::Fragment] {
        assert_exact_tls_source(plugin.clone(), profile, &["tls-websocket-plugin-wrapper"]);
    }

    let source = vless_xhttp_parser_fixture_url("packet-up", "h3", "");
    let shape = assert_exact_source(
        &source,
        &config_for(TlsProfile::Fragment),
        &["xhttp-h3-wrapper"],
    );
    assert_eq!(
        shape.tls_variant(),
        MaterializedTlsVariant::new(MaterializedSecurity::QuicTls, MaterializedTlsFeatures::NONE,)
    );
}
