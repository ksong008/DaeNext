use super::*;
use dae_outbound::{
    MaterializedQuicVerification, MaterializedSecurity, MaterializedTlsFeatures,
    MaterializedTlsVariant, MaterializedXhttpMode, MaterializedXhttpSettings,
};

const XHTTP_MODES: [&str; 3] = ["packet-up", "stream-up", "stream-one"];
const EXTENDED_HEADERS: &str = r#"{"headers":{"X-Test":"alpha"}}"#;

#[test]
fn h1_and_h2_cover_every_tls_variant_and_mode() {
    for (alpn, shape_id) in [
        ("http/1.1", "xhttp-h1-wrapper"),
        ("h2", "stream-wrapper-xhttp"),
    ] {
        for mode in XHTTP_MODES {
            for profile in TlsProfile::ALL {
                assert_exact_tls_source(
                    xhttp_tls_source(mode, alpn, "", profile),
                    profile,
                    &[shape_id],
                );
            }
        }
    }
}

#[test]
fn h2_reality_covers_both_underlays_and_every_mode() {
    for mode in XHTTP_MODES {
        for fingerprint in ["", "chrome"] {
            let source = xhttp_reality_source(mode, "h2", "", fingerprint);
            let shape = assert_exact_source(&source, &fixture_config(), &["stream-wrapper-xhttp"]);
            assert_eq!(shape.tls_variant(), reality_variant(fingerprint));
            assert_eq!(shape.xhttp_mode, materialized_mode(mode));
        }
    }
}

#[test]
fn h1_and_h3_reality_are_rejected_for_every_mode() {
    for mode in XHTTP_MODES {
        for alpn in ["http/1.1", "h3"] {
            let error = build(&xhttp_reality_source(mode, alpn, "", "")).unwrap_err();
            let error_lower = error.to_ascii_lowercase();
            assert!(error_lower.contains("reality"), "{mode}/{alpn}: {error}");
            assert!(error_lower.contains(alpn), "{mode}/{alpn}: {error}");
            assert!(
                error_lower.contains("not supported") || error_lower.contains("does not admit"),
                "{mode}/{alpn}: {error}"
            );
        }
    }
}

#[test]
fn h3_covers_both_verification_modes_and_normalizes_fragment_for_every_mode() {
    for mode in XHTTP_MODES {
        let verified = xhttp_tls_source(mode, "h3", "", TlsProfile::Fragment);
        let verified_shape = assert_exact_source(
            &verified,
            &config_for(TlsProfile::Fragment),
            &["xhttp-h3-wrapper"],
        );
        assert_h3_shape(verified_shape, mode, MaterializedQuicVerification::WebPki);

        let mut insecure = VLESSLink::parse(&verified).unwrap();
        insecure.allow_insecure = true;
        let insecure = insecure.export_url();
        let insecure_shape = assert_exact_source(
            &insecure,
            &config_for(TlsProfile::Fragment),
            &["xhttp-h3-wrapper"],
        );
        assert_h3_shape(insecure_shape, mode, MaterializedQuicVerification::Insecure);
    }
}

#[test]
fn extended_primary_settings_are_aggregate_for_every_admitted_version_and_mode() {
    for mode in XHTTP_MODES {
        for alpn in ["http/1.1", "h2", "h3"] {
            assert_extended(xhttp_tls_source(
                mode,
                alpn,
                EXTENDED_HEADERS,
                TlsProfile::Standard,
            ));
        }
        for fingerprint in ["", "chrome"] {
            assert_extended(xhttp_reality_source(
                mode,
                "h2",
                EXTENDED_HEADERS,
                fingerprint,
            ));
        }
    }
}

#[test]
fn download_and_xmux_extensions_have_only_the_aggregate_disposition() {
    for alpn in ["http/1.1", "h2", "h3"] {
        assert_extended(xhttp_tls_source(
            "packet-up",
            alpn,
            &download_extra(),
            TlsProfile::Standard,
        ));
        assert_extended(xhttp_tls_source(
            "packet-up",
            alpn,
            r#"{"xmux":{"maxConnections":2}}"#,
            TlsProfile::Standard,
        ));
    }
    assert_extended(xhttp_reality_source(
        "packet-up",
        "h2",
        &download_extra(),
        "chrome",
    ));
}

fn xhttp_tls_source(mode: &str, alpn: &str, extra: &str, profile: TlsProfile) -> String {
    let mut link = VLESSLink::parse(&vless_xhttp_parser_fixture_url(mode, alpn, extra)).unwrap();
    link.allow_insecure = profile.allow_insecure();
    link.fingerprint = profile.link_fingerprint().to_owned();
    link.export_url()
}

fn xhttp_reality_source(mode: &str, alpn: &str, extra: &str, fingerprint: &str) -> String {
    let reality = VLESSLink::parse(&vless_reality_fixture_url()).unwrap();
    let mut link = VLESSLink::parse(&vless_xhttp_parser_fixture_url(mode, alpn, extra)).unwrap();
    link.tls = "reality".to_owned();
    link.public_key = reality.public_key;
    link.short_id = reality.short_id;
    link.spider_x = reality.spider_x;
    link.fingerprint = fingerprint.to_owned();
    link.export_url()
}

fn assert_h3_shape(
    shape: MaterializedSourceShape,
    mode: &str,
    verification: MaterializedQuicVerification,
) {
    assert_eq!(
        shape.tls_variant(),
        MaterializedTlsVariant::new(MaterializedSecurity::QuicTls, MaterializedTlsFeatures::NONE)
    );
    assert_eq!(shape.quic_verification, verification);
    assert_eq!(shape.xhttp_mode, materialized_mode(mode));
}

fn assert_extended(source: String) {
    let proxy = build(&source).unwrap_or_else(|error| panic!("build extended xHTTP: {error}"));
    let shape = materialized_source_shape(&proxy, &source);
    assert_eq!(shape.xhttp_settings, MaterializedXhttpSettings::Extended);
    assert!(
        production_match_ids(&source, &proxy).is_empty(),
        "{shape:?}"
    );
    let disposition = source_shape_reconciliation("xhttp-extended-settings-wrapper").unwrap();
    assert_eq!(
        disposition.kind,
        SourceShapeReconciliationKind::AggregateCapability
    );
    assert!(disposition.classifies(shape), "{shape:?}");
}

fn materialized_mode(mode: &str) -> MaterializedXhttpMode {
    match mode {
        "packet-up" => MaterializedXhttpMode::PacketUp,
        "stream-up" => MaterializedXhttpMode::StreamUp,
        "stream-one" => MaterializedXhttpMode::StreamOne,
        other => panic!("unexpected xHTTP mode {other}"),
    }
}

fn reality_variant(fingerprint: &str) -> MaterializedTlsVariant {
    if fingerprint.is_empty() {
        MaterializedTlsVariant::new(
            MaterializedSecurity::RealityRustls,
            MaterializedTlsFeatures::NONE,
        )
    } else {
        MaterializedTlsVariant::new(
            MaterializedSecurity::RealityFingerprint,
            MaterializedTlsFeatures::FINGERPRINT,
        )
    }
}

fn download_extra() -> String {
    format!(
        r#"{{"downloadSettings":{{"address":"download.fixture.invalid","port":{},"network":"xhttp","security":"tls","tlsSettings":{{"serverName":"download.fixture.invalid","alpn":["h2"]}},"xhttpSettings":{{"host":"download.fixture.invalid","path":"/download","mode":"packet-up"}}}}}}"#,
        fixture_port(9)
    )
}
