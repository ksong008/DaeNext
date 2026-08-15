use super::*;
use dae_outbound::{MaterializedSecurity, MaterializedTlsFeatures, MaterializedTlsVariant};

#[test]
fn meek_tls_and_reality_variants_have_exact_dispositions() {
    for profile in TlsProfile::ALL {
        let mut link = VLESSLink::parse(&meek_tls_source()).unwrap();
        link.allow_insecure = profile.allow_insecure();
        link.fingerprint = profile.link_fingerprint().to_owned();
        assert_exact_tls_source(
            link.export_url(),
            profile,
            &["vless-meek-tls-stream-wrapper"],
        );
    }

    for fingerprint in ["", "chrome"] {
        let mut link = VLESSLink::parse(&vless_reality_fixture_url()).unwrap();
        link.net = "meek".to_owned();
        link.flow.clear();
        link.host.clear();
        link.path = meek_url();
        link.alpn = dae_outbound::shared_transport::UTLS_ALPN_HTTP_1_1.to_owned();
        link.fingerprint = fingerprint.to_owned();
        let source = link.export_url();
        let shape = assert_exact_source(
            &source,
            &fixture_config(),
            &["vless-meek-reality-stream-wrapper"],
        );
        assert_eq!(shape.tls_variant(), reality_variant(fingerprint));
    }
}

#[test]
fn mux_reaches_its_exact_row_for_every_stream_tls_variant() {
    for profile in TlsProfile::ALL {
        let mut link = VLESSLink::parse(&vless_mux_fixture_url()).unwrap();
        link.allow_insecure = profile.allow_insecure();
        link.fingerprint = profile.link_fingerprint().to_owned();
        assert_exact_tls_source(link.export_url(), profile, &["mux-transport-wrapper"]);
    }
}

fn meek_tls_source() -> String {
    vless_fixture_url(
        "",
        &fixture_host(FixtureEndpoint::Primary),
        fixture_port(4),
        "meek",
        "",
        &meek_url(),
        &fixture_host(FixtureEndpoint::Authority),
        "",
        "",
    )
}

fn meek_url() -> String {
    "https://meek.fixture.invalid/resource".to_owned()
}

fn reality_variant(fingerprint: &str) -> MaterializedTlsVariant {
    if fingerprint.is_empty() {
        MaterializedTlsVariant::new(
            MaterializedSecurity::RealityBoring,
            MaterializedTlsFeatures::NONE,
        )
    } else {
        MaterializedTlsVariant::new(
            MaterializedSecurity::RealityFingerprint,
            MaterializedTlsFeatures::FINGERPRINT,
        )
    }
}
