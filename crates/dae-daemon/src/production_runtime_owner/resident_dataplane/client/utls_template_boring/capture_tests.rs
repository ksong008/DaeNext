use super::*;
use crate::production_runtime_owner::resident_dataplane::plan::{
    ResidentProxyProtocolPlan, ResidentRealityUnderlayPlan, ResidentXhttpMode,
    ResidentXhttpSettingsPlan,
};
use dae_outbound::shared_transport::{
    SUPPORTED_UTLS_FINGERPRINTS, UtlsClientHelloProfile, UtlsFingerprint, UtlsRuntimeTemplate,
    parse_utls_client_hello_record, parse_utls_client_hello_record_hex,
    resolve_utls_runtime_template, utls_fingerprint_default_alpn_protocols,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, timeout};

const FIXTURE_SERVER_NAME: &str = "utls-profiles.invalid";
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(5);
const FIXTURE_REALITY_PUBLIC_KEY: [u8; 32] = [
    0x4c, 0x23, 0xa2, 0x05, 0x07, 0xab, 0x96, 0xb6, 0x73, 0xd3, 0xcc, 0xf5, 0x96, 0xb6, 0x60, 0x87,
    0x47, 0x2b, 0xe6, 0x98, 0xbb, 0xe6, 0x97, 0xfa, 0x67, 0x0b, 0x63, 0x81, 0xfb, 0xa4, 0xd6, 0x50,
];

#[tokio::test(flavor = "current_thread")]
async fn boring_template_clienthello_matches_runtime_templates() {
    for fingerprint in exact_runtime_fingerprints() {
        let template = resolve_utls_runtime_template(&fingerprint).unwrap();
        let captured = capture_boring_client_hello(test_tls_proxy(&fingerprint))
            .await
            .unwrap_or_else(|err| panic!("capture {} ordinary TLS: {err}", fingerprint.name));
        let fixture = fixture_profile(fingerprint.name);
        assert_profile_matches_template(fingerprint.name, &captured, template);
        assert_profile_matches_fixture(fingerprint.name, &captured, &fixture);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn reality_boring_template_clienthello_matches_runtime_templates_before_session_mutation() {
    for fingerprint in exact_runtime_fingerprints()
        .into_iter()
        .filter(|fingerprint| {
            resolve_utls_runtime_template(fingerprint)
                .is_some_and(|template| !template.key_share_groups.is_empty())
        })
    {
        let template = resolve_utls_runtime_template(&fingerprint).unwrap();
        let captured = capture_boring_client_hello(test_reality_proxy(&fingerprint))
            .await
            .unwrap_or_else(|err| panic!("capture {} Reality TLS: {err}", fingerprint.name));
        let fixture = fixture_profile(fingerprint.name);
        assert_profile_matches_template(fingerprint.name, &captured, template);
        assert_profile_matches_fixture_except_session_id(fingerprint.name, &captured, &fixture);
        assert_eq!(
            captured.session_id_len, 32,
            "{} Reality session id",
            fingerprint.name
        );
    }
}

async fn capture_boring_client_hello(
    mut proxy: ResidentProxyPlan,
) -> Result<UtlsClientHelloProfile, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|err| format!("bind local TLS capture listener: {err}"))?;
    let addr = listener
        .local_addr()
        .map_err(|err| format!("read local TLS capture address: {err}"))?;
    proxy.server_host = addr.ip().to_string();
    proxy.server_port = addr.port();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|err| format!("accept local TLS capture connection: {err}"))?;
        let mut header = [0_u8; 5];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|err| format!("read TLS record header: {err}"))?;
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut record = Vec::with_capacity(5 + record_len);
        record.extend_from_slice(&header);
        let mut body = vec![0_u8; record_len];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|err| format!("read TLS record body: {err}"))?;
        record.extend_from_slice(&body);
        Ok::<_, String>(record)
    });

    let client_proxy = proxy.clone();
    let client = tokio::spawn(async move {
        let policy = ResidentTlsPolicy::from_proxy(&client_proxy);
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|err| format!("connect local TLS capture listener: {err}"))?;
        let connector = boring_vless_connector(&client_proxy, &policy)?;
        let mut config = connector
            .configure()
            .map_err(|err| format!("configure BoringSSL client: {err}"))?;
        configure_utls_template_boring_ssl(&mut config, &client_proxy)?;
        if policy.verification.reality_material().is_some() {
            config.set_verify_hostname(false);
            let mldsa65_verify = client_proxy
                .reality
                .as_ref()
                .and_then(|reality| reality.mldsa65_verify.clone());
            config.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
                verify_reality_boring_server_cert(ssl, mldsa65_verify.as_ref())
            });
            configure_reality_boring_ssl(&mut config, &policy.verification)?;
        }
        tokio_boring::connect(config, &policy.server_name, tcp)
            .await
            .map(|_| ())
            .map_err(|err| format!("BoringSSL handshake stopped before capture completed: {err}"))
    });

    let server_result = timeout(CAPTURE_TIMEOUT, server)
        .await
        .map_err(|_| "capture TLS ClientHello timed out".to_owned())?
        .map_err(|err| format!("join TLS capture server: {err}"))?;
    let client_result = timeout(CAPTURE_TIMEOUT, client)
        .await
        .map_err(|_| "capture TLS client timed out".to_owned())?
        .map_err(|err| format!("join TLS capture client: {err}"))?;
    let record = match server_result {
        Ok(record) => record,
        Err(server_err) => {
            return Err(format!("{server_err}; client result: {client_result:?}"));
        }
    };

    parse_utls_client_hello_record(&record)
        .map_err(|err| format!("parse captured TLS ClientHello: {err}"))
}

fn exact_runtime_fingerprints() -> Vec<UtlsFingerprint> {
    SUPPORTED_UTLS_FINGERPRINTS
        .iter()
        .copied()
        .filter(|fingerprint| resolve_utls_runtime_template(fingerprint).is_some())
        .collect()
}

fn fixture_profile(fingerprint_name: &str) -> UtlsClientHelloProfile {
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/utls_clienthello/generated.json");
    let fixture = std::fs::read_to_string(&fixture_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", fixture_path.display()));
    let fixture: serde_json::Value = serde_json::from_str(&fixture)
        .unwrap_or_else(|err| panic!("parse {}: {err}", fixture_path.display()));
    let sample = fixture["samples"]
        .as_array()
        .unwrap()
        .iter()
        .find(|sample| sample["fingerprint"].as_str().unwrap() == fingerprint_name)
        .unwrap_or_else(|| panic!("missing fixture sample for {fingerprint_name}"));
    parse_utls_client_hello_record_hex(sample["record_hex"].as_str().unwrap())
        .unwrap_or_else(|err| panic!("parse fixture {fingerprint_name}: {err}"))
}

fn assert_profile_matches_template(
    fingerprint_name: &str,
    profile: &UtlsClientHelloProfile,
    template: &UtlsRuntimeTemplate,
) {
    assert_eq!(
        normalized_u16_values(&profile.cipher_suites),
        template.cipher_suites,
        "{fingerprint_name} cipher suites"
    );
    assert_eq!(
        normalized_u16_values(&profile.extension_types),
        template.extension_order,
        "{fingerprint_name} extension order"
    );
    assert_eq!(
        normalized_optional_u16_values(&profile.supported_versions),
        template.supported_versions,
        "{fingerprint_name} supported versions"
    );
    assert_eq!(
        normalized_optional_u16_values(&profile.supported_groups),
        template.supported_groups,
        "{fingerprint_name} supported groups"
    );
    assert_eq!(
        normalized_optional_u16_values(&profile.key_share_groups),
        template.key_share_groups,
        "{fingerprint_name} key share groups"
    );
    assert_eq!(
        normalized_optional_u16_values(&profile.signature_schemes),
        template.signature_schemes,
        "{fingerprint_name} signature schemes"
    );
    assert_eq!(
        normalized_optional_u16_values(&profile.delegated_credential_signature_schemes),
        template.delegated_credential_signature_schemes,
        "{fingerprint_name} delegated credential signature schemes"
    );
    assert_eq!(
        normalized_optional_u16_values(&profile.record_size_limit)
            .first()
            .copied(),
        template.record_size_limit,
        "{fingerprint_name} record size limit"
    );
}

fn assert_profile_matches_fixture(
    fingerprint_name: &str,
    captured: &UtlsClientHelloProfile,
    fixture: &UtlsClientHelloProfile,
) {
    assert_profile_matches_fixture_except_session_id(fingerprint_name, captured, fixture);
    assert_eq!(
        captured.session_id_len, fixture.session_id_len,
        "{fingerprint_name} session id length"
    );
}

fn assert_profile_matches_fixture_except_session_id(
    fingerprint_name: &str,
    captured: &UtlsClientHelloProfile,
    fixture: &UtlsClientHelloProfile,
) {
    assert_eq!(captured.sni, fixture.sni, "{fingerprint_name} SNI");
    assert_eq!(captured.alpn, fixture.alpn, "{fingerprint_name} ALPN");
    assert_eq!(
        captured.compression_methods, fixture.compression_methods,
        "{fingerprint_name} compression methods"
    );
    assert_eq!(
        captured.legacy_version, fixture.legacy_version,
        "{fingerprint_name} legacy version"
    );
}

fn normalized_optional_u16_values(values: &Option<Vec<String>>) -> Vec<u16> {
    values
        .as_deref()
        .map(normalized_u16_values)
        .unwrap_or_default()
}

fn normalized_u16_values(values: &[String]) -> Vec<u16> {
    values
        .iter()
        .map(|value| {
            if is_grease_u16_hex(value) {
                dae_outbound::shared_transport::UTLS_TEMPLATE_GREASE
            } else {
                u16::from_str_radix(value, 16).unwrap()
            }
        })
        .collect()
}

fn is_grease_u16_hex(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 4 {
        return false;
    }
    let Some(high) = hex_byte(&bytes[0..2]) else {
        return false;
    };
    let Some(low) = hex_byte(&bytes[2..4]) else {
        return false;
    };
    high == low && (high & 0x0f) == 0x0a
}

fn hex_byte(bytes: &[u8]) -> Option<u8> {
    Some((hex_nibble(bytes[0])? << 4) | hex_nibble(bytes[1])?)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn test_tls_proxy(fingerprint: &UtlsFingerprint) -> ResidentProxyPlan {
    let mut proxy = base_proxy(
        fingerprint,
        ResidentProxyProtocolPlan::TrojanTcpTls {
            password: "capture-secret".to_owned(),
        },
    );
    proxy.protocol = "trojan";
    proxy.tls = "tls".to_owned();
    proxy.materialize_execution();
    proxy
}

fn test_reality_proxy(fingerprint: &UtlsFingerprint) -> ResidentProxyPlan {
    let mut proxy = base_proxy(
        fingerprint,
        ResidentProxyProtocolPlan::VlessVisionTcpTls {
            key: [0; 16],
            encryption: None,
        },
    );
    proxy.protocol = "vless";
    proxy.tls = "reality".to_owned();
    proxy.flow = "xtls-rprx-vision".to_owned();
    proxy.reality = Some(ResidentRealityUnderlayPlan {
        public_key: FIXTURE_REALITY_PUBLIC_KEY,
        short_id: vec![1, 2, 3, 4],
        spider_x: "/".to_owned(),
        mldsa65_verify: None,
    });
    proxy.materialize_execution();
    proxy
}

fn base_proxy(
    fingerprint: &UtlsFingerprint,
    handler: ResidentProxyProtocolPlan,
) -> ResidentProxyPlan {
    ResidentProxyPlan {
        graph_id: "resident-graph:utls-capture".to_owned(),
        graph_link_hash: "sha256:utls-capture".to_owned(),
        redacted_link_source: "capture:<redacted>".to_owned(),
        protocol: "test",
        group_name: "capture".to_owned(),
        group_policy: "fixed".to_owned(),
        node_tag: format!("capture-{}", fingerprint.name),
        server_host: "127.0.0.1".to_owned(),
        server_port: 0,
        server_name: FIXTURE_SERVER_NAME.to_owned(),
        alpn: utls_fingerprint_default_alpn_protocols(fingerprint)
            .iter()
            .map(|protocol| (*protocol).to_owned())
            .collect(),
        flow: String::new(),
        net: "tcp".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        grpc_mode: dae_outbound::shared_transport::GrpcMode::Gun,
        xhttp_download: None,
        xhttp_mode: ResidentXhttpMode::PacketUp,
        xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
        xhttp_xmux: None,
        tls: String::new(),
        allow_insecure: false,
        tls_fragment: None,
        utls_fingerprint: Some(ResidentUtlsFingerprintPlan {
            source: "capture fp",
            requested: fingerprint.name.to_owned(),
            name: fingerprint.name.to_owned(),
            canonical: fingerprint.canonical.to_owned(),
            family: fingerprint.family.to_owned(),
            client: fingerprint.client.to_owned(),
            randomized: fingerprint.randomized,
            alpn_policy: fingerprint.alpn_policy.to_owned(),
            default_alpn: utls_fingerprint_default_alpn_protocols(fingerprint)
                .iter()
                .map(|protocol| (*protocol).to_owned())
                .collect(),
        }),
        ech: None,
        reality: None,
        handler,
        execution: None,
        chain_parent: None,
        mark: 0,
        mptcp: false,
    }
}
