use dae_outbound::shared_transport::{UtlsClientHelloProfile, parse_utls_client_hello_record_hex};
use serde_json::{Value, json};

const GO_UTLS_CLIENTHELLO_PROFILE_JSON: &str = include_str!(
    "../../../../../testdata/rebuild-golden/outbound/protocol/stage139_go_utls_clienthello_profile.json"
);

pub(super) struct Stage139UtlsWireStats {
    pub sample_count: usize,
    pub parsed_profile_count: usize,
    pub profile_match_count: usize,
    pub total_extension_type_count: usize,
    pub total_cipher_suite_count: usize,
    pub fingerprints: Vec<String>,
    pub sample_profiles: Vec<Value>,
}

pub(super) fn stage139_utls_wire_stats() -> Result<Stage139UtlsWireStats, String> {
    let fixture: Value = serde_json::from_str(GO_UTLS_CLIENTHELLO_PROFILE_JSON)
        .map_err(|err| format!("failed to parse stage139 Go uTLS fixture: {err}"))?;
    let samples = fixture["samples"]
        .as_array()
        .ok_or_else(|| "stage139 Go uTLS fixture missing samples".to_owned())?;

    let mut parsed_profile_count = 0;
    let mut profile_match_count = 0;
    let mut total_extension_type_count = 0;
    let mut total_cipher_suite_count = 0;
    let mut fingerprints = Vec::new();
    let mut sample_profiles = Vec::new();

    for sample in samples {
        let fingerprint = sample["fingerprint"]
            .as_str()
            .ok_or_else(|| "stage139 Go uTLS fixture sample missing fingerprint".to_owned())?;
        let record_hex = sample["record_hex"]
            .as_str()
            .ok_or_else(|| format!("{fingerprint}: missing record_hex"))?;
        let expected = &sample["profile"];
        let profile = parse_utls_client_hello_record_hex(record_hex)
            .map_err(|err| format!("{fingerprint}: failed to parse ClientHello: {err}"))?;
        parsed_profile_count += 1;
        if profile_matches_fixture(&profile, expected) {
            profile_match_count += 1;
        }
        total_extension_type_count += profile.extension_types.len();
        total_cipher_suite_count += profile.cipher_suites.len();
        fingerprints.push(fingerprint.to_owned());
        sample_profiles.push(json!({
            "fingerprint": fingerprint,
            "record_len": profile.record_len,
            "handshake_len": profile.handshake_len,
            "cipher_suite_count": profile.cipher_suites.len(),
            "extension_type_count": profile.extension_types.len(),
            "sni": profile.sni,
            "alpn": profile.alpn,
            "supported_versions": profile.supported_versions,
            "key_share_groups": profile.key_share_groups,
            "profile_matches_fixture": profile_matches_fixture(&profile, expected)
        }));
    }

    Ok(Stage139UtlsWireStats {
        sample_count: samples.len(),
        parsed_profile_count,
        profile_match_count,
        total_extension_type_count,
        total_cipher_suite_count,
        fingerprints,
        sample_profiles,
    })
}

fn profile_matches_fixture(profile: &UtlsClientHelloProfile, expected: &Value) -> bool {
    profile.record_content_type == expected["record_content_type"].as_str().unwrap_or_default()
        && profile.record_version == expected["record_version"].as_str().unwrap_or_default()
        && profile.record_len == expected["record_len"].as_u64().unwrap_or_default() as usize
        && profile.handshake_type == expected["handshake_type"].as_str().unwrap_or_default()
        && profile.handshake_len == expected["handshake_len"].as_u64().unwrap_or_default() as usize
        && profile.legacy_version == expected["legacy_version"].as_str().unwrap_or_default()
        && profile.random_len == expected["random_len"].as_u64().unwrap_or_default() as usize
        && profile.session_id_len
            == expected["session_id_len"].as_u64().unwrap_or_default() as usize
        && profile.cipher_suites == string_vec(&expected["cipher_suites"])
        && profile.compression_methods == string_vec(&expected["compression_methods"])
        && profile.extension_types == string_vec(&expected["extension_types"])
        && profile.sni.as_deref() == expected["sni"].as_str()
        && profile.alpn == optional_string_vec(&expected["alpn"])
        && profile.supported_versions == optional_string_vec(&expected["supported_versions"])
        && profile.supported_groups == optional_string_vec(&expected["supported_groups"])
        && profile.ec_point_formats == optional_string_vec(&expected["ec_point_formats"])
        && profile.signature_schemes == optional_string_vec(&expected["signature_schemes"])
        && profile.key_share_groups == optional_string_vec(&expected["key_share_groups"])
}

fn string_vec(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|item| item.as_str().map(str::to_owned))
        .collect()
}

fn optional_string_vec(value: &Value) -> Option<Vec<String>> {
    value.as_array().map(|items| {
        items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect()
    })
}
