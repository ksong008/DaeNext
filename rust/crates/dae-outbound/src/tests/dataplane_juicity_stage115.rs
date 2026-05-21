use super::*;

const GO_CHAIN_HASH_HEX: &str = "584fb94485a58b9036f20086e915df79e51c4eb8b7dbb46fb75a113bb656bf4e";
const URL_SAFE_PIN: &str = "WE-5RIWli5A28gCG6RXfeeUcTri327Rvt1oRO7ZWv04=";
const STD_PIN: &str = "WE+5RIWli5A28gCG6RXfeeUcTri327Rvt1oRO7ZWv04=";

fn stage115_raw_certs() -> [&'static [u8]; 2] {
    [b"leaf-0".as_slice(), b"intermediate-0".as_slice()]
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn stage115_juicity_certchain_hash_matches_go_vector() {
    let raw = stage115_raw_certs();
    let hash = juicity::generate_cert_chain_hash(&raw);
    assert_eq!(hex_encode(&hash), GO_CHAIN_HASH_HEX);
}

#[test]
fn stage115_juicity_certchain_pin_verifies_url_and_std_base64() {
    let raw = stage115_raw_certs();

    let url_check = juicity::verify_pinned_certchain(&raw, URL_SAFE_PIN).unwrap();
    assert_eq!(url_check.pin_format, "url-base64");
    assert_eq!(hex_encode(&url_check.chain_hash), GO_CHAIN_HASH_HEX);
    assert!(url_check.matched);
    assert_eq!(url_check.cert_count, 2);
    assert!(url_check.forces_insecure_verify);
    assert!(url_check.verifies_full_chain_hash);
    assert!(url_check.not_hysteria2_pin_sha256);

    let std_check = juicity::verify_pinned_certchain(&raw, STD_PIN).unwrap();
    assert_eq!(std_check.pin_format, "std-base64");
    assert_eq!(std_check.chain_hash, url_check.chain_hash);
    assert!(std_check.matched);
}

#[test]
fn stage115_juicity_certchain_hex_looking_sha256_pin_records_go_decode_caveat() {
    let raw = stage115_raw_certs();
    let check = juicity::check_pinned_certchain(&raw, GO_CHAIN_HASH_HEX).unwrap();

    assert_eq!(check.pin_format, "url-base64");
    assert_eq!(check.decoded_pin.len(), 48);
    assert_eq!(check.chain_hash.len(), 32);
    assert!(!check.matched);

    let err = juicity::verify_pinned_certchain(&raw, GO_CHAIN_HASH_HEX).unwrap_err();
    assert!(err.to_string().contains("pinned hash of cert chain"));
}

#[test]
fn stage115_juicity_certchain_bad_pin_fails_decode() {
    let raw = stage115_raw_certs();
    let err = juicity::check_pinned_certchain(&raw, "bad-pin").unwrap_err();
    assert!(
        err.to_string()
            .contains("failed to decode PinnedCertchainSha256")
    );
}
