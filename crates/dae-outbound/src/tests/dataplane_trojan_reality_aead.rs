use super::*;

fn case_options(
    algorithm: shared_transport::RealityAeadAlgorithm,
) -> shared_transport::RealitySessionIdMutationOptions {
    let sid = [0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44];
    let unix_seconds = 1_717_171_717;
    let mut client_random = [0_u8; shared_transport::REALITY_CLIENT_RANDOM_LEN];
    for (index, byte) in client_random.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(7).wrapping_add(3);
    }
    let mut shared_secret = [0_u8; 32];
    for (index, byte) in shared_secret.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(11).wrapping_add(5);
    }
    let plaintext = shared_transport::reality_session_id_plaintext(sid, unix_seconds);
    let mut hello_raw = vec![0x42; 96];
    hello_raw[shared_transport::REALITY_SESSION_ID_RAW_OFFSET
        ..shared_transport::REALITY_SESSION_ID_RAW_OFFSET
            + shared_transport::REALITY_SESSION_ID_PLAINTEXT_LEN]
        .copy_from_slice(&plaintext);
    shared_transport::RealitySessionIdMutationOptions {
        sid,
        unix_seconds,
        client_random,
        shared_secret,
        hello_raw,
        algorithm,
    }
}

#[test]
fn case_reality_session_plaintext_layout_matches_native() {
    let options = case_options(shared_transport::RealityAeadAlgorithm::AesGcm);
    let plaintext =
        shared_transport::reality_session_id_plaintext(options.sid, options.unix_seconds);

    assert_eq!(&plaintext[..3], &[1, 8, 10]);
    assert_eq!(plaintext[3], 0);
    assert_eq!(&plaintext[4..8], &options.unix_seconds.to_be_bytes());
    assert_eq!(&plaintext[8..16], &options.sid);
}

#[test]
fn case_reality_aead_mutates_session_id_and_hello_raw() {
    let options = case_options(shared_transport::RealityAeadAlgorithm::AesGcm);
    let plaintext =
        shared_transport::reality_session_id_plaintext(options.sid, options.unix_seconds);
    let mutated = shared_transport::mutate_reality_session_id(&options).unwrap();

    assert_eq!(mutated.len(), shared_transport::REALITY_SESSION_ID_LEN);
    assert_ne!(
        &mutated[..shared_transport::REALITY_SESSION_ID_PLAINTEXT_LEN],
        &plaintext
    );
    let report = shared_transport::reality_session_id_mutation_report(&options).unwrap();
    assert_eq!(report.algorithm, "aes-gcm");
    assert_eq!(report.session_id_offset, 39);
    assert!(report.mutation_applied_to_hello_raw);
    assert!(!report.full_utls_stack);
}

#[test]
fn case_reality_chacha_branch_uses_same_nonce_and_different_ciphertext() {
    let aes = case_options(shared_transport::RealityAeadAlgorithm::AesGcm);
    let chacha = case_options(shared_transport::RealityAeadAlgorithm::ChaCha20Poly1305);
    let aes_report = shared_transport::reality_session_id_mutation_report(&aes).unwrap();
    let chacha_report = shared_transport::reality_session_id_mutation_report(&chacha).unwrap();

    assert_eq!(aes_report.nonce_hex, chacha_report.nonce_hex);
    assert_eq!(aes_report.auth_key_hex, chacha_report.auth_key_hex);
    assert_ne!(
        aes_report.mutated_session_id_hex,
        chacha_report.mutated_session_id_hex
    );
    assert_eq!(chacha_report.algorithm, "chacha20poly1305");
}

#[test]
fn case_reality_hello_raw_short_buffer_is_rejected() {
    let session_id = [0_u8; shared_transport::REALITY_SESSION_ID_LEN];
    let mut short = vec![0_u8; shared_transport::REALITY_SESSION_ID_RAW_OFFSET];
    let err = shared_transport::apply_reality_session_id_to_hello_raw(&mut short, &session_id)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("REALITY hello raw too short for session id offset")
    );
}
