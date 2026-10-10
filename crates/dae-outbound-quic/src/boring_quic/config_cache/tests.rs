use super::*;

#[test]
fn quic_templates_reuse_only_matching_crypto_and_session_identity() {
    let policy = BoringQuicClientPolicy::new([b"cache-template-test".as_slice()])
        .unwrap()
        .allow_insecure(true);
    let sessions = new_boring_quic_session_cache();
    let before = BUILDS.with(std::cell::Cell::get);
    client_config(
        &policy,
        Arc::new(quinn::TransportConfig::default()),
        Some(Arc::clone(&sessions)),
        None,
    )
    .unwrap();
    let mut other_transport = quinn::TransportConfig::default();
    other_transport.max_concurrent_uni_streams(17_u8.into());
    client_config(
        &policy,
        Arc::new(other_transport),
        Some(Arc::clone(&sessions)),
        None,
    )
    .unwrap();
    assert_eq!(BUILDS.with(std::cell::Cell::get), before + 1);
    client_config(
        &policy.clone().zero_rtt(true),
        Arc::new(quinn::TransportConfig::default()),
        Some(sessions),
        None,
    )
    .unwrap();
    client_config(
        &policy,
        Arc::new(quinn::TransportConfig::default()),
        Some(new_boring_quic_session_cache()),
        None,
    )
    .unwrap();
    assert_eq!(BUILDS.with(std::cell::Cell::get), before + 3);
}
