use super::*;

#[test]
fn stage121_juicity_authenticate_header_matches_tuic_juicity_layout() {
    let header = juicity::build_deterministic_authenticate_header();

    assert_eq!(header.version, juicity::JUICITY_AUTHENTICATE_VERSION0);
    assert_eq!(header.command_type, juicity::JUICITY_AUTHENTICATE_TYPE);
    assert_eq!(header.uuid.len(), juicity::JUICITY_AUTHENTICATE_UUID_LEN);
    assert_eq!(header.token.len(), juicity::JUICITY_AUTHENTICATE_TOKEN_LEN);
    assert_eq!(
        header.encoded.len(),
        juicity::JUICITY_AUTHENTICATE_HEADER_LEN
    );
    assert_eq!(header.encoded[0], 0x00);
    assert_eq!(header.encoded[1], 0x00);
    assert_eq!(
        &header.encoded[2..2 + juicity::JUICITY_AUTHENTICATE_UUID_LEN],
        header.uuid.as_slice()
    );
    assert_eq!(
        &header.encoded[2 + juicity::JUICITY_AUTHENTICATE_UUID_LEN..],
        header.token.as_slice()
    );
    assert_eq!(header.token_source, "deterministic-fixture-not-live-ekm");
    assert!(header.layout_valid());
}

#[test]
fn stage121_juicity_auth_stream_transcript_writes_header_before_dialauth_record() {
    let header = juicity::build_deterministic_authenticate_header();
    let dialauth = juicity::build_dialauth_record_for_port_zero("stage121-zero.example:0").unwrap();
    let transcript = juicity::build_auth_stream_transcript(&header, &dialauth);

    assert_eq!(transcript.target, "stage121-zero.example:0");
    assert_eq!(transcript.auth_header_offset, 0);
    assert_eq!(
        transcript.dialauth_record_offset,
        juicity::JUICITY_AUTHENTICATE_HEADER_LEN
    );
    assert_eq!(
        transcript.transcript_len,
        juicity::JUICITY_AUTHENTICATE_HEADER_LEN + dialauth.packed.len()
    );
    assert_eq!(
        &transcript.transcript[..juicity::JUICITY_AUTHENTICATE_HEADER_LEN],
        header.encoded.as_slice()
    );
    assert_eq!(
        &transcript.transcript[juicity::JUICITY_AUTHENTICATE_HEADER_LEN..],
        dialauth.packed.as_slice()
    );
    assert!(transcript.auth_header_written_first);
    assert!(transcript.dialauth_record_matches_packet_state_contract);
    assert!(transcript.dialauth_record_order_valid);
}

#[test]
fn stage121_juicity_auth_stream_smoke_admits_only_local_transcript_contract() {
    let report = juicity::auth_stream_smoke("stage121-zero.example:0").unwrap();

    assert_eq!(report.target, "stage121-zero.example:0");
    assert_eq!(report.authenticate_version, 0x00);
    assert_eq!(report.authenticate_type, 0x00);
    assert_eq!(
        report.authenticate_header_len,
        juicity::JUICITY_AUTHENTICATE_HEADER_LEN
    );
    assert_eq!(
        report.dialauth_record_offset,
        juicity::JUICITY_AUTHENTICATE_HEADER_LEN
    );
    assert_eq!(
        report.dialauth_iv_len,
        juicity::JUICITY_UNDERLAY_AUTH_IV_LEN
    );
    assert_eq!(
        report.dialauth_psk_len,
        juicity::JUICITY_UNDERLAY_AUTH_PSK_LEN
    );
    assert_eq!(
        report.dialauth_record_len,
        juicity::JUICITY_UNDERLAY_AUTH_IV_LEN
            + juicity::JUICITY_UNDERLAY_AUTH_PSK_LEN
            + report.dialauth_metadata_len
    );
    assert!(report.authenticate_header_layout_valid);
    assert!(report.auth_header_written_first);
    assert!(report.dialauth_record_matches_packet_state_contract);
    assert!(report.dialauth_record_order_valid);
    assert!(report.juicity_authenticate_header_layout_admitted);
    assert!(report.juicity_auth_uni_stream_write_order_admitted);
    assert!(report.juicity_dialauth_record_over_auth_stream_admitted);

    assert!(!report.juicity_auth_token_live_ekm_admitted);
    assert!(!report.juicity_dialauth_over_h3_admitted);
    assert!(!report.juicity_transport_packet_conn_dataplane_admitted);
    assert!(!report.juicity_stream_packet_conn_dataplane_admitted);
    assert!(!report.juicity_true_quic_h3_dataplane_admitted);
}
