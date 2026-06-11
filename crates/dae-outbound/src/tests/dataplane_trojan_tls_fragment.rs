use super::*;

fn tls_handshake_record(payload_len: usize, trailing: &[u8]) -> Vec<u8> {
    let mut record = vec![shared_transport::TLS_HANDSHAKE_CONTENT_TYPE, 0x03, 0x03];
    record.extend_from_slice(&(payload_len as u16).to_be_bytes());
    record.extend((0..payload_len).map(|index| (index % 251) as u8));
    record.extend_from_slice(trailing);
    record
}

#[test]
fn case_tls_fragment_splits_and_reassembles_handshake_record() {
    let options = shared_transport::TlsFragmentOptions::from_ranges("16-16", "0-0").unwrap();
    let input = tls_handshake_record(50, b"after-record");
    let fragmented = shared_transport::fragment_tls_write(&input, &options).unwrap();

    assert!(fragmented.report.fragmented);
    assert!(fragmented.report.handshake_record_fragmented);
    assert!(fragmented.report.reassembled_record_matches);
    assert_eq!(fragmented.report.original_payload_len, 50);
    assert_eq!(fragmented.report.trailing_len, b"after-record".len());
    assert_eq!(fragmented.report.fragment_payload_lens, vec![16, 16, 16, 2]);
    assert_eq!(fragmented.report.fragment_record_count, 4);

    let mut offset = 0;
    let mut reassembled = Vec::new();
    for payload_len in &fragmented.report.fragment_payload_lens {
        assert_eq!(
            fragmented.bytes[offset],
            shared_transport::TLS_HANDSHAKE_CONTENT_TYPE
        );
        assert_eq!(&fragmented.bytes[offset + 1..offset + 3], &[0x03, 0x03]);
        let record_len =
            u16::from_be_bytes([fragmented.bytes[offset + 3], fragmented.bytes[offset + 4]])
                as usize;
        assert_eq!(record_len, *payload_len);
        reassembled.extend_from_slice(
            &fragmented.bytes[offset + shared_transport::TLS_RECORD_HEADER_LEN
                ..offset + shared_transport::TLS_RECORD_HEADER_LEN + record_len],
        );
        offset += shared_transport::TLS_RECORD_HEADER_LEN + record_len;
    }
    assert_eq!(
        &reassembled,
        &input[shared_transport::TLS_RECORD_HEADER_LEN..55]
    );
    assert_eq!(&fragmented.bytes[offset..], b"after-record");
}

#[test]
fn case_tls_fragment_preserves_passthrough_boundaries() {
    let options = shared_transport::TlsFragmentOptions::from_ranges("8-8", "0-0").unwrap();
    let app_data = [23, 0x03, 0x03, 0, 3, 1, 2, 3];
    let pass = shared_transport::fragment_tls_write(&app_data, &options).unwrap();
    assert!(!pass.report.fragmented);
    assert!(pass.report.passthrough);
    assert_eq!(pass.report.passthrough_reason, Some("not-handshake-record"));
    assert_eq!(pass.bytes, app_data);

    let incomplete = [22, 0x03, 0x03, 0, 8, 1, 2, 3];
    let pass = shared_transport::fragment_tls_write(&incomplete, &options).unwrap();
    assert!(!pass.report.fragmented);
    assert!(pass.report.passthrough);
    assert_eq!(
        pass.report.passthrough_reason,
        Some("incomplete-handshake-record")
    );
    assert_eq!(pass.bytes, incomplete);

    let short = [22, 0x03, 0x03, 0, 1];
    let pass = shared_transport::fragment_tls_write(&short, &options).unwrap();
    assert!(!pass.report.fragmented);
    assert!(pass.report.passthrough);
    assert_eq!(pass.report.passthrough_reason, Some("short-write"));
    assert_eq!(pass.bytes, short);
}

#[test]
fn case_tls_fragment_range_parser_matches_native_error_boundary() {
    assert_eq!(
        shared_transport::parse_tls_fragment_range("50-100").unwrap(),
        (50, 100)
    );
    let err = shared_transport::parse_tls_fragment_range("50").unwrap_err();
    assert!(err.to_string().contains("invalid range: 50"));
}
