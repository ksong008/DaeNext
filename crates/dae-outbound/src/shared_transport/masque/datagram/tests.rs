use super::*;

#[test]
fn request_stream_ids_roundtrip_through_quarter_stream_ids() {
    for stream_id in [0, 4, 8, 1_048_576, MAX_HTTP3_REQUEST_STREAM_ID] {
        let quarter = MasqueQuarterStreamId::from_http3_stream_id(stream_id).unwrap();
        assert_eq!(quarter.http3_stream_id(), stream_id);
    }
    for invalid in [1, 2, 3, 5, (1_u64 << 62) - 1] {
        assert!(MasqueQuarterStreamId::from_http3_stream_id(invalid).is_err());
    }
}

#[test]
fn http_datagram_roundtrips_without_losing_stream_identity() {
    let quarter = MasqueQuarterStreamId::from_http3_stream_id(12).unwrap();
    let encoded = encode_http_datagram(quarter, b"payload", 1200).unwrap();
    assert_eq!(
        decode_http_datagram(Bytes::from(encoded), 1200).unwrap(),
        MasqueHttpDatagram {
            quarter_stream_id: quarter,
            payload: Bytes::from_static(b"payload"),
        }
    );
}

#[test]
fn unknown_context_truncation_and_oversize_fail_closed() {
    let quarter = MasqueQuarterStreamId::from_http3_stream_id(0).unwrap();
    let mut unknown_context = Vec::new();
    encode_quic_varint(quarter.value(), &mut unknown_context).unwrap();
    encode_quic_varint(9, &mut unknown_context).unwrap();
    unknown_context.push(1);
    assert_eq!(
        decode_http_datagram(Bytes::from(unknown_context), 1200).unwrap_err(),
        MasqueCodecError::UnsupportedContextId(9)
    );

    assert_eq!(
        decode_http_datagram(Bytes::from_static(&[0x40]), 1200).unwrap_err(),
        MasqueCodecError::TruncatedVarInt
    );
    assert!(matches!(
        encode_http_datagram(quarter, &[0; 1201], 1200),
        Err(MasqueCodecError::DatagramPayloadLimitExceeded { .. })
    ));
}

#[test]
fn near_limit_datagram_is_admitted_exactly_at_the_boundary() {
    let quarter = MasqueQuarterStreamId::from_http3_stream_id(4).unwrap();
    let payload = vec![7_u8; 1232];
    let encoded = encode_http_datagram(quarter, &payload, payload.len()).unwrap();
    let decoded = decode_http_datagram(Bytes::from(encoded), payload.len()).unwrap();
    assert_eq!(decoded.payload.as_ref(), payload.as_slice());
}

#[test]
fn deterministic_stream_and_payload_corpus_roundtrips() {
    for index in 0..4096_u64 {
        let quarter = MasqueQuarterStreamId::from_http3_stream_id(index * 4).unwrap();
        let payload_len = (index as usize) % 257;
        let payload = vec![(index & 0xff) as u8; payload_len];
        let encoded = encode_http_datagram(quarter, &payload, 256).unwrap();
        let decoded = decode_http_datagram(Bytes::from(encoded), 256).unwrap();
        assert_eq!(decoded.quarter_stream_id, quarter);
        assert_eq!(decoded.payload.as_ref(), payload.as_slice());
    }
}
