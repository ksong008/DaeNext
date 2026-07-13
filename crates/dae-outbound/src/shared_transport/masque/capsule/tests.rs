use super::*;

fn limits() -> MasqueCapsuleLimits {
    MasqueCapsuleLimits::new(4096, 2048, 1500).unwrap()
}

#[test]
fn datagram_capsule_roundtrips_one_byte_at_a_time() {
    let payload = b"connect-udp-capsule";
    let encoded = encode_connect_udp_capsule(payload, limits()).unwrap();
    let mut decoder = MasqueCapsuleDecoder::new(limits());
    let mut decoded = Vec::new();
    for byte in encoded {
        decoded.extend(decoder.push(&[byte]).unwrap());
    }
    assert_eq!(
        decoded,
        [MasqueCapsule::Datagram(Bytes::from_static(payload))]
    );
    assert_eq!(decoder.buffered_len(), 0);
    decoder.finish().unwrap();
}

#[test]
fn multiple_capsules_and_unknown_types_preserve_boundaries() {
    let mut wire = encode_unknown_capsule(42, b"ignore", limits()).unwrap();
    wire.extend_from_slice(&encode_connect_udp_capsule(b"first", limits()).unwrap());
    wire.extend_from_slice(&encode_connect_udp_capsule(b"second", limits()).unwrap());
    let mut decoder = MasqueCapsuleDecoder::new(limits());
    assert_eq!(
        decoder.push(&wire).unwrap(),
        [
            MasqueCapsule::Unknown {
                capsule_type: 42,
                payload: Bytes::from_static(b"ignore"),
            },
            MasqueCapsule::Datagram(Bytes::from_static(b"first")),
            MasqueCapsule::Datagram(Bytes::from_static(b"second")),
        ]
    );
}

#[test]
fn unknown_context_and_truncated_context_fail_closed() {
    let mut unknown_context = Vec::new();
    encode_quic_varint(CONNECT_UDP_CAPSULE_TYPE, &mut unknown_context).unwrap();
    encode_quic_varint(2, &mut unknown_context).unwrap();
    encode_quic_varint(1, &mut unknown_context).unwrap();
    unknown_context.push(7);
    let mut decoder = MasqueCapsuleDecoder::new(limits());
    assert_eq!(
        decoder.push(&unknown_context).unwrap_err(),
        MasqueCodecError::UnsupportedContextId(1)
    );

    let mut empty_datagram_capsule = Vec::new();
    encode_quic_varint(CONNECT_UDP_CAPSULE_TYPE, &mut empty_datagram_capsule).unwrap();
    encode_quic_varint(0, &mut empty_datagram_capsule).unwrap();
    let mut decoder = MasqueCapsuleDecoder::new(limits());
    assert_eq!(
        decoder.push(&empty_datagram_capsule).unwrap_err(),
        MasqueCodecError::TruncatedVarInt
    );
}

#[test]
fn declared_and_received_sizes_are_bounded_before_allocation() {
    let small = MasqueCapsuleLimits::new(64, 32, 16).unwrap();
    assert!(matches!(
        encode_connect_udp_capsule(&[0; 17], small),
        Err(MasqueCodecError::DatagramPayloadLimitExceeded { .. })
    ));

    let mut declared_oversized = Vec::new();
    encode_quic_varint(CONNECT_UDP_CAPSULE_TYPE, &mut declared_oversized).unwrap();
    encode_quic_varint(33, &mut declared_oversized).unwrap();
    let mut decoder = MasqueCapsuleDecoder::new(small);
    assert!(matches!(
        decoder.push(&declared_oversized),
        Err(MasqueCodecError::CapsulePayloadLimitExceeded { .. })
    ));

    let mut decoder = MasqueCapsuleDecoder::new(small);
    assert!(matches!(
        decoder.push(&[0; 65]),
        Err(MasqueCodecError::BufferLimitExceeded { .. })
    ));
}

#[test]
fn stream_end_rejects_partial_capsules() {
    let encoded = encode_connect_udp_capsule(b"partial", limits()).unwrap();
    let mut decoder = MasqueCapsuleDecoder::new(limits());
    assert!(
        decoder
            .push(&encoded[..encoded.len() - 1])
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        decoder.finish().unwrap_err(),
        MasqueCodecError::TruncatedCapsule(encoded.len() - 1)
    );
}

#[test]
fn invalid_limit_relationships_are_rejected() {
    assert!(MasqueCapsuleLimits::new(0, 1, 1).is_err());
    assert!(MasqueCapsuleLimits::new(64, 16, 16).is_err());
}

#[test]
fn every_two_chunk_boundary_preserves_capsule_framing() {
    let payload = (0..=255).collect::<Vec<u8>>();
    let encoded = encode_connect_udp_capsule(&payload, limits()).unwrap();
    for split in 0..=encoded.len() {
        let mut decoder = MasqueCapsuleDecoder::new(limits());
        let mut decoded = decoder.push(&encoded[..split]).unwrap();
        decoded.extend(decoder.push(&encoded[split..]).unwrap());
        assert_eq!(
            decoded,
            [MasqueCapsule::Datagram(Bytes::copy_from_slice(&payload))],
            "split={split}"
        );
        decoder.finish().unwrap();
    }
}
