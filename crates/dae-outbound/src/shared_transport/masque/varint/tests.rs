use super::*;

#[test]
fn boundary_values_roundtrip_with_minimal_encoding() {
    for (value, expected_len) in [
        (0, 1),
        (63, 1),
        (64, 2),
        (16_383, 2),
        (16_384, 4),
        (1_073_741_823, 4),
        (1_073_741_824, 8),
        ((1_u64 << 62) - 1, 8),
    ] {
        let mut encoded = Vec::new();
        assert_eq!(
            encode_quic_varint(value, &mut encoded).unwrap(),
            expected_len
        );
        assert_eq!(encoded.len(), expected_len);
        assert_eq!(decode_quic_varint_exact(&encoded).unwrap(), value);
    }
}

#[test]
fn decoder_accepts_valid_non_minimal_wire_lengths() {
    assert_eq!(decode_quic_varint_exact(&[0x40, 0x01]).unwrap(), 1);
    assert_eq!(decode_quic_varint_exact(&[0x80, 0, 0, 1]).unwrap(), 1);
    assert_eq!(
        decode_quic_varint_exact(&[0xc0, 0, 0, 0, 0, 0, 0, 1]).unwrap(),
        1
    );
}

#[test]
fn prefix_decoder_waits_for_every_encoded_byte() {
    for value in [64, 16_384, 1_073_741_824] {
        let mut encoded = Vec::new();
        encode_quic_varint(value, &mut encoded).unwrap();
        for prefix_len in 0..encoded.len() {
            assert_eq!(
                decode_quic_varint_prefix(&encoded[..prefix_len]).unwrap(),
                None
            );
        }
        assert_eq!(
            decode_quic_varint_prefix(&encoded).unwrap(),
            Some((value, encoded.len()))
        );
    }
}

#[test]
fn overflow_truncation_and_trailing_bytes_are_rejected() {
    assert_eq!(
        encode_quic_varint(1_u64 << 62, &mut Vec::new()).unwrap_err(),
        MasqueCodecError::VarIntOverflow(1_u64 << 62)
    );
    assert_eq!(
        decode_quic_varint_exact(&[0x40]).unwrap_err(),
        MasqueCodecError::TruncatedVarInt
    );
    assert_eq!(
        decode_quic_varint_exact(&[0x01, 0x00]).unwrap_err(),
        MasqueCodecError::TrailingVarIntBytes(1)
    );
}

#[test]
fn deterministic_value_corpus_preserves_every_decoded_integer() {
    let mut encoded = Vec::with_capacity(8);
    for value in 0..=u16::MAX as u64 {
        encoded.clear();
        encode_quic_varint(value, &mut encoded).unwrap();
        assert_eq!(decode_quic_varint_exact(&encoded).unwrap(), value);
    }

    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for _ in 0..10_000 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let value = state & ((1_u64 << 62) - 1);
        encoded.clear();
        encode_quic_varint(value, &mut encoded).unwrap();
        assert_eq!(decode_quic_varint_exact(&encoded).unwrap(), value);
    }
}
