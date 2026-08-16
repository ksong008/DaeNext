use super::*;

#[test]
fn in_place_sealing_matches_allocating_wire_for_all_body_modes() {
    let key = *b"dae-vmess-key!!!";
    let iv = *b"dae-vmess-aead!!";
    for (security, options) in [
        (
            VMESS_AEAD_SECURITY_AES_128_GCM,
            OPTION_CHUNK_STREAM | OPTION_CHUNK_LENGTH_MASKING,
        ),
        (
            VMESS_AEAD_SECURITY_CHACHA20_POLY1305,
            OPTION_CHUNK_STREAM | OPTION_CHUNK_LENGTH_MASKING,
        ),
        (
            VMESS_AEAD_SECURITY_NONE,
            OPTION_CHUNK_STREAM | OPTION_CHUNK_LENGTH_MASKING,
        ),
        (VMESS_AEAD_SECURITY_NONE, 0),
    ] {
        let mut allocating = BodyCodec::new(key, iv, security, options).unwrap();
        let mut in_place = BodyCodec::new(key, iv, security, options).unwrap();
        let mut buffer = [0_u8; VMESS_AEAD_TCP_UPLOAD_BUFFER_SIZE];
        for payload_len in [1, 17, MAX_CHUNK_SIZE] {
            let payload = vec![payload_len as u8; payload_len];
            let expected = allocating.seal_chunk(&payload).unwrap();
            in_place.chunk_payload_buffer(&mut buffer)[..payload_len].copy_from_slice(&payload);
            let wire_len = in_place
                .seal_chunk_in_place(&mut buffer, payload_len)
                .unwrap();
            assert_eq!(&buffer[..wire_len], expected);
        }
    }
}

#[test]
fn in_place_opening_matches_allocating_wire_for_all_body_modes() {
    let key = *b"dae-vmess-key!!!";
    let iv = *b"dae-vmess-aead!!";
    for (security, options) in [
        (
            VMESS_AEAD_SECURITY_AES_128_GCM,
            OPTION_CHUNK_STREAM | OPTION_CHUNK_LENGTH_MASKING,
        ),
        (
            VMESS_AEAD_SECURITY_CHACHA20_POLY1305,
            OPTION_CHUNK_STREAM | OPTION_CHUNK_LENGTH_MASKING,
        ),
        (
            VMESS_AEAD_SECURITY_NONE,
            OPTION_CHUNK_STREAM | OPTION_CHUNK_LENGTH_MASKING,
        ),
        (VMESS_AEAD_SECURITY_NONE, 0),
    ] {
        let payloads = [vec![0x11; 1], vec![0x22; 4097], vec![0x33; MAX_CHUNK_SIZE]];
        let mut encoder = BodyCodec::new(key, iv, security, options).unwrap();
        let mut wire = Vec::new();
        for payload in &payloads {
            wire.extend_from_slice(&encoder.seal_chunk(payload).unwrap());
        }

        let mut decoder = BodyCodec::new(key, iv, security, options).unwrap();
        let mut cursor = 0;
        let mut pending = None;
        let mut decoded = Vec::new();
        while let Some(payload) = decoder
            .try_open_chunk_in_place_from_buffer(&mut wire, &mut cursor, &mut pending)
            .unwrap()
        {
            decoded.extend_from_slice(&wire[payload]);
        }

        let expected = payloads.concat();
        assert_eq!(decoded, expected);
        assert_eq!(cursor, wire.len());
        assert!(pending.is_none());
    }
}

#[test]
fn chunk_nonce_errors_instead_of_wrapping_when_counter_exhausted() {
    let mut nonce = ChunkNonce::new(&[0x5a; 16]);
    for _ in 0..=u16::MAX {
        assert!(
            nonce.next().is_ok(),
            "all 65,536 distinct u16 nonce values must be usable once"
        );
    }
    let err = nonce
        .next()
        .expect_err("VMess chunk nonce counter must error instead of wrapping");
    assert!(err.to_string().contains("nonce exhausted"));

    // Direct boundary construction: a counter already at u16::MAX fails immediately.
    let mut at_max = ChunkNonce {
        base: [0_u8; 12],
        count: u32::from(u16::MAX) + 1,
    };
    assert!(at_max.next().is_err());
}
