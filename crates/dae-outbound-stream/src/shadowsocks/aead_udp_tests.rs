use super::*;

#[test]
fn udp_scratch_matches_independent_aead_and_retains_packet_salt_keys() {
    for spec in AEAD_CIPHER_SPECS {
        let codec = AeadUdpCodec::new(spec.cipher, "scratch-test").unwrap();
        let mut scratch = Vec::with_capacity(65568 + 32);
        let allocation = scratch.as_ptr();
        for target in ["192.0.2.1:53", "[2001:db8::1]:443", "example.com:53"] {
            let target = Socks5Address::parse(target).unwrap();
            for len in [0, 1, 1500, 65500, 8] {
                for seed in [1, 2] {
                    let salt = vec![seed; spec.salt_len];
                    let payload = vec![5; len];
                    let mut plain = target.encode().unwrap();
                    plain.extend_from_slice(&payload);
                    let encrypted = codec
                        .packet_cipher(&salt)
                        .unwrap()
                        .encrypt(&nonce_from_counter(0), &plain)
                        .unwrap();
                    let expected = [salt.as_slice(), encrypted.as_slice()].concat();
                    codec
                        .encode_packet_into(&salt, &target, &payload, &mut scratch)
                        .unwrap();
                    assert_eq!(scratch, expected);
                    assert_eq!(scratch.as_ptr(), allocation);
                    let decoded = codec.decode_packet(&scratch).unwrap();
                    assert_eq!(decoded.payload, payload);
                    assert_eq!(decoded.target, target.authority());
                    // Each packet must still authenticate under its own salt.
                    scratch[0] ^= 1;
                    assert!(codec.decode_packet(&scratch).is_err());
                }
            }
        }
        assert!(
            codec
                .encode_packet_into(
                    &[0],
                    &Socks5Address::parse("example.com:53").unwrap(),
                    b"",
                    &mut scratch
                )
                .is_err()
        );
    }
}
