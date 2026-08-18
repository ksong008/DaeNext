#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use super::super::*;

    #[test]
    fn resident_vless_vision_unpadder_removes_padding_blocks() {
        let key = [
            0x87, 0xe8, 0x7f, 0x74, 0x76, 0xef, 0x5c, 0x4a, 0x90, 0x46, 0x2e, 0x6b, 0x47, 0xef,
            0x76, 0x0a,
        ];
        let mut block = Vec::from(key);
        block.extend_from_slice(&[VISION_COMMAND_CONTINUE, 0, 4, 0, 3]);
        block.extend_from_slice(b"HTTP");
        block.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        block.extend_from_slice(&[VISION_COMMAND_END, 0, 3, 0, 0]);
        block.extend_from_slice(b"/1.");

        let mut unpadder = VisionUnpadder::new(key);
        assert!(unpadder.consume(&block[..7]).unwrap().is_empty());
        let payload = unpadder.consume(&block[7..]).unwrap();
        assert_eq!(payload, b"HTTP/1.");
        assert_eq!(unpadder.completed_blocks, 2);
        assert!(!unpadder.direct_command_seen);
    }

    #[test]
    fn resident_vless_vision_uplink_end_block_is_wrapped_once() {
        let key = [7_u8; 16];
        let payload = [23, 3, 3, 0, 2, 0xaa, 0xbb];
        assert!(tls_application_data_records_complete(&payload));
        assert!(!tls_application_data_records_complete(&payload[..6]));

        let mut uuid_sent = false;
        let block = vision_padding_block(&payload, VISION_COMMAND_END, key, &mut uuid_sent, false);
        assert!(uuid_sent);
        assert_eq!(&block[..16], &key);
        assert_eq!(block[16], VISION_COMMAND_END);
        assert_eq!(
            u16::from_be_bytes([block[17], block[18]]),
            payload.len() as u16
        );
        let padding_len = u16::from_be_bytes([block[19], block[20]]) as usize;
        assert!(padding_len <= 255);
        assert_eq!(&block[21..21 + payload.len()], &payload);
        assert_eq!(block.len(), 21 + payload.len() + padding_len);

        let second = vision_padding_block(
            &payload,
            VISION_COMMAND_CONTINUE,
            key,
            &mut uuid_sent,
            false,
        );
        assert_eq!(second[0], VISION_COMMAND_CONTINUE);
        let second_padding_len = u16::from_be_bytes([second[3], second[4]]) as usize;
        assert_eq!(&second[5..5 + payload.len()], &payload);
        assert_eq!(second.len(), 5 + payload.len() + second_padding_len);
    }

    #[test]
    fn resident_vless_vision_long_padding_matches_compatible_floor() {
        let key = [9_u8; 16];
        let payload = [22, 3, 1, 0, 2, 0x01, 0x00];
        let mut uuid_sent = false;

        let block =
            vision_padding_block(&payload, VISION_COMMAND_CONTINUE, key, &mut uuid_sent, true);

        let padding_len = u16::from_be_bytes([block[19], block[20]]) as usize;
        assert!((900 - payload.len()..900 - payload.len() + 500).contains(&padding_len));
    }

    #[test]
    fn resident_vless_vision_uplink_parses_ccs_before_direct_record() {
        let mut pending = vec![20, 3, 3, 0, 1, 1, 23, 3, 3, 0, 2, 0xaa, 0xbb];

        let (ty, record) = pop_complete_tls_record(&mut pending).unwrap().unwrap();
        assert_eq!(ty, 20);
        assert_eq!(record, [20, 3, 3, 0, 1, 1]);

        let (ty, record) = pop_complete_tls_record(&mut pending).unwrap().unwrap();
        assert_eq!(ty, 23);
        assert_eq!(record, [23, 3, 3, 0, 2, 0xaa, 0xbb]);
        assert!(pending.is_empty());
    }

    #[test]
    fn resident_vless_vision_uplink_accepts_client_hello_legacy_record_version() {
        let mut pending = vec![22, 3, 1, 0, 2, 0x01, 0x00];

        let (ty, record) = pop_complete_tls_record(&mut pending).unwrap().unwrap();
        assert_eq!(ty, 22);
        assert_eq!(record, [22, 3, 1, 0, 2, 0x01, 0x00]);
        assert!(pending.is_empty());
    }

    #[test]
    fn resident_vless_vision_tls_prefix_rejects_short_non_tls_mtproto() {
        assert!(!could_be_tls_record_prefix(&[0xef]));
        assert!(!looks_like_tls_record_start(&[0xef, 0xef, 0xef, 0xef]));
        assert!(could_be_tls_record_prefix(&[22]));
        assert!(could_be_tls_record_prefix(&[22, 3, 3]));
        assert!(looks_like_tls_record_start(&[22, 3, 3, 0, 1]));
    }

    #[test]
    fn resident_vless_vision_non_tls_after_first_block_does_not_wait_on_fake_appdata_prefix() {
        let mut state = VisionInnerTlsState::new();
        state
            .observe_client_payload(&[0xee, 0xee, 0xee, 0xee])
            .unwrap();

        assert!(!state.client_tls_filter_active());
        assert!(!should_continue_vision_tls_filtering(
            &[23, 3, 3, 0, 2, 0xaa, 0xbb],
            &state
        ));
    }

    #[test]
    fn resident_vless_vision_observed_tls_allows_application_data_filtering() {
        let mut state = VisionInnerTlsState::new();
        state.client_tls_observed = true;

        assert!(state.client_tls_filter_active());
        assert!(should_continue_vision_tls_filtering(
            &[23, 3, 3, 0, 2, 0xaa, 0xbb],
            &state
        ));
    }

    #[test]
    fn resident_vless_vision_inner_tls_parser_admits_tls13_server_hello() {
        let mut state = VisionInnerTlsState::new();
        let server_hello = tls13_server_hello_record(0x1301, true);

        state.observe_server_payload(&server_hello).unwrap();

        assert_eq!(
            vision_uplink_command(TLS_CONTENT_TYPE_APPLICATION_DATA, &state),
            Some(VISION_COMMAND_DIRECT)
        );
    }

    #[test]
    fn resident_vless_vision_inner_tls_parser_rejects_tls12_server_hello() {
        let mut state = VisionInnerTlsState::new();
        let server_hello = tls13_server_hello_record(0x1301, false);

        state.observe_server_payload(&server_hello).unwrap();

        assert_eq!(
            vision_uplink_command(TLS_CONTENT_TYPE_APPLICATION_DATA, &state),
            Some(VISION_COMMAND_END)
        );
    }

    #[test]
    fn resident_vless_vision_waits_for_native_tls13_decision_before_direct() {
        let state = VisionInnerTlsState::new();

        assert_eq!(
            vision_uplink_command(TLS_CONTENT_TYPE_APPLICATION_DATA, &state),
            None
        );
    }

    fn tls13_server_hello_record(cipher_suite: u16, selected_tls13: bool) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0);

        let mut extensions = Vec::new();
        if selected_tls13 {
            extensions.extend_from_slice(&TLS_EXTENSION_SUPPORTED_VERSIONS.to_be_bytes());
            extensions.extend_from_slice(&2_u16.to_be_bytes());
            extensions.extend_from_slice(&TLS_VERSION_1_3.to_be_bytes());
        }
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(TLS_HANDSHAKE_TYPE_SERVER_HELLO);
        handshake.extend_from_slice(&u24_bytes(body.len()));
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(TLS_CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn u24_bytes(len: usize) -> [u8; 3] {
        [
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ]
    }
}
