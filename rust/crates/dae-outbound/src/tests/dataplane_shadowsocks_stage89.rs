use super::*;

#[test]
fn stage89_ss2022_tcp_multi_psk_identity_header_roundtrips_payload() {
    let cipher = "2022-blake3-aes-128-gcm";
    let password = "AQIDBAUGBwgJCgsMDQ4PEA==:ERITFBUWFxgZGhscHR4fIA==";
    let target = "stage89-ss2022-multi-psk.example:8443";
    let payload = b"stage89-ss2022-multi-psk-ping".to_vec();
    let conf = shadowsocks::ss2022::cipher_conf(cipher).unwrap();
    let client_salt = salt_for(conf.salt_len, 0x51);
    let server_salt = salt_for(conf.salt_len, 0xa1);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let payload_for_server = payload.clone();
    let server_salt_for_thread = server_salt.clone();
    let client_salt_for_thread = client_salt.clone();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = shadowsocks::read_ss2022_tcp_multi_psk_client_request_from_stream(
            &mut stream,
            cipher,
            password,
            payload_for_server.len(),
        )
        .unwrap();
        assert_eq!(request.target, target);
        assert_eq!(
            request.request_header_type,
            shadowsocks::ss2022::HEADER_TYPE_CLIENT_STREAM
        );
        assert_eq!(request.fixed_header_len, 11);
        assert_eq!(request.request_salt_len, conf.salt_len);
        assert_eq!(request.psk_count, 2);
        assert_eq!(request.upsk_index, 1);
        assert_eq!(request.identity_header_count, 1);
        assert_eq!(request.identity_header_bytes_len, 16);
        assert!(request.identity_header_validated);
        assert_eq!(request.padding_len, 0);
        assert_eq!(request.payload, payload_for_server);
        let response = shadowsocks::encode_ss2022_tcp_multi_psk_server_response(
            cipher,
            password,
            &server_salt_for_thread,
            &client_salt_for_thread,
            &request.payload,
            1_765_000_089,
        )
        .unwrap();
        stream.write_all(&response).unwrap();
        request
    });

    let report = shadowsocks::ss2022_tcp_multi_psk_exchange_over_stream(
        &mut TcpStream::connect(&endpoint).unwrap(),
        &endpoint,
        cipher,
        password,
        target,
        &payload,
        shadowsocks::Ss2022TcpSalts {
            client: &client_salt,
            server: &server_salt,
        },
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.cipher, cipher);
    assert_eq!(report.psk_count, 2);
    assert_eq!(report.upsk_index, 1);
    assert_eq!(report.key_len, 16);
    assert_eq!(report.client_salt_len, conf.salt_len);
    assert_eq!(report.server_salt_len, conf.salt_len);
    assert_eq!(
        report.request_header_type,
        shadowsocks::ss2022::HEADER_TYPE_CLIENT_STREAM
    );
    assert_eq!(
        report.response_header_type,
        shadowsocks::ss2022::HEADER_TYPE_SERVER_STREAM
    );
    assert!(report.request_salt_echo_validated);
    assert_eq!(report.identity_header_count, 1);
    assert_eq!(report.identity_header_bytes_len, 16);
    assert!(report.identity_header_validated);
    assert!(report.multi_psk_identity_header_dataplane_admitted);
    assert!(!report.ss2022_udp_true_dataplane_admitted);
    assert_eq!(report.target, target);
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(accepted.target, target);
}

#[test]
fn stage89_ss2022_tcp_multi_psk_requires_multiple_psks() {
    let cipher = "2022-blake3-aes-128-gcm";
    let password = "AQIDBAUGBwgJCgsMDQ4PEA==";
    let err = shadowsocks::encode_ss2022_tcp_multi_psk_client_initial(
        cipher,
        password,
        &[0x51; 16],
        "stage89-ss2022-multi-psk.example:8443",
        b"ping",
        1_765_000_089,
    )
    .unwrap_err();
    assert!(err.to_string().contains("at least two PSKs"));
}

fn salt_for(len: usize, base: u8) -> Vec<u8> {
    (0..len)
        .map(|offset| base.wrapping_add(offset as u8))
        .collect()
}
