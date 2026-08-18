use super::*;
use std::io::Cursor;

#[test]
fn case_ss2022_tcp_single_psk_roundtrips_payload() {
    let cipher = "2022-blake3-aes-256-gcm";
    let password = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    let target = "fixture-ss2022.fixture.invalid:443";
    let payload = b"fixture-ss2022-tcp-ping".to_vec();
    let conf = shadowsocks::ss2022::cipher_conf(cipher).unwrap();
    let client_salt = salt_for(conf.salt_len, 0x41);
    let server_salt = salt_for(conf.salt_len, 0x81);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let payload_for_server = payload.clone();
    let server_salt_for_thread = server_salt.clone();
    let client_salt_for_thread = client_salt.clone();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = shadowsocks::read_ss2022_tcp_client_request_from_stream(
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
        assert_eq!(request.psk_count, 1);
        assert_eq!(request.upsk_index, 0);
        assert_eq!(request.padding_len, 0);
        assert_eq!(request.payload, payload_for_server);
        let response = shadowsocks::encode_ss2022_tcp_server_response(
            cipher,
            password,
            &server_salt_for_thread,
            &client_salt_for_thread,
            &request.payload,
            1_765_000_088,
        )
        .unwrap();
        stream.write_all(&response).unwrap();
        request
    });

    let report = shadowsocks::ss2022_tcp_exchange_over_stream(
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
    assert_eq!(report.cipher, cipher);
    assert_eq!(report.psk_count, 1);
    assert_eq!(report.upsk_index, 0);
    assert_eq!(report.key_len, 32);
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
    assert_eq!(report.target, target);
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.echoed_payload, payload);
    assert!(!report.multi_psk_identity_header_dataplane_admitted);
    assert!(!report.ss2022_udp_true_dataplane_admitted);
    assert_eq!(accepted.target, target);
}

#[test]
fn ss2022_client_stream_encoder_roundtrips_large_initial_payload() {
    let cipher = "2022-blake3-aes-128-gcm";
    let password = "AQIDBAUGBwgJCgsMDQ4PEA==";
    let target = "ss2022.fixture.invalid:443";
    let conf = shadowsocks::ss2022::cipher_conf(cipher).unwrap();
    let client_salt = salt_for(conf.salt_len, 0x31);
    let payload = vec![0x5a; shadowsocks::ss2022::TCP_CHUNK_MAX_LEN + 128];
    let (_encoder, initial) = shadowsocks::ss2022_tcp_client_stream_encoder(
        cipher,
        password,
        &client_salt,
        target,
        &payload,
        shadowsocks::ss2022_tcp_unix_timestamp_now(),
    )
    .unwrap();
    let request = shadowsocks::read_ss2022_tcp_client_request_from_stream(
        &mut Cursor::new(initial),
        cipher,
        password,
        payload.len(),
    )
    .unwrap();

    assert_eq!(request.target, target);
    assert_eq!(request.request_salt_len, conf.salt_len);
    assert_eq!(request.payload, payload);
    assert_eq!(request.identity_header_count, 0);
}

#[test]
fn ss2022_server_stream_decoder_reads_initial_response() {
    let cipher = "2022-blake3-aes-128-gcm";
    let password = "AQIDBAUGBwgJCgsMDQ4PEA==";
    let conf = shadowsocks::ss2022::cipher_conf(cipher).unwrap();
    let request_salt = salt_for(conf.salt_len, 0x41);
    let server_salt = salt_for(conf.salt_len, 0x81);
    let payload = b"ss2022-response".to_vec();
    let response = shadowsocks::encode_ss2022_tcp_server_response(
        cipher,
        password,
        &server_salt,
        &request_salt,
        &payload,
        1_765_000_288,
    )
    .unwrap();
    let (_decoder, start) = shadowsocks::ss2022_tcp_server_stream_decoder(
        &mut Cursor::new(response),
        cipher,
        password,
        &request_salt,
    )
    .unwrap();

    assert_eq!(start.server_salt_len, conf.salt_len);
    assert!(start.request_salt_echo_validated);
    assert_eq!(start.payload, payload);
}

#[test]
fn case_ss2022_tcp_keeps_multi_psk_identity_header_gated() {
    let cipher = "2022-blake3-aes-128-gcm";
    let password = "AQIDBAUGBwgJCgsMDQ4PEA==:ERITFBUWFxgZGhscHR4fIA==";
    let err = shadowsocks::encode_ss2022_tcp_client_initial(
        cipher,
        password,
        &[0x41; 16],
        "fixture-ss2022.fixture.invalid:443",
        b"ping",
        1_765_000_088,
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("multi-PSK identity header remains gated")
    );
}

fn salt_for(len: usize, base: u8) -> Vec<u8> {
    (0..len)
        .map(|offset| base.wrapping_add(offset as u8))
        .collect()
}
