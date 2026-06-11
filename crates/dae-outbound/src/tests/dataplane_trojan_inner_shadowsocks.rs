use super::*;

#[test]
fn case_trojan_inner_shadowsocks_wraps_raw_trojanc_without_ss_request_metadata() {
    let cipher = "aes-256-gcm";
    let shadowsocks_password = "fixture-ss-password";
    let trojan_password = "fixture-trojan-password";
    let target = "fixture-trojan-inner-ss.fixture.invalid:443";
    let response_metadata_target = "";
    let payload = b"fixture-trojan-inner-shadowsocks-ping".to_vec();
    let spec = shadowsocks::cipher_spec(cipher).unwrap();
    let client_salt = salt_for(spec.salt_len, 0x31);
    let server_salt = salt_for(spec.salt_len, 0x91);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let server_payload = payload.clone();
    let server_salt_for_thread = server_salt.clone();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = trojan::read_inner_shadowsocks_trojan_request_from_stream(
            &mut stream,
            cipher,
            shadowsocks_password,
            server_payload.len(),
        )
        .unwrap();
        assert_eq!(
            request.request.password_sha224_hex,
            trojan::packet::password_sha224_hex(trojan_password)
        );
        assert_eq!(request.request.command, trojan::TrojanNetwork::Tcp.byte());
        assert_eq!(request.request.target, target);
        assert_eq!(request.request.payload, server_payload);
        assert!(!request.inner_shadowsocks_is_client);
        assert!(!request.inner_shadowsocks_request_metadata_present);
        let response = trojan::encode_inner_shadowsocks_response(
            cipher,
            shadowsocks_password,
            &server_salt_for_thread,
            response_metadata_target,
            &request.request.payload,
        )
        .unwrap();
        stream.write_all(&response).unwrap();
        request
    });

    let report = trojan::tcp_exchange_over_inner_shadowsocks_stream(
        &mut TcpStream::connect(&endpoint).unwrap(),
        &endpoint,
        cipher,
        shadowsocks_password,
        trojan_password,
        target,
        response_metadata_target,
        &payload,
        shadowsocks::AeadTcpSalts {
            client: &client_salt,
            server: &server_salt,
        },
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.trojan_inner_shadowsocks);
    assert_eq!(report.cipher, cipher);
    assert_eq!(report.client_salt_len, spec.salt_len);
    assert_eq!(report.server_salt_len, spec.salt_len);
    assert!(!report.inner_shadowsocks_is_client);
    assert!(!report.inner_shadowsocks_request_metadata_present);
    assert_eq!(report.server_response_metadata, "");
    assert_eq!(
        report.password_sha224_hex,
        trojan::packet::password_sha224_hex(trojan_password)
    );
    assert_eq!(report.command, trojan::TrojanNetwork::Tcp.byte());
    assert_eq!(report.target, target);
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.echoed_payload, payload);
    assert!(report.shadowsocks_chunk_validated);
    assert!(report.shadowsocks_request_len > report.trojan_request_header_len);
    assert_eq!(report.shadowsocks_response_metadata_len, 0);
    assert_eq!(accepted.request.payload, payload);
    assert!(!accepted.inner_shadowsocks_request_metadata_present);
}

fn salt_for(len: usize, base: u8) -> Vec<u8> {
    (0..len)
        .map(|offset| base.wrapping_add(offset as u8))
        .collect()
}
