use super::*;

#[test]
fn case_wss_inner_shadowsocks_frame_roundtrip_decodes_trojanc_request() {
    let cipher = "aes-128-gcm";
    let ss_password = "fixture-ss-password";
    let trojan_password = "fixture-trojan-password";
    let target = "fixture-target.fixture.invalid:443";
    let payload = b"fixture-wss-inner-ss-ping";
    let client_salt = [0x31; 16];

    let frame = trojan::trojan_wss_inner_shadowsocks_request_frame(
        cipher,
        ss_password,
        trojan_password,
        target,
        payload,
        &client_salt,
    )
    .unwrap();
    let request = trojan::read_inner_shadowsocks_trojan_request_from_websocket_stream(
        &mut std::io::Cursor::new(frame),
        cipher,
        ss_password,
        payload.len(),
    )
    .unwrap();

    assert_eq!(request.request.target, target);
    assert_eq!(request.request.payload, payload);
    assert_eq!(
        request.request.password_sha224_hex,
        trojan::packet::password_sha224_hex(trojan_password)
    );
    assert!(!request.inner_shadowsocks_is_client);
    assert!(!request.inner_shadowsocks_request_metadata_present);
}

#[test]
fn case_wss_inner_shadowsocks_response_frame_is_websocket_binary_payload() {
    let cipher = "aes-128-gcm";
    let ss_password = "fixture-ss-password";
    let response_metadata_target = "";
    let payload = b"fixture-wss-inner-ss-response";
    let server_salt = [0x91; 16];

    let frame = trojan::trojan_wss_inner_shadowsocks_response_frame(
        cipher,
        ss_password,
        &server_salt,
        response_metadata_target,
        payload,
    )
    .unwrap();
    let response_payload =
        shared_transport::read_websocket_binary_frame(&mut std::io::Cursor::new(frame)).unwrap();
    assert!(response_payload.starts_with(&server_salt));
    assert!(response_payload.len() > payload.len() + server_salt.len());
}
