use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use super::*;

#[test]
fn case_shadowsocksr_parser_keeps_daenew_base64_and_ipv6_compatibility() {
    let password = URL_SAFE_NO_PAD.encode("fixture-password");
    let remarks = URL_SAFE_NO_PAD.encode("fixture ssr");
    let obfs_param = URL_SAFE_NO_PAD.encode("front.fixture.invalid");
    let direct = format!(
        "ssr://fixture.fixture.invalid:443:origin:aes-128-cfb:http_simple:{password}/?remarks={remarks}&protoparam=&obfsparam={obfs_param}"
    );
    let parsed = shadowsocks::ShadowsocksRLink::parse(&direct).unwrap();
    assert_eq!(parsed.server, "fixture.fixture.invalid");
    assert_eq!(parsed.port, 443);
    assert_eq!(parsed.password, "fixture-password");
    assert_eq!(parsed.cipher, "aes-128-cfb");
    assert_eq!(parsed.proto, "origin");
    assert_eq!(parsed.obfs, "http_simple");
    assert_eq!(parsed.name, "fixture ssr");
    assert_eq!(parsed.obfs_param, "front.fixture.invalid");
    assert_eq!(parsed.protocol, "shadowsocksr");

    let ipv6_content = format!(
        "2001:db8::1:8389:origin:aes-128-cfb:http_simple:{password}/?remarks={remarks}&protoparam=&obfsparam="
    );
    let wrapped = format!("ssr://{}", URL_SAFE_NO_PAD.encode(ipv6_content));
    let ipv6 = shadowsocks::ShadowsocksRLink::parse(&wrapped).unwrap();
    assert_eq!(ipv6.server, "2001:db8::1");
    assert_eq!(ipv6.address(), "[2001:db8::1]:8389");
    assert_eq!(ipv6.password, "fixture-password");
}

#[test]
fn case_shadowsocksr_three_layer_http_simple_aes_cfb_origin_roundtrips_payload() {
    let cipher = "aes-128-cfb";
    let password = "fixture-password";
    let target = "fixture-shadowsocksr.fixture.invalid:9443";
    let payload = b"fixture-shadowsocksr-three-layer-ping".to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let options = shadowsocks::ShadowsocksRThreeLayerOptions::http_simple_origin(
        "fixture-obfs.fixture.invalid",
        endpoint.port(),
        [0x45; 16],
        [0x95; 16],
    );
    let options_for_thread = options.clone();
    let payload_for_server = payload.clone();

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = shadowsocks::read_shadowsocksr_http_simple_request(
            &mut stream,
            cipher,
            password,
            &options_for_thread,
        )
        .unwrap();
        assert_eq!(request.obfs, "http_simple");
        assert_eq!(request.protocol, "origin");
        assert_eq!(request.stream_cipher, "aes-128-cfb");
        assert_eq!(request.stream_iv_len, 16);
        assert_eq!(request.stream_key_len, 16);
        assert_eq!(request.target, target);
        assert_eq!(request.payload, payload_for_server);
        let response = shadowsocks::encode_shadowsocksr_http_simple_response(
            cipher,
            password,
            &options_for_thread.server_iv,
            &request.payload,
        )
        .unwrap();
        stream.write_all(&response).unwrap();
        stream.flush().unwrap();
        request
    });

    let report = shadowsocks::shadowsocksr_three_layer_tcp_exchange_over_stream(
        &mut TcpStream::connect(endpoint).unwrap(),
        &endpoint.to_string(),
        cipher,
        password,
        target,
        &payload,
        &options,
    )
    .unwrap();
    let request = handle.join().unwrap();

    assert_eq!(report.protocol_name, "shadowsocksr");
    assert_eq!(report.obfs, "http_simple");
    assert_eq!(report.protocol, "origin");
    assert_eq!(report.stream_cipher, "aes-128-cfb");
    assert_eq!(report.target, target);
    assert_eq!(report.obfs_host, "fixture-obfs.fixture.invalid");
    assert_eq!(report.obfs_port, endpoint.port());
    assert_eq!(report.stream_iv_len, 16);
    assert_eq!(report.stream_key_len, 16);
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(
        report.obfs_request_payload_len,
        request.obfs_request_payload_len
    );
    assert!(report.obfs_request_head_len >= request.obfs_request_head_len);
    assert!(report.ssr_protocol_addr_len > 0);
    assert!(report.obfs_layer_validated);
    assert!(report.stream_cipher_validated);
    assert!(report.protocol_wrapper_validated);
    assert!(report.three_layer_order_validated);
    assert!(report.true_dataplane);
}
