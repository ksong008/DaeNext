use super::*;

#[test]
fn base_socks5_tcp_dataplane_echoes_payload() {
    let fixture = fixture("outbound/protocol/base_dataplane.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let (proxy, handle) = spawn_socks5_echo_proxy();
    let report = socks5::tcp_connect_exchange(
        &proxy,
        fixture["socks5"]["target"].as_str().unwrap(),
        fixture["socks5"]["username"].as_str().unwrap(),
        fixture["socks5"]["password"].as_str().unwrap(),
        payload,
        Duration::from_secs(2),
    )
    .unwrap();
    handle.join().unwrap();

    assert!(report.true_dataplane);
    assert_eq!(report.method, 2);
    assert_eq!(
        report.bind,
        fixture["socks5"]["bind"].as_str().unwrap().to_owned()
    );
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn base_http_connect_dataplane_echoes_payload() {
    let fixture = fixture("outbound/protocol/base_dataplane.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let (proxy, handle) = spawn_http_connect_echo_proxy();
    let mut options =
        http_proxy::HttpConnectOptions::connect(fixture["http"]["target"].as_str().unwrap());
    options.username = fixture["http"]["username"].as_str().unwrap().to_owned();
    options.password = fixture["http"]["password"].as_str().unwrap().to_owned();
    options.host_override = fixture["http"]["host_override"]
        .as_str()
        .unwrap()
        .to_owned();
    let report =
        http_proxy::connect_exchange(&proxy, &options, payload, Duration::from_secs(2)).unwrap();
    handle.join().unwrap();

    assert!(report.true_dataplane);
    assert_eq!(report.status, 200);
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn base_shadowsocks_aead_tcp_dataplane_echoes_payload() {
    let fixture = fixture("outbound/protocol/base_dataplane.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let cipher = fixture["shadowsocks"]["cipher"].as_str().unwrap();
    let password = fixture["shadowsocks"]["password"].as_str().unwrap();
    let client_salt = hex_decode(fixture["shadowsocks"]["client_salt_hex"].as_str().unwrap());
    let server_salt = hex_decode(fixture["shadowsocks"]["server_salt_hex"].as_str().unwrap());
    let (server, handle) = spawn_shadowsocks_aead_echo_server(
        cipher.to_owned(),
        password.to_owned(),
        server_salt.clone(),
    );
    let report = shadowsocks::tcp_exchange(
        &server,
        cipher,
        password,
        fixture["shadowsocks"]["target"].as_str().unwrap(),
        payload,
        shadowsocks::AeadTcpSalts {
            client: &client_salt,
            server: &server_salt,
        },
        Duration::from_secs(2),
    )
    .unwrap();
    let accepted_target = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert_eq!(
        accepted_target,
        fixture["shadowsocks"]["target"].as_str().unwrap()
    );
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn case_shadowsocks_aead_udp_packet_wraps_target_and_payload() {
    let cipher = "aes-128-gcm";
    let password = "fixture-password";
    let target = "fixture.fixture.invalid:5353";
    let payload = b"fixture-shadowsocks-udp-ping";
    let salt = hex_decode("202122232425262728292a2b2c2d2e2f");
    let packet = shadowsocks::encode_udp_packet(cipher, password, &salt, target, payload).unwrap();
    let decoded = shadowsocks::decode_udp_packet(cipher, password, &packet).unwrap();

    assert_eq!(decoded.target, target);
    assert_eq!(decoded.payload, payload);
    assert_eq!(decoded.salt_len, salt.len());
    assert!(decoded.packet_len > payload.len() + salt.len());
}
