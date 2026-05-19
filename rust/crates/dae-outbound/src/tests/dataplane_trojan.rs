use super::*;

#[test]
fn stage60_trojanc_tcp_dataplane_echoes_payload() {
    let password = "stage60-password";
    let target = "stage60.example:443";
    let payload = b"stage60-trojanc-tcp-ping";
    let (proxy, handle) = spawn_trojanc_tcp_echo_server(password.to_owned(), payload.len());
    let report = trojan::tcp_exchange_over_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        password,
        target,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.command, trojan::TrojanNetwork::Tcp.byte());
    assert_eq!(
        report.password_sha224_hex,
        trojan::packet::password_sha224_hex(password)
    );
    assert_eq!(report.target, target);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(
        accepted.password_sha224_hex,
        trojan::packet::password_sha224_hex(password)
    );
    assert_eq!(accepted.command, trojan::TrojanNetwork::Tcp.byte());
    assert_eq!(accepted.target, target);
    assert_eq!(accepted.payload, payload);
}

#[test]
fn stage61_trojan_udp_over_tcp_dataplane_echoes_packet_payload() {
    let password = "stage61-password";
    let session_target = "stage61-session.example:443";
    let packet_target = "stage61-packet.example:5353";
    let payload = b"stage61-trojan-udp-over-tcp-ping";
    let (proxy, handle) = spawn_trojan_udp_over_tcp_echo_server(password.to_owned(), payload.len());
    let report = trojan::udp_over_tcp_exchange_over_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        password,
        session_target,
        packet_target,
        payload,
    )
    .unwrap();
    let (accepted_header, accepted_packet) = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.command, trojan::TrojanNetwork::Udp.byte());
    assert_eq!(
        report.password_sha224_hex,
        trojan::packet::password_sha224_hex(password)
    );
    assert_eq!(report.session_target, session_target);
    assert_eq!(report.packet_target, packet_target);
    assert_eq!(report.echoed_payload, payload);
    assert!(report.packet_len > payload.len());
    assert_eq!(accepted_header.command, trojan::TrojanNetwork::Udp.byte());
    assert_eq!(accepted_header.target, session_target);
    assert_eq!(accepted_packet.target, packet_target);
    assert_eq!(accepted_packet.payload, payload);
}
