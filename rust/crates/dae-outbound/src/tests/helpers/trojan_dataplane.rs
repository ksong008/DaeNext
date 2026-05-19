use super::*;

pub(in crate::tests) fn spawn_trojanc_tcp_echo_server(
    password: String,
    payload_len: usize,
) -> (String, thread::JoinHandle<trojan::TrojanTcpRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = trojan::read_tcp_request_from_stream(&mut stream, payload_len).unwrap();
        assert_eq!(
            request.password_sha224_hex,
            trojan::packet::password_sha224_hex(&password)
        );
        stream.write_all(&request.payload).unwrap();
        request
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_trojan_udp_over_tcp_echo_server(
    password: String,
    payload_len: usize,
) -> (
    String,
    thread::JoinHandle<(trojan::TrojanRequestHeader, trojan::TrojanUdpPacket)>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let header = trojan::read_request_header_from_stream(&mut stream).unwrap();
        assert_eq!(
            header.password_sha224_hex,
            trojan::packet::password_sha224_hex(&password)
        );
        assert_eq!(header.command, trojan::TrojanNetwork::Udp.byte());
        let packet = trojan::read_udp_packet_from_stream(&mut stream).unwrap();
        assert_eq!(packet.payload_len, payload_len);
        let response = trojan::packet::udp_packet(&packet.target, &packet.payload).unwrap();
        stream.write_all(&response).unwrap();
        (header, packet)
    });
    (addr, handle)
}
