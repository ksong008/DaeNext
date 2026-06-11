use super::*;

pub(in crate::tests) fn spawn_httpupgrade_echo_server() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_head_for_test(&mut stream);
        assert!(request.starts_with("GET /upgrade HTTP/1.1\r\n"));
        assert!(request.contains("Host: upgrade.fixture.invalid\r\n"));
        assert!(request.contains("Connection: upgrade\r\n"));
        assert!(request.contains("Upgrade: websocket\r\n"));
        stream
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n")
            .unwrap();
        echo_one_payload(&mut stream);
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_websocket_echo_server() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_head_for_test(&mut stream);
        assert!(request.starts_with("GET /ws HTTP/1.1\r\n"));
        assert!(request.contains("Host: ws.fixture.invalid\r\n"));
        assert!(request.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            )
            .unwrap();
        let payload =
            shared_transport::dataplane::read_websocket_binary_frame(&mut stream).unwrap();
        let frame = shared_transport::dataplane::websocket_server_binary_frame(&payload).unwrap();
        stream.write_all(&frame).unwrap();
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_simpleobfs_http_echo_server() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (request, leftover) = read_http_head_and_leftover_for_test(&mut stream);
        assert!(request.starts_with("GET / HTTP/1.1\r\n"));
        assert!(request.contains("Host: obfs.fixture.invalid\r\n"));
        assert!(request.contains("User-Agent: curl/7.64.1\r\n"));
        echo_one_payload_with_leftover(&mut stream, leftover);
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_reality_mutation_echo_server(
    expected_session_id: [u8; 32],
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let message = shared_transport::reality::read_reality_harness_message(&mut stream).unwrap();
        assert_eq!(message.session_id, expected_session_id);
        assert_eq!(message.server_name, "reality.fixture.invalid");
        shared_transport::reality::write_len_payload(&mut stream, &message.payload).unwrap();
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_xhttp_packet_echo_server(
    expected_path: String,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (request, leftover) = read_http_head_and_leftover_for_test(&mut stream);
        assert!(request.starts_with(&format!("POST {expected_path} HTTP/1.1\r\n")));
        assert!(request.contains("Host: xhttp.fixture.invalid\r\n"));
        assert!(request.contains("X-DAE-XHTTP-Mode: packet-up\r\n"));
        assert!(request.contains("X-DAE-XHTTP-ALPN: h3\r\n"));
        let body = read_http_body_for_test(&mut stream, &request, leftover);
        write_http_response_for_test(&mut stream, &body);
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_grpc_hunk_echo_server(
    expected_service_name: &str,
) -> (String, thread::JoinHandle<()>) {
    let expected_service_name = expected_service_name.to_owned();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (request, leftover) = read_http_head_and_leftover_for_test(&mut stream);
        assert!(request.starts_with(&format!("POST /{expected_service_name}/Tun HTTP/2\r\n")));
        assert!(request.contains("content-type: application/grpc\r\n"));
        let payload = read_grpc_hunk_frame_for_test(&mut stream, leftover);
        stream
            .write_all(&shared_transport::grpc_hunk_frame(&payload).unwrap())
            .unwrap();
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_meek_roundtripper_echo_server(
    expected_path: String,
    expected_session_id: String,
    round_trips: usize,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        for _ in 0..round_trips {
            let (mut stream, _) = listener.accept().unwrap();
            let (request, leftover) = read_http_head_and_leftover_for_test(&mut stream);
            assert!(request.starts_with(&format!("POST {expected_path} HTTP/1.1\r\n")));
            assert!(request.contains("Host: front.fixture.invalid\r\n"));
            assert!(request.contains(&format!("X-Session-ID: {expected_session_id}\r\n")));
            let body = read_http_body_for_test(&mut stream, &request, leftover);
            if body.is_empty() {
                write_http_response_for_test(&mut stream, b"poll-ok");
            } else {
                write_http_response_for_test(&mut stream, &body);
            }
        }
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_mux_frame_echo_server(
    expected_id: [u8; 2],
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let new_frame = shared_transport::mux::read_mux_frame(&mut stream).unwrap();
        assert_eq!(new_frame.id, expected_id);
        assert_eq!(new_frame.status, shared_transport::mux::SESSION_STATUS_NEW);
        let data_frame = shared_transport::mux::read_mux_frame(&mut stream).unwrap();
        assert_eq!(data_frame.id, expected_id);
        assert_eq!(
            data_frame.status,
            shared_transport::mux::SESSION_STATUS_KEEP
        );
        assert_eq!(data_frame.option, shared_transport::mux::OPTION_DATA);
        stream
            .write_all(&shared_transport::mux_data_frame(expected_id, &data_frame.payload).unwrap())
            .unwrap();
        let end_frame = shared_transport::mux::read_mux_frame(&mut stream).unwrap();
        assert_eq!(end_frame.id, expected_id);
        assert_eq!(end_frame.status, shared_transport::mux::SESSION_STATUS_END);
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_quic_h3_datagram_echo_server() -> (String, thread::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (n, peer) = socket.recv_from(&mut buf).unwrap();
        let parsed = shared_transport::parse_quic_h3_datagram(&buf[..n]).unwrap();
        assert_eq!(parsed.flow_id, 7);
        assert_eq!(parsed.datagram_id, 11);
        socket.send_to(&buf[..n], peer).unwrap();
    });
    (addr, handle)
}
