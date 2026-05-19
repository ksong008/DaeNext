use super::*;

pub(in crate::tests) fn spawn_vless_tcp_echo_server(
    expected_key: [u8; 16],
    payload_len: usize,
) -> (String, thread::JoinHandle<vless::VlessTcpRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = vless::read_tcp_request_from_stream(&mut stream, payload_len).unwrap();
        assert_eq!(request.key, expected_key);
        assert_eq!(request.command, crate::vmess::VMessNetwork::Tcp.byte());
        stream.write_all(&request.payload).unwrap();
        request
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_vless_udp_over_tcp_echo_server(
    expected_key: [u8; 16],
) -> (String, thread::JoinHandle<vless::VlessUdpRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = vless::read_udp_request_from_stream(&mut stream).unwrap();
        assert_eq!(request.key, expected_key);
        assert_eq!(request.command, crate::vmess::VMessNetwork::Udp.byte());
        let response = vless::udp_response_packet(&request.payload).unwrap();
        stream.write_all(&response).unwrap();
        request
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_vless_mux_echo_server(
    expected_key: [u8; 16],
    expected_id: [u8; 2],
    expected_target: String,
) -> (
    String,
    thread::JoinHandle<(
        vless::VlessMuxRequest,
        shared_transport::mux::MuxFrame,
        shared_transport::mux::MuxFrame,
        shared_transport::mux::MuxFrame,
    )>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = vless::read_mux_request_from_stream(&mut stream).unwrap();
        assert_eq!(request.key, expected_key);
        assert_eq!(request.command, crate::vmess::VMessNetwork::Mux.byte());
        let (host, port) = expected_target.rsplit_once(':').unwrap();
        let options = shared_transport::MuxFrameOptions::new(
            expected_id,
            host,
            port.parse::<u16>().unwrap(),
            "tcp",
        );
        let new_frame = shared_transport::mux::read_mux_frame(&mut stream).unwrap();
        let expected_new = shared_transport::mux_new_frame(&options);
        assert_eq!(new_frame.metadata, expected_new[2..]);
        let data_frame = shared_transport::mux::read_mux_frame(&mut stream).unwrap();
        assert_eq!(data_frame.id, expected_id);
        assert_eq!(data_frame.option, shared_transport::mux::OPTION_DATA);
        stream
            .write_all(&shared_transport::mux_data_frame(expected_id, &data_frame.payload).unwrap())
            .unwrap();
        let end_frame = shared_transport::mux::read_mux_frame(&mut stream).unwrap();
        (request, new_frame, data_frame, end_frame)
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_vless_websocket_echo_server(
    expected_key: [u8; 16],
    expected_target: String,
    expected_host: String,
    expected_path: String,
    payload_len: usize,
) -> (String, thread::JoinHandle<vless::VlessWebSocketRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request_head = read_http_head_for_test(&mut stream);
        assert!(request_head.starts_with(&format!("GET {expected_path} HTTP/1.1\r\n")));
        assert!(request_head.contains(&format!("Host: {expected_host}\r\n")));
        assert!(request_head.contains("Upgrade: websocket\r\n"));
        stream
            .write_all(
                format!(
                    "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                    shared_transport::WS_ACCEPT_SAMPLE
                )
                .as_bytes(),
            )
            .unwrap();
        let request =
            vless::read_tcp_request_from_websocket_stream(&mut stream, payload_len).unwrap();
        assert_eq!(request.request.key, expected_key);
        assert_eq!(
            request.request.command,
            crate::vmess::VMessNetwork::Tcp.byte()
        );
        assert_eq!(request.request.target, expected_target);
        let response = vless::response_payload_bytes(&request.request.payload);
        let response = shared_transport::websocket_server_binary_frame(&response).unwrap();
        stream.write_all(&response).unwrap();
        request
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_vless_httpupgrade_echo_server(
    expected_key: [u8; 16],
    expected_target: String,
    expected_host: String,
    expected_path: String,
    payload_len: usize,
) -> (String, thread::JoinHandle<vless::VlessTcpRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request_head = read_http_head_for_test(&mut stream);
        assert!(request_head.starts_with(&format!("GET {expected_path} HTTP/1.1\r\n")));
        assert!(request_head.contains(&format!("Host: {expected_host}\r\n")));
        assert!(request_head.contains("Connection: upgrade\r\n"));
        assert!(request_head.contains("Upgrade: websocket\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .unwrap();
        let request = vless::read_tcp_request_from_stream(&mut stream, payload_len).unwrap();
        assert_eq!(request.key, expected_key);
        assert_eq!(request.command, crate::vmess::VMessNetwork::Tcp.byte());
        assert_eq!(request.target, expected_target);
        let response = vless::response_payload_bytes(&request.payload);
        stream.write_all(&response).unwrap();
        request
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_vless_grpc_hunk_echo_server(
    expected_key: [u8; 16],
    expected_target: String,
    expected_service_name: String,
    payload_len: usize,
) -> (String, thread::JoinHandle<vless::VlessGrpcHunkRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let expected_preface = shared_transport::grpc_stream_preface(&expected_service_name);
        let mut preface = vec![0_u8; expected_preface.len()];
        stream.read_exact(&mut preface).unwrap();
        assert_eq!(preface, expected_preface);
        let request =
            vless::read_tcp_request_from_grpc_hunk_stream(&mut stream, payload_len).unwrap();
        assert_eq!(request.request.key, expected_key);
        assert_eq!(
            request.request.command,
            crate::vmess::VMessNetwork::Tcp.byte()
        );
        assert_eq!(request.request.target, expected_target);
        let response = vless::response_payload_bytes(&request.request.payload);
        let response = shared_transport::grpc_hunk_frame(&response).unwrap();
        stream.write_all(&response).unwrap();
        request
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_vless_meek_polling_echo_server(
    expected_key: [u8; 16],
    expected_target: String,
    meek_options: shared_transport::MeekRoundTripOptions,
    payload_len: usize,
) -> (String, thread::JoinHandle<vless::VlessMeekPollingRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = vless::read_tcp_request_from_meek_polling_stream(
            &mut stream,
            payload_len,
            &meek_options,
        )
        .unwrap();
        assert_eq!(request.request.key, expected_key);
        assert_eq!(
            request.request.command,
            crate::vmess::VMessNetwork::Tcp.byte()
        );
        assert_eq!(request.request.target, expected_target);
        let response = vless::response_payload_bytes(&request.request.payload);
        let response_head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            response.len()
        );
        stream.write_all(response_head.as_bytes()).unwrap();
        stream.write_all(&response).unwrap();
        request
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_vless_http_transport_echo_server(
    expected_key: [u8; 16],
    expected_target: String,
    options: crate::http_proxy::HttpConnectOptions,
    expected_payload_len: usize,
) -> (
    String,
    thread::JoinHandle<(vless::VlessHttpTransportRequestHead, vless::VlessTcpRequest)>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let head =
            vless::read_http_transport_request_head_from_stream(&mut stream, &options).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        let request =
            vless::read_tcp_request_from_stream(&mut stream, expected_payload_len).unwrap();
        assert_eq!(request.key, expected_key);
        assert_eq!(request.addons_len, 0);
        assert_eq!(request.command, crate::vmess::VMessNetwork::Tcp.byte());
        assert_eq!(request.target, expected_target);
        let response = vless::response_payload_bytes(&request.payload);
        stream.write_all(&response).unwrap();
        (head, request)
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_vless_xhttp_packet_echo_server(
    expected_key: [u8; 16],
    expected_target: String,
    options: shared_transport::XHttpLifecycleOptions,
    expected_payload_len: usize,
) -> (String, thread::JoinHandle<vless::VlessXHttpPacketRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = vless::read_tcp_request_from_xhttp_packet_stream(
            &mut stream,
            expected_payload_len,
            &options,
        )
        .unwrap();
        assert_eq!(request.request.key, expected_key);
        assert_eq!(request.request.addons_len, 0);
        assert_eq!(
            request.request.command,
            crate::vmess::VMessNetwork::Tcp.byte()
        );
        assert_eq!(request.request.target, expected_target);
        let response = vless::response_payload_bytes(&request.request.payload);
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    response.len()
                )
                .as_bytes(),
            )
            .unwrap();
        stream.write_all(&response).unwrap();
        request
    });
    (addr, handle)
}
