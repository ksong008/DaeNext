use super::*;

pub(in crate::tests) fn spawn_vmess_aead_tcp_echo_server(
    uuid: String,
) -> (String, thread::JoinHandle<vmess::VMessAeadTcpRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = vmess::read_aead_tcp_request_from_stream(&mut stream, &uuid).unwrap();
        assert_eq!(request.command, crate::vmess::VMessNetwork::Tcp.byte());
        let response = vmess::aead_tcp_response_packet(&request, &request.payload).unwrap();
        stream.write_all(&response).unwrap();
        request
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_vmess_aead_udp_over_tcp_echo_server(
    uuid: String,
) -> (
    String,
    thread::JoinHandle<vmess::VMessAeadUdpOverTcpRequest>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request =
            vmess::read_aead_udp_over_tcp_request_from_stream(&mut stream, &uuid).unwrap();
        assert_eq!(
            request.request.command,
            crate::vmess::VMessNetwork::Udp.byte()
        );
        let response =
            vmess::aead_tcp_response_packet(&request.request, &request.request.payload).unwrap();
        stream.write_all(&response).unwrap();
        request
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_vmess_packet_addr_udp_echo_server(
    uuid: String,
) -> (
    String,
    thread::JoinHandle<vmess::VMessAeadPacketAddrUdpRequest>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request =
            vmess::read_aead_packet_addr_udp_request_from_stream(&mut stream, &uuid).unwrap();
        assert_eq!(
            request.request.command,
            crate::vmess::VMessNetwork::Udp.byte()
        );
        assert_eq!(
            request.request.target,
            format!("{}:53", vmess::VMESS_PACKET_ADDR_MAGIC_ADDRESS)
        );
        let response =
            vmess::aead_tcp_response_packet(&request.request, &request.request.payload).unwrap();
        stream.write_all(&response).unwrap();
        request
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_vmess_aead_mux_echo_server(
    uuid: String,
    expected_id: [u8; 2],
    expected_target: String,
) -> (String, thread::JoinHandle<vmess::VMessAeadMuxRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = vmess::read_aead_mux_request_from_stream(&mut stream, &uuid).unwrap();
        assert_eq!(
            request.request.command,
            crate::vmess::VMessNetwork::Mux.byte()
        );
        assert_eq!(request.request.target, "0.0.0.0:0");
        assert_eq!(request.new_frame.id, expected_id);
        let (host, port) = expected_target.rsplit_once(':').unwrap();
        let options = shared_transport::MuxFrameOptions::new(
            expected_id,
            host,
            port.parse::<u16>().unwrap(),
            "tcp",
        );
        let expected_new = shared_transport::mux_new_frame(&options).unwrap();
        assert_eq!(request.new_frame.metadata, expected_new[2..]);
        assert_eq!(request.data_frame.id, expected_id);
        assert_eq!(
            request.data_frame.option,
            shared_transport::mux::OPTION_DATA
        );
        assert_eq!(request.end_frame.id, expected_id);
        assert_eq!(
            request.end_frame.status,
            shared_transport::mux::SESSION_STATUS_END
        );
        let response =
            shared_transport::mux_data_frame(expected_id, &request.data_frame.payload).unwrap();
        let response = vmess::aead_tcp_response_packet(&request.request, &response).unwrap();
        stream.write_all(&response).unwrap();
        request
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_vmess_aead_websocket_echo_server(
    uuid: String,
    expected_target: String,
    expected_host: String,
    expected_path: String,
) -> (String, thread::JoinHandle<vmess::VMessAeadWebSocketRequest>) {
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
            vmess::read_aead_tcp_request_from_websocket_stream(&mut stream, &uuid).unwrap();
        assert_eq!(
            request.request.command,
            crate::vmess::VMessNetwork::Tcp.byte()
        );
        assert_eq!(request.request.target, expected_target);
        let response =
            vmess::aead_tcp_response_packet(&request.request, &request.request.payload).unwrap();
        let response = shared_transport::websocket_server_binary_frame(&response).unwrap();
        stream.write_all(&response).unwrap();
        request
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_vmess_aead_httpupgrade_echo_server(
    uuid: String,
    expected_target: String,
    expected_host: String,
    expected_path: String,
) -> (
    String,
    thread::JoinHandle<vmess::VMessAeadHttpUpgradeRequest>,
) {
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
        let request =
            vmess::read_aead_tcp_request_from_httpupgrade_stream(&mut stream, &uuid).unwrap();
        assert_eq!(
            request.request.command,
            crate::vmess::VMessNetwork::Tcp.byte()
        );
        assert_eq!(request.request.target, expected_target);
        let response =
            vmess::aead_tcp_response_packet(&request.request, &request.request.payload).unwrap();
        stream.write_all(&response).unwrap();
        request
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_vmess_aead_grpc_hunk_echo_server(
    uuid: String,
    expected_target: String,
    expected_service_name: String,
) -> (String, thread::JoinHandle<vmess::VMessAeadGrpcHunkRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let expected_preface = shared_transport::grpc_stream_preface(&expected_service_name);
        let mut preface = vec![0_u8; expected_preface.len()];
        stream.read_exact(&mut preface).unwrap();
        assert_eq!(preface, expected_preface);

        let request =
            vmess::read_aead_tcp_request_from_grpc_hunk_stream(&mut stream, &uuid).unwrap();
        assert_eq!(
            request.request.command,
            crate::vmess::VMessNetwork::Tcp.byte()
        );
        assert_eq!(request.request.target, expected_target);
        let response =
            vmess::aead_tcp_response_packet(&request.request, &request.request.payload).unwrap();
        stream
            .write_all(&shared_transport::grpc_hunk_frame(&response).unwrap())
            .unwrap();
        request
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_vmess_aead_meek_polling_echo_server(
    uuid: String,
    expected_target: String,
    options: shared_transport::MeekRoundTripOptions,
) -> (
    String,
    thread::JoinHandle<vmess::VMessAeadMeekPollingRequest>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request =
            vmess::read_aead_tcp_request_from_meek_polling_stream(&mut stream, &uuid, &options)
                .unwrap();
        assert_eq!(
            request.request.command,
            crate::vmess::VMessNetwork::Tcp.byte()
        );
        assert_eq!(request.request.target, expected_target);
        let response =
            vmess::aead_tcp_response_packet(&request.request, &request.request.payload).unwrap();
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

pub(in crate::tests) fn spawn_vmess_aead_http_transport_echo_server(
    uuid: String,
    expected_target: String,
    options: crate::http_proxy::HttpConnectOptions,
) -> (
    String,
    thread::JoinHandle<(
        vmess::VMessHttpTransportRequestHead,
        vmess::VMessAeadTcpRequest,
    )>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let head =
            vmess::read_http_transport_request_head_from_stream(&mut stream, &options).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        let request = vmess::read_aead_tcp_request_from_stream(&mut stream, &uuid).unwrap();
        assert_eq!(request.command, crate::vmess::VMessNetwork::Tcp.byte());
        assert_eq!(request.target, expected_target);
        let response = vmess::aead_tcp_response_packet(&request, &request.payload).unwrap();
        stream.write_all(&response).unwrap();
        (head, request)
    });
    (addr, handle)
}
