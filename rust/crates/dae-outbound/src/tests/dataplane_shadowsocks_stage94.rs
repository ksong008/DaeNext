use std::sync::Arc;

use rustls::ServerConnection;

use super::*;

#[test]
fn stage94_sip003_v2ray_plugin_wraps_tls_ws_mux_shadowsocks_aead_tcp() {
    let cipher = "aes-128-gcm";
    let password = "stage94-password";
    let proxy = "127.0.0.1:0";
    let target = "stage94-sip003-v2ray-plugin.example:8443";
    let payload = b"stage94-sip003-v2ray-plugin-ping".to_vec();
    let client_salt = hex_decode("404142434445464748494a4b4c4d4e4f");
    let server_salt = hex_decode("808182838485868788898a8b8c8d8e8f");
    let options = shadowsocks::Sip003V2rayPluginOptions::new(
        "stage94-v2ray-plugin.example",
        "http/1.1",
        "stage94-v2ray-host.example",
        "/",
    )
    .unwrap();
    let material = shared_transport::tls_loopback_material(&options.tls).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let payload_for_server = payload.clone();
    let server_salt_for_thread = server_salt.clone();
    let options_for_thread = options.clone();
    let server_config = Arc::clone(&material.server_config);

    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let conn = ServerConnection::new(server_config).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, stream);
        let request_head = shared_transport::read_http_head(&mut tls).unwrap();
        let request_text = String::from_utf8(request_head).unwrap();
        assert!(request_text.starts_with("GET / HTTP/1.1\r\n"));
        assert!(request_text.contains("Host: stage94-v2ray-host.example\r\n"));
        tls.write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                shared_transport::WS_ACCEPT_SAMPLE
            )
            .as_bytes(),
        )
        .unwrap();
        let request =
            shadowsocks::read_v2ray_plugin_muxed_shadowsocks_request(&mut tls, cipher, password)
                .unwrap();
        assert_eq!(request.mux_new.id, [0, 0]);
        assert_eq!(
            request.mux_new.status,
            shared_transport::mux::SESSION_STATUS_NEW
        );
        assert_eq!(request.mux_new.option, shared_transport::mux::OPTION_NONE);
        assert_eq!(request.mux_new.metadata[4], 0x01);
        assert_eq!(&request.mux_new.metadata[5..7], &[0, 0]);
        assert_eq!(request.mux_new.metadata[7], 0x01);
        assert_eq!(&request.mux_new.metadata[8..12], &[127, 0, 0, 1]);
        assert_eq!(request.mux_data.id, [0, 0]);
        assert_eq!(request.target, target);
        assert_eq!(request.payload, payload_for_server);
        let response = shadowsocks::encode_v2ray_plugin_muxed_shadowsocks_response(
            cipher,
            password,
            &server_salt_for_thread,
            options_for_thread.mux.id,
            &request.payload,
        )
        .unwrap();
        tls.write_all(&response).unwrap();
        tls.flush().unwrap();
        request
    });

    let report = shadowsocks::v2ray_plugin_tls_ws_mux_shadowsocks_aead_exchange_over_stream(
        TcpStream::connect(&endpoint).unwrap(),
        &material,
        &options,
        proxy,
        cipher,
        password,
        target,
        &payload,
        shadowsocks::AeadTcpSalts {
            client: &client_salt,
            server: &server_salt,
        },
    )
    .unwrap();
    let request = handle.join().unwrap();

    assert_eq!(report.plugin_name, "v2ray-plugin");
    assert!(report.tls_enabled);
    assert!(report.websocket_enabled);
    assert!(report.mux_enabled);
    assert_eq!(report.tls_server_name, "stage94-v2ray-plugin.example");
    assert_eq!(report.selected_alpn, "http/1.1");
    assert_eq!(report.ws_host, "stage94-v2ray-host.example");
    assert_eq!(report.ws_path, "/");
    assert_eq!(report.mux_id_hex, "0000");
    assert_eq!(report.mux_host, "127.0.0.1");
    assert_eq!(report.mux_port, 0);
    assert_eq!(report.mux_network, "tcp");
    assert!(report.tls_passthrough_udp);
    assert!(report.ws_passthrough_udp);
    assert!(report.mux_passthrough_udp);
    assert!(report.websocket_handshake_validated);
    assert!(report.websocket_binary_frame_validated);
    assert!(report.mux_new_frame_validated);
    assert!(report.mux_data_frame_validated);
    assert!(report.tls_handshake_validated);
    assert!(report.certificate_chain_validated);
    assert!(report.server_name_validated);
    assert!(report.alpn_validated);
    assert!(report.inner.true_dataplane);
    assert!(report.inner.default_go_path);
    assert_eq!(report.inner.target, target);
    assert_eq!(report.inner.client_salt_len, client_salt.len());
    assert_eq!(report.inner.server_salt_len, server_salt.len());
    assert_eq!(report.inner.payload_len, payload.len());
    assert_eq!(report.inner.echoed_payload, payload);
    assert!(report.websocket_request_frame_len > request.websocket_payload_len);
    assert_eq!(
        report.mux_request_payload_len,
        request.websocket_payload_len
    );
}

#[test]
fn stage94_sip003_v2ray_plugin_options_keep_go_mux_defaults() {
    let options =
        shadowsocks::Sip003V2rayPluginOptions::new("sni.example", "http/1.1", "host.example", "")
            .unwrap();
    assert_eq!(options.ws_path, "/");
    assert_eq!(options.mux.id, [0, 0]);
    assert_eq!(options.mux.host, "127.0.0.1");
    assert_eq!(options.mux.port, 0);
    assert_eq!(options.mux.network, "tcp");
    assert!(options.tls_passthrough_udp);
    assert!(options.ws_passthrough_udp);
    assert!(options.mux_passthrough_udp);
}
