use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use h3::server;
use http::{Response, StatusCode};

use super::*;
use crate::hysteria2::tls::{
    DEFAULT_HYSTERIA2_SERVER_NAME, build_hysteria2_pinned_client_config,
    build_hysteria2_server_config,
};
use crate::hysteria2::underlay::raw_cert_sha256_hex;
use crate::hysteria2::wire::{build_tcp_request_stream, build_tcp_response_stream};

const AUTH: &str = "hysteria2-auth-session-fixture";
const TCP_TARGET: &str = "hysteria2-auth-session-target.invalid:443";

#[tokio::test(flavor = "current_thread")]
async fn authenticated_session_keeps_quic_open_for_hysteria2_streams() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (server_config, cert_der) =
            build_hysteria2_server_config(DEFAULT_HYSTERIA2_SERVER_NAME).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_task = tokio::spawn(run_auth_then_stream_server(server_endpoint));

        let mut client_endpoint =
            quinn::Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        client_endpoint.set_default_client_config(
            build_hysteria2_pinned_client_config(raw_cert_sha256_hex(cert_der.as_ref())).unwrap(),
        );
        let connection = client_endpoint
            .connect(server_addr, DEFAULT_HYSTERIA2_SERVER_NAME)
            .unwrap()
            .await
            .unwrap();
        let auth_session = authenticate_hysteria2_connection(connection.clone(), AUTH, 0)
            .await
            .unwrap();
        assert!(auth_session.report().auth_ok);
        assert!(auth_session.report().udp_enabled);

        tokio::time::sleep(Duration::from_millis(25)).await;
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        crate::hysteria2::write_hysteria2_tcp_request(&mut send, TCP_TARGET)
            .await
            .unwrap();
        let response = crate::hysteria2::read_hysteria2_tcp_response(&mut recv)
            .await
            .unwrap();
        assert!(response.ok);

        drop(auth_session);
        connection.close(0_u32.into(), b"auth session test done");
        client_endpoint.wait_idle().await;
        server_task.await.unwrap();
    })
    .await
    .unwrap();
}

async fn run_auth_then_stream_server(endpoint: quinn::Endpoint) {
    let connection = endpoint.accept().await.unwrap().await.unwrap();
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let mut incoming: server::Connection<h3_quinn::Connection, Bytes> =
        server::Connection::new(h3_connection).await.unwrap();
    let request = incoming.accept().await.unwrap().unwrap();
    let (request, mut stream) = request.resolve_request().await.unwrap();
    assert_eq!(request.uri().path(), URL_PATH);
    assert_eq!(
        request
            .headers()
            .get(REQUEST_HEADER_AUTH)
            .and_then(|value| value.to_str().ok()),
        Some(AUTH)
    );
    while stream.recv_data().await.unwrap().is_some() {}
    stream
        .send_response(
            Response::builder()
                .status(StatusCode::from_u16(STATUS_AUTH_OK).unwrap())
                .header(RESPONSE_HEADER_UDP_ENABLED, "true")
                .header(COMMON_HEADER_CC_RX, "0")
                .body(())
                .unwrap(),
        )
        .await
        .unwrap();
    stream.finish().await.unwrap();

    let expected = build_tcp_request_stream(TCP_TARGET, &[]).unwrap();
    let (mut send, mut recv) = connection.accept_bi().await.unwrap();
    let mut request = vec![0_u8; expected.len()];
    recv.read_exact(&mut request).await.unwrap();
    assert_eq!(request, expected);
    send.write_all(&build_tcp_response_stream(true, "", &[]).unwrap())
        .await
        .unwrap();
    send.finish().unwrap();

    let _ = connection.closed().await;
    drop(incoming);
    endpoint.wait_idle().await;
}
