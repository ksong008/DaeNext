use super::*;

use crate::production_runtime_owner::resident_dataplane::plan::ResidentXhttpSettingsPlan;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

const TEST_SECOND_ACCEPT_TIMEOUT: Duration = Duration::from_millis(100);

fn socks5_proxy(server: SocketAddr) -> ResidentProxyPlan {
    ResidentProxyPlan {
        graph_id: "test-graph".to_owned(),
        graph_link_hash: "test-hash".to_owned(),
        redacted_link_source: "test-source".to_owned(),
        protocol: "socks5",
        group_name: "test-group".to_owned(),
        group_policy: "fixed".to_owned(),
        node_tag: "test-node".to_owned(),
        server_host: server.ip().to_string(),
        server_port: server.port(),
        server_name: server.ip().to_string(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        xhttp_download: None,
        xhttp_mode: ResidentXhttpMode::PacketUp,
        xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
        xhttp_xmux: None,
        tls: "none".to_owned(),
        allow_insecure: false,
        tls_fragment: None,
        utls_fingerprint: None,
        reality: None,
        handler: ResidentProxyProtocolPlan::Socks5Tcp {
            username: String::new(),
            password: String::new(),
        },
        execution: None,
        chain_parent: None,
        mark: 0,
        mptcp: false,
    }
}

async fn serve_udp_associate_once(listener: tokio::net::TcpListener, relay: SocketAddr) -> bool {
    let (mut control, _) = listener.accept().await.unwrap();
    let mut greeting_head = [0_u8; 2];
    control.read_exact(&mut greeting_head).await.unwrap();
    assert_eq!(greeting_head[0], 5);
    let mut methods = vec![0_u8; greeting_head[1] as usize];
    control.read_exact(&mut methods).await.unwrap();
    control.write_all(&[5, 0]).await.unwrap();

    let mut request = [0_u8; 10];
    control.read_exact(&mut request).await.unwrap();
    assert_eq!(&request[..4], &[5, 3, 0, 1]);

    let SocketAddr::V4(relay) = relay else {
        panic!("test relay must be IPv4");
    };
    let mut response = vec![5, 0, 0, 1];
    response.extend_from_slice(&relay.ip().octets());
    response.extend_from_slice(&relay.port().to_be_bytes());
    control.write_all(&response).await.unwrap();

    time::timeout(TEST_SECOND_ACCEPT_TIMEOUT, listener.accept())
        .await
        .is_ok()
}

#[tokio::test(flavor = "current_thread")]
async fn udp_associate_reuses_existing_control_and_relay() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let server = listener.local_addr().unwrap();
    let relay = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let server_task = tokio::spawn(serve_udp_associate_once(listener, relay_addr));
    let mut proxy = socks5_proxy(server);
    proxy.materialize_execution();
    let binding = ResidentProxyBinding::configuration(Arc::new(proxy)).unwrap();
    let mut session = Socks5UdpAssociateSession::default();

    session.ensure_open(&binding).await.unwrap();
    let first_peer = session.control.as_ref().unwrap().peer_addr().unwrap();
    session.ensure_open(&binding).await.unwrap();
    let second_peer = session.control.as_ref().unwrap().peer_addr().unwrap();

    assert_eq!(first_peer, second_peer);
    assert!(session.relay.is_open());
    assert!(
        !server_task.await.unwrap(),
        "unexpected second control connection"
    );
}

#[test]
fn udp_associate_response_source_is_checked_before_payload_access() {
    let session = Socks5UdpAssociateSession::default();
    let expected: SocketAddr = "192.0.2.1:53".parse().unwrap();
    let other: SocketAddr = "192.0.2.2:53".parse().unwrap();
    let packet = udp_packet::wrap_target(&other.to_string(), b"response").unwrap();
    let mut response = session.decode_response(&packet).unwrap();
    let expectation = response.fixed_target_expectation(expected);
    assert_eq!(
        response.take_fixed_target_payload(expectation).validation(),
        UdpFixedTargetValidation::Dropped(UdpResponseDropReason::UnexpectedWireSource)
    );
}

#[test]
fn udp_associate_domain_response_is_rejected_for_a_fixed_socket_target() {
    let session = Socks5UdpAssociateSession::default();
    let expected: SocketAddr = "192.0.2.1:53".parse().unwrap();
    let packet = udp_packet::wrap_target("example.invalid:53", b"response").unwrap();
    let mut response = session.decode_response(&packet).unwrap();
    let expectation = response.fixed_target_expectation(expected);
    assert_eq!(
        response.take_fixed_target_payload(expectation).validation(),
        UdpFixedTargetValidation::Dropped(UdpResponseDropReason::MalformedIdentity)
    );
}
