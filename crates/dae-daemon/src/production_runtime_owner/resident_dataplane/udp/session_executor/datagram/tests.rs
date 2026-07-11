use super::*;

use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time;

const TEST_RECEIVE_TIMEOUT: Duration = Duration::from_secs(1);
const TEST_NO_DATAGRAM_TIMEOUT: Duration = Duration::from_millis(50);

fn open_test_sender() -> tokio::net::UdpSocket {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket.set_nonblocking(true).unwrap();
    tokio::net::UdpSocket::from_std(socket).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn opening_candidates_skips_failure_without_reordering() {
    let first: SocketAddr = "192.0.2.10:53".parse().unwrap();
    let second: SocketAddr = "192.0.2.20:53".parse().unwrap();
    let attempted = Arc::new(Mutex::new(Vec::new()));
    let mut relay = DatagramRelay {
        remote_candidates: vec![first, second],
        ..DatagramRelay::default()
    };

    relay
        .select_open_candidate_with(0, 0, "test", {
            let attempted = Arc::clone(&attempted);
            move |candidate, _| {
                attempted.lock().unwrap().push(candidate);
                async move {
                    if candidate == first {
                        Err("injected first-candidate open failure".to_owned())
                    } else {
                        Ok(open_test_sender())
                    }
                }
            }
        })
        .await
        .unwrap();

    assert_eq!(*attempted.lock().unwrap(), vec![first, second]);
    assert_eq!(relay.selected_index, 1);
    assert!(relay.socket.is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn immediate_send_failure_moves_to_later_candidate_once() {
    let listener = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let available = listener.local_addr().unwrap();
    let incompatible = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), available.port());
    let mut relay = DatagramRelay {
        socket: Some(open_test_sender()),
        remote_candidates: vec![incompatible, available],
        selected_index: 0,
        response_buf: Vec::new(),
    };

    relay.send_packet(b"fallback", 0, "test").await.unwrap();

    let mut received = [0_u8; 32];
    let (read, _) = time::timeout(TEST_RECEIVE_TIMEOUT, listener.recv_from(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received[..read], b"fallback");
    assert_eq!(relay.selected_index, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn successful_first_candidate_does_not_emit_duplicate_datagram() {
    let first = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let second = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let mut relay = DatagramRelay {
        socket: Some(open_test_sender()),
        remote_candidates: vec![first.local_addr().unwrap(), second.local_addr().unwrap()],
        selected_index: 0,
        response_buf: Vec::new(),
    };

    relay.send_packet(b"single", 0, "test").await.unwrap();

    let mut received = [0_u8; 32];
    let (read, _) = time::timeout(TEST_RECEIVE_TIMEOUT, first.recv_from(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received[..read], b"single");
    assert!(
        time::timeout(TEST_NO_DATAGRAM_TIMEOUT, second.recv_from(&mut received))
            .await
            .is_err()
    );
    assert_eq!(relay.selected_index, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn awaited_response_blocks_until_the_socket_is_readable() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let relay_socket = open_test_sender();
    let relay_addr = relay_socket.local_addr().unwrap();
    let mut relay = DatagramRelay {
        socket: Some(relay_socket),
        remote_candidates: vec![upstream.local_addr().unwrap()],
        selected_index: 0,
        response_buf: Vec::new(),
    };

    assert!(
        time::timeout(TEST_NO_DATAGRAM_TIMEOUT, relay.wait_response("test"))
            .await
            .is_err()
    );

    upstream.send_to(b"response", relay_addr).await.unwrap();
    let response = time::timeout(TEST_RECEIVE_TIMEOUT, relay.wait_response("test"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, b"response");
}
