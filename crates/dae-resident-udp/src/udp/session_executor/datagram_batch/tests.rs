use super::*;

async fn relay_to(receiver: &tokio::net::UdpSocket) -> DatagramRelay {
    let mut relay = DatagramRelay::default();
    relay
        .open_candidates(vec![receiver.local_addr().unwrap()], 0, "test")
        .await
        .unwrap();
    relay.batch = Some(Vec::new());
    relay.batch_limit = 32;
    relay
}

#[tokio::test]
async fn profile_batch_limits_are_enforced_and_scalar_builds_do_not_queue() {
    for (profile, expected) in [
        (ResidentRuntimeProfile::LowMemory, 8),
        (ResidentRuntimeProfile::Balanced, 16),
        (ResidentRuntimeProfile::HighPerformance, 32),
    ] {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut relay = relay_to(&receiver).await;
        relay.batch = None;
        let batched = relay.begin_batch(profile.udp_syscall_batch_limit());
        assert_eq!(batched, !cfg!(feature = "test-scalar-udp-send"));
        if batched {
            for _ in 0..expected {
                relay.send_packet(b"queued", 0, "test").await.unwrap();
            }
            assert!(relay.send_packet(b"overflow", 0, "test").await.is_err());
            assert_eq!(relay.flush_batch(0).await.len(), expected);
        } else {
            relay.send_packet(b"scalar", 0, "test").await.unwrap();
            assert!(relay.batch.is_none());
            let mut out = [0; 20];
            let read = time::timeout(Duration::from_secs(1), receiver.recv(&mut out))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&out[..read], b"scalar");
        }
    }
}

#[tokio::test]
async fn batch_preserves_datagram_order_and_sends_only_after_flush() {
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut relay = relay_to(&receiver).await;
    for sequence in 0..32 {
        relay
            .send_packet(&[sequence; 1200], 0, "test")
            .await
            .unwrap();
    }
    let mut out = [0; 1300];
    assert_eq!(
        receiver.try_recv(&mut out).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(relay.send_packet(b"overflow", 0, "test").await.is_err());
    let results = relay.flush_batch(0).await;
    assert_eq!(results.len(), 32);
    assert!(results.iter().all(Result::is_ok));
    for sequence in 0..32 {
        let read = time::timeout(Duration::from_secs(1), receiver.recv(&mut out))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&out[..read], &[sequence; 1200]);
    }
    assert_eq!(
        receiver.try_recv(&mut out).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn partially_sent_batch_does_not_replay_accepted_prefix_and_recovers_after_invalid_packet() {
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut relay = relay_to(&receiver).await;
    for payload in [b"first".as_slice(), &vec![0; 70000], b"last".as_slice()] {
        relay.send_packet(payload, 0, "test").await.unwrap();
    }
    let results = relay.flush_batch(0).await;
    assert!(results[0].is_ok());
    assert!(results[1].is_err());
    assert!(results[2].is_ok());
    let mut out = [0; 20];
    for expected in [b"first".as_slice(), b"last".as_slice()] {
        let len = time::timeout(Duration::from_secs(1), receiver.recv(&mut out))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&out[..len], expected);
    }
    assert_eq!(
        receiver.try_recv(&mut out).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
