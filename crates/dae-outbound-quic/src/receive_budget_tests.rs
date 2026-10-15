use crate::receive_budget::QuicReceiveBudget;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_quic_receive_budgets_backpressure_and_resume_multiple_streams() {
    for budget in [
        QuicReceiveBudget::LowMemory,
        QuicReceiveBudget::Balanced,
        QuicReceiveBudget::HighPerformance,
    ] {
        for protocol in 0..3 {
            let config = match protocol {
                0 => crate::tuic::tls::build_tuic_client_config_with_receive_budget(
                    &[], true, crate::QuicCongestionController::Bbr, None, budget).unwrap(),
                1 => crate::hysteria2::tls::build_hysteria2_runtime_client_config_with_receive_budget(
                    &crate::hysteria2::Hysteria2TlsIdentity::from_node_and_global(
                        "localhost", Some(true), false, "").unwrap(), 0, None, None, budget).unwrap(),
                _ => crate::juicity::runtime::build_juicity_runtime_client_config_with_receive_budget(
                    true, "", crate::QuicCongestionController::Bbr, None, budget).unwrap(),
            };
            assert_backpressure(config, budget).await;
        }
    }
}

async fn assert_backpressure(config: quinn::ClientConfig, budget: QuicReceiveBudget) {
    let window = budget.bytes() as usize;
    const PAYLOAD_BYTES: usize = 1024 * 1024; // Below Quinn's per-stream window.
    let streams = window / PAYLOAD_BYTES + 8; // Enough to exhaust every profile.
    let (client, server, receiver, sender) = pair(config).await;
    let progress = Arc::new(AtomicUsize::new(0));
    let mut writers = tokio::task::JoinSet::new();
    for sequence in 0..streams as u8 {
        let mut send = sender.open_uni().await.unwrap();
        let progress = Arc::clone(&progress);
        writers.spawn(async move {
            let data = vec![sequence; 16 * 1024];
            for _ in 0..PAYLOAD_BYTES / data.len() {
                let mut remaining = data.as_slice();
                while !remaining.is_empty() {
                    let count = send.write(remaining).await.unwrap();
                    progress.fetch_add(count, Ordering::SeqCst);
                    remaining = &remaining[count..];
                }
            }
            send.finish().unwrap();
        });
    }
    tokio::time::timeout(Duration::from_secs(15), async {
        while progress.load(Ordering::SeqCst) < window {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("sender must reach the advertised connection window");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let stalled = progress.load(Ordering::SeqCst);
    assert!(
        stalled <= window + 128 * 1024,
        "unread data escaped budget: {stalled}/{window}"
    );
    assert!(stalled < streams * PAYLOAD_BYTES);
    let mut readers = tokio::task::JoinSet::new();
    for _ in 0..streams {
        let mut recv = receiver.accept_uni().await.unwrap();
        readers.spawn(async move {
            let mut total = 0;
            let mut sequence = None;
            while let Some(chunk) = recv.read_chunk(64 * 1024, true).await.unwrap() {
                let expected = *sequence.get_or_insert(chunk.bytes[0]);
                assert!(chunk.bytes.iter().all(|byte| *byte == expected));
                total += chunk.bytes.len();
            }
            assert_eq!(total, PAYLOAD_BYTES);
        });
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(result) = readers.join_next().await {
            result.unwrap();
        }
        while let Some(result) = writers.join_next().await {
            result.unwrap();
        }
    })
    .await
    .expect("reading must restore connection credit for all streams");
    assert_eq!(progress.load(Ordering::SeqCst), streams * PAYLOAD_BYTES);
    sender.close(0_u32.into(), b"done");
    client.wait_idle().await;
    server.wait_idle().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tuic_and_juicity_survive_the_old_eight_second_idle_limit() {
    for mut transport in [
        crate::tuic::tls::tuic_transport_config(None).unwrap(),
        crate::juicity::runtime::transport_config(crate::QuicCongestionController::Bbr).unwrap(),
    ] {
        transport.keep_alive_interval(None);
        let policy = crate::boring_quic::BoringQuicClientPolicy::new([b"h3".as_slice()])
            .unwrap()
            .allow_insecure(true);
        let config =
            crate::boring_quic::build_boring_quic_client_config(&policy, Arc::new(transport))
                .unwrap();
        let (client, server, receiver, sender) = pair(config).await;
        tokio::time::sleep(Duration::from_secs(9)).await;
        let mut send = sender.open_uni().await.unwrap();
        send.write_all(b"still alive").await.unwrap();
        send.finish().unwrap();
        let mut recv = tokio::time::timeout(Duration::from_secs(3), receiver.accept_uni())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recv.read_to_end(64).await.unwrap(), b"still alive");
        sender.close(0_u32.into(), b"done");
        client.wait_idle().await;
        server.wait_idle().await;
    }
}

async fn pair(
    config: quinn::ClientConfig,
) -> (
    quinn::Endpoint,
    quinn::Endpoint,
    quinn::Connection,
    quinn::Connection,
) {
    let identity = crate::test_support::self_signed_tls_identity(&["localhost"]).unwrap();
    let mut server_transport = quinn::TransportConfig::default();
    server_transport.send_window(64 * 1024);
    let server_config = crate::test_support::boring_quic_server_config(
        &identity,
        &[b"h3".to_vec()],
        Arc::new(server_transport),
    )
    .unwrap();
    let server = crate::test_support::boring_quic_server_endpoint(
        server_config,
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut client =
        crate::test_support::boring_quic_client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(config);
    let (receiver, sender) = tokio::join!(
        client
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap(),
        async { server.accept().await.unwrap().await }
    );
    (client, server, receiver.unwrap(), sender.unwrap())
}
