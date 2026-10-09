use std::{sync::Arc, time::Duration};

pub(crate) async fn assert_receive_burst(transport: quinn::TransportConfig) {
    // Hold the application reader until an entire burst has reached QUIC.
    // This exposes internal queue eviction independently of socket loss.
    let transport = Arc::new(transport);
    let identity = crate::test_support::self_signed_tls_identity(&["localhost"]).unwrap();
    let server_config = crate::test_support::boring_quic_server_config(
        &identity,
        &[b"h3".to_vec()],
        Arc::clone(&transport),
    )
    .unwrap();
    let policy = crate::boring_quic::BoringQuicClientPolicy::new([b"h3".as_slice()])
        .unwrap()
        .allow_insecure(true);
    let client_config =
        crate::boring_quic::build_boring_quic_client_config(&policy, transport).unwrap();
    let server = crate::test_support::boring_quic_server_endpoint(
        server_config,
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut client =
        crate::test_support::boring_quic_client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);
    let (sender, receiver) = tokio::join!(
        client
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap(),
        async { server.accept().await.unwrap().await }
    );
    let sender = sender.unwrap();
    let receiver = receiver.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        for sequence in 0_u8..128 {
            let mut data = vec![0; 1_100];
            data[0] = sequence;
            sender.send_datagram_wait(data.into()).await.unwrap();
        }
        while receiver.stats().frame_rx.datagram < 128 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        for sequence in 0_u8..128 {
            let data = receiver.read_datagram().await.unwrap();
            assert_eq!(data.len(), 1_100);
            assert_eq!(
                data[0], sequence,
                "QUIC discarded a received datagram before application delivery"
            );
        }
    })
    .await
    .expect("burst must be delivered without a stalled receive");
    sender.close(0_u32.into(), b"done");
    client.wait_idle().await;
    server.wait_idle().await;
}
