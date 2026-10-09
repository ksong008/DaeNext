use std::future::Future;
use std::task::{Context, Poll, Waker};

use super::*;

pub(super) async fn assert_send_backpressure<F, Fut>(send: F)
where
    F: Fn(quinn::Connection, Bytes) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    use dae_outbound_quic::{boring_quic, test_support};
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_send_buffer_size(64 * 1024);
    transport.datagram_receive_buffer_size(Some(256 * 1024));
    let transport = Arc::new(transport);
    let identity = test_support::self_signed_tls_identity(&["localhost"]).unwrap();
    let server_config = test_support::boring_quic_server_config(
        &identity,
        &[b"h3".to_vec()],
        Arc::clone(&transport),
    )
    .unwrap();
    let policy = boring_quic::BoringQuicClientPolicy::new([b"h3".as_slice()])
        .unwrap()
        .allow_insecure(true);
    let client_config = boring_quic::build_boring_quic_client_config(&policy, transport).unwrap();
    let server =
        test_support::boring_quic_server_endpoint(server_config, "127.0.0.1:0".parse().unwrap())
            .unwrap();
    let mut client =
        test_support::boring_quic_client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);
    let (connection, peer) = tokio::join!(
        client
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap(),
        async { server.accept().await.unwrap().await },
    );
    let connection = connection.unwrap();
    let peer = peer.unwrap();
    time::timeout(Duration::from_secs(5), async {
        let mut accepted = 0_u8;
        // On this current-thread runtime the transport driver cannot drain until
        // we yield. Fill the real send queue and cancel the first blocked send.
        for sequence in 0_u8..128 {
            let mut data = vec![0; 1_100];
            data[0] = sequence;
            let before = connection.datagram_send_buffer_space();
            let mut sending = Box::pin(send(connection.clone(), data.into()));
            match sending
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
            {
                Poll::Ready(result) => {
                    result.unwrap();
                    accepted += 1;
                }
                Poll::Pending => {
                    drop(sending);
                    assert_eq!(connection.datagram_send_buffer_space(), before);
                    break;
                }
            }
        }
        assert!(
            accepted > 0 && accepted < 128,
            "saturated sends must wait instead of evicting old packets"
        );
        for sequence in 0..accepted {
            let data = peer.read_datagram().await.unwrap();
            assert_eq!(
                data[0], sequence,
                "a previously accepted packet was evicted"
            );
        }
        assert!(
            time::timeout(Duration::from_millis(20), peer.read_datagram())
                .await
                .is_err(),
            "cancelled send reached the peer"
        );
        send(
            connection.clone(),
            Bytes::from_static(b"after cancellation"),
        )
        .await
        .unwrap();
        assert_eq!(
            peer.read_datagram().await.unwrap(),
            b"after cancellation"[..]
        );
        connection.close(0_u32.into(), b"done");
        assert!(
            send(connection.clone(), Bytes::from_static(b"closed"))
                .await
                .is_err()
        );
    })
    .await
    .unwrap();
    client.wait_idle().await;
    server.wait_idle().await;
}
