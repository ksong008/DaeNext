use super::*;
use std::collections::BTreeMap;
use tokio::sync::{mpsc, oneshot};

fn packet_up_endpoint() -> ResidentXhttpEndpointPlan {
    ResidentXhttpEndpointPlan {
        server_host: "xhttp.test".to_owned(),
        server_port: 443,
        server_name: "xhttp.test".to_owned(),
        alpn: vec!["h2".to_owned()],
        stream_host: "xhttp.test".to_owned(),
        stream_path: "/xhttp".to_owned(),
        mode: ResidentXhttpMode::PacketUp,
        settings: ResidentXhttpSettingsPlan::official_default(),
        xmux: None,
        allow_insecure: false,
        tls_fragment: None,
        utls_fingerprint: None,
        ech: None,
        reality: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delayed_h2_responses_do_not_serialize_packet_up_requests() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (mut sender, connection) = h2::client::handshake(client_io).await.unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let (accepted_tx, mut accepted_rx) = mpsc::channel(3);
    let (response_sent_tx, mut response_sent_rx) = mpsc::channel(3);
    let (server_release_tx, server_release_rx) = oneshot::channel();
    let mut release_senders = BTreeMap::new();
    let mut release_receivers = BTreeMap::new();
    for seq in 1..=3 {
        let (release_tx, release_rx) = oneshot::channel();
        release_senders.insert(seq, release_tx);
        release_receivers.insert(seq, release_rx);
    }
    let server_task = tokio::spawn(async move {
        let mut builder = h2::server::Builder::new();
        builder.max_concurrent_streams(100);
        let mut server = builder.handshake::<_, Bytes>(server_io).await.unwrap();
        let mut handlers = tokio::task::JoinSet::new();
        for _ in 0..3 {
            let (request, mut response) = server.accept().await.unwrap().unwrap();
            let seq = request
                .uri()
                .path()
                .rsplit('/')
                .next()
                .unwrap()
                .parse::<u64>()
                .unwrap();
            let accepted_tx = accepted_tx.clone();
            let response_sent_tx = response_sent_tx.clone();
            let release = release_receivers.remove(&seq).unwrap();
            handlers.spawn(async move {
                let mut response_stream = response
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                accepted_tx.send(seq).await.unwrap();
                release.await.unwrap();
                drop(request);
                response_stream
                    .send_data(Bytes::from_static(b"ok"), true)
                    .unwrap();
                response_sent_tx.send(seq).await.unwrap();
            });
        }
        drop(accepted_tx);
        drop(response_sent_tx);
        while !handlers.is_empty() {
            tokio::select! {
                result = handlers.join_next() => result.unwrap().unwrap(),
                accepted = server.accept() => {
                    assert!(accepted.is_none(), "unexpected extra H2 packet-up request");
                }
            }
        }
        tokio::pin!(server_release_rx);
        loop {
            tokio::select! {
                result = &mut server_release_rx => {
                    result.unwrap();
                    break;
                }
                accepted = server.accept() => {
                    assert!(accepted.is_none(), "unexpected extra H2 packet-up request");
                }
            }
        }
    });

    let endpoint = packet_up_endpoint();
    let mut completions = Vec::new();
    for (seq, payload) in [
        (1, Bytes::from_static(b"first")),
        (2, Bytes::from_static(b"second")),
        (3, Bytes::from_static(b"third")),
    ] {
        let completion = time::timeout(
            Duration::from_secs(1),
            begin_xhttp_h2_packet_up_request(&mut sender, &endpoint, "session", seq, payload),
        )
        .await
        .expect("packet-up begin waited for response")
        .unwrap();
        completions.push(completion);
    }

    let mut accepted = Vec::new();
    for _ in 0..3 {
        accepted.push(
            time::timeout(Duration::from_secs(1), accepted_rx.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    accepted.sort_unstable();
    assert_eq!(accepted, vec![1, 2, 3]);

    release_senders.remove(&3).unwrap().send(()).unwrap();
    assert_eq!(
        time::timeout(Duration::from_secs(1), response_sent_rx.recv())
            .await
            .unwrap(),
        Some(3)
    );
    time::timeout(Duration::from_secs(1), completions.pop().unwrap())
        .await
        .unwrap()
        .unwrap();
    release_senders.remove(&2).unwrap().send(()).unwrap();
    time::timeout(Duration::from_secs(1), completions.pop().unwrap())
        .await
        .unwrap()
        .unwrap();
    release_senders.remove(&1).unwrap().send(()).unwrap();
    time::timeout(Duration::from_secs(1), completions.pop().unwrap())
        .await
        .unwrap()
        .unwrap();

    server_release_tx.send(()).unwrap();
    drop(sender);
    server_task.await.unwrap();
    connection_task.await.unwrap();
}
