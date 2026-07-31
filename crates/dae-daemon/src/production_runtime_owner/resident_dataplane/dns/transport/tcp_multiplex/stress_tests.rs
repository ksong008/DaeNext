use super::*;

use futures_util::stream::{FuturesUnordered, StreamExt};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TCP_MULTIPLEX_STRESS_TOTAL: usize = 10_000;
const TCP_MULTIPLEX_STRESS_CONCURRENCY: usize = 128;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_multiplex_preserves_every_response_under_sustained_concurrency() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        for _ in 0..TCP_MULTIPLEX_STRESS_TOTAL {
            let request = read_frame(&mut stream).await;
            write_response(&mut stream, &request).await;
        }
    });

    let stream = TokioTcpStream::connect(target).await.unwrap();
    let (handle, registration) = ResidentDnsTcpMultiplexHandle::new(256);
    let actor = tokio::spawn(registration.run(stream));
    let mut requests = FuturesUnordered::new();
    let mut completed = 0_usize;

    for index in 0..TCP_MULTIPLEX_STRESS_TOTAL {
        let handle = handle.clone();
        requests.push(async move {
            let original_id = (index as u16).wrapping_add(1);
            let query = build_dns_query_packet(
                original_id,
                &format!("tcp-stress-{index}.example"),
                DNS_QTYPE_A,
            )
            .unwrap();
            let response = handle
                .exchange(
                    &query,
                    ProxyDnsRequestContext::from_timeout(Duration::from_secs(2)),
                )
                .await?;
            assert_eq!(&response[0..2], &original_id.to_be_bytes());
            Ok::<(), ProxyDnsRequestError>(())
        });
        while requests.len() >= TCP_MULTIPLEX_STRESS_CONCURRENCY {
            requests.next().await.unwrap().unwrap();
            completed += 1;
        }
    }
    while let Some(result) = requests.next().await {
        result.unwrap();
        completed += 1;
    }

    assert_eq!(completed, TCP_MULTIPLEX_STRESS_TOTAL);
    assert_eq!(handle.pending(), 0);
    handle.close();
    actor.await.unwrap().unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_multiplex_discards_a_queued_request_cancelled_while_command_queue_is_full() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = listener.local_addr().unwrap();
    let stream = TokioTcpStream::connect(target).await.unwrap();
    let (mut upstream, _) = listener.accept().await.unwrap();
    let (handle, registration) = ResidentDnsTcpMultiplexHandle::new(1);
    let query = build_dns_query_packet(0x4455, "cancelled.example", DNS_QTYPE_A).unwrap();
    let request_handle = handle.clone();
    let request = tokio::spawn(async move {
        request_handle
            .exchange(
                &query,
                ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
            )
            .await
    });
    time::timeout(Duration::from_millis(200), async {
        while handle.pending() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    request.abort();
    let _ = request.await;

    let actor = tokio::spawn(registration.run(stream));
    time::timeout(Duration::from_millis(200), async {
        while handle.pending() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled queued request retained its multiplex slot");
    assert!(
        time::timeout(Duration::from_millis(20), read_frame(&mut upstream))
            .await
            .is_err(),
        "cancelled queued request was written upstream"
    );
    handle.close();
    actor.await.unwrap().unwrap();
}

async fn read_frame(stream: &mut TokioTcpStream) -> Vec<u8> {
    let len = stream.read_u16().await.unwrap() as usize;
    let mut payload = vec![0_u8; len];
    stream.read_exact(&mut payload).await.unwrap();
    payload
}

async fn write_response(stream: &mut TokioTcpStream, request: &[u8]) {
    let view = DnsPacketView::parse(request).unwrap();
    let mut response = Vec::new();
    response.extend_from_slice(&request[0..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&request[12..view.answer_offset()]);
    response.extend_from_slice(&0xc00c_u16.to_be_bytes());
    response.extend_from_slice(&DNS_QTYPE_A.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&60_u32.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&[198, 51, 100, 42]);
    stream.write_u16(response.len() as u16).await.unwrap();
    tokio::task::yield_now().await;
    for chunk in response.chunks(7) {
        stream.write_all(chunk).await.unwrap();
        tokio::task::yield_now().await;
    }
}
