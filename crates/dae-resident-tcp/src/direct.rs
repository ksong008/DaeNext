#[cfg(test)]
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream as TokioTcpStream;
#[cfg(test)]
use tokio::time;

pub use dae_resident_transport::{DirectTcpConnection, open_direct_tcp_connection_async};

#[cfg(test)]
use dae_resident_core::ResidentStopSignal;
use dae_resident_core::{ResidentDataplaneMetrics, SharedResidentStopSignal};

use super::relay_raw_tcp_streams;

#[derive(Default, Debug, Eq, PartialEq)]
pub struct DirectTcpRelayStats {
    pub client_to_direct: usize,
    pub direct_to_client: usize,
}

pub async fn relay_tcp_direct_async(
    inbound: &mut TokioTcpStream,
    direct: &mut TokioTcpStream,
    stop: SharedResidentStopSignal,
    initial_payload: Vec<u8>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut stats = DirectTcpRelayStats::default();
    if !initial_payload.is_empty() {
        direct
            .write_all(&initial_payload)
            .await
            .map_err(|err| format!("write sniffed client payload to direct TCP: {err}"))?;
        stats.client_to_direct += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }
    drop(initial_payload);

    relay_raw_tcp_streams(inbound, direct, stop, stats, metrics).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, atomic::Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    #[tokio::test(flavor = "current_thread")]
    async fn resident_direct_async_relay_preserves_sniffed_initial_payload() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_done = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut got = [0_u8; 5];
            stream.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"HELLO");
            stream.write_all(b"WORLD").unwrap();
        });

        let inbound_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let inbound_addr = inbound_listener.local_addr().unwrap();
        let client = TcpStream::connect(inbound_addr).unwrap();
        let (inbound, _) = inbound_listener.accept().unwrap();
        let direct = TcpStream::connect(upstream_addr).unwrap();
        inbound.set_nonblocking(true).unwrap();
        direct.set_nonblocking(true).unwrap();

        let mut inbound = TokioTcpStream::from_std(inbound).unwrap();
        let mut direct = TokioTcpStream::from_std(direct).unwrap();
        let stop = ResidentStopSignal::shared();
        let metrics = ResidentDataplaneMetrics::default();
        let stats = relay_tcp_direct_async(
            &mut inbound,
            &mut direct,
            Arc::clone(&stop),
            b"HELLO".to_vec(),
            &metrics,
        )
        .await
        .unwrap();
        assert_eq!(stats.client_to_direct, 5);
        assert_eq!(stats.direct_to_client, 5);

        let mut client = client;
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut response = [0_u8; 5];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"WORLD");
        stop.store(true, Ordering::Relaxed);
        upstream_done.join().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn direct_tcp_relay_preserves_download_after_client_half_close() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_done = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"request");
            stream.write_all(b"response-after-eof").unwrap();
        });

        let inbound_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let inbound_addr = inbound_listener.local_addr().unwrap();
        let mut client = TcpStream::connect(inbound_addr).unwrap();
        let (inbound, _) = inbound_listener.accept().unwrap();
        let direct = TcpStream::connect(upstream_addr).unwrap();
        inbound.set_nonblocking(true).unwrap();
        direct.set_nonblocking(true).unwrap();
        client.write_all(b"request").unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        let mut inbound = TokioTcpStream::from_std(inbound).unwrap();
        let mut direct = TokioTcpStream::from_std(direct).unwrap();
        let metrics = ResidentDataplaneMetrics::default();
        let stats = relay_tcp_direct_async(
            &mut inbound,
            &mut direct,
            ResidentStopSignal::shared(),
            Vec::new(),
            &metrics,
        )
        .await
        .unwrap();
        assert_eq!(stats.client_to_direct, b"request".len());
        assert_eq!(stats.direct_to_client, b"response-after-eof".len());

        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"response-after-eof");
        upstream_done.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn direct_tcp_relay_download_progresses_while_upload_is_backpressured() {
        let (mut inbound, client) = tokio_tcp_pair().unwrap();
        let (mut direct, mut upstream) = tokio_tcp_pair().unwrap();
        let stop = ResidentStopSignal::shared();
        let metrics = ResidentDataplaneMetrics::default();
        let relay = relay_tcp_direct_async(
            &mut inbound,
            &mut direct,
            Arc::clone(&stop),
            Vec::new(),
            &metrics,
        );
        let exchange = async {
            let (mut client_read, mut client_write) = client.into_split();
            let upload = tokio::spawn(async move {
                let chunk = [0x5a; 64 * 1024];
                for _ in 0..512 {
                    client_write.write_all(&chunk).await?;
                }
                Ok::<(), io::Error>(())
            });
            upstream.write_all(b"download while blocked").await.unwrap();
            let mut response = [0_u8; 22];
            time::timeout(
                Duration::from_secs(1),
                client_read.read_exact(&mut response),
            )
            .await
            .expect("download stalled behind the backpressured upload")
            .unwrap();
            assert_eq!(&response, b"download while blocked");
            stop.store(true, Ordering::Release);
            upload.abort();
            let _ = upload.await;
        };

        let (stats, ()) = tokio::join!(relay, exchange);
        let stats = stats.unwrap();
        assert_eq!(stats.direct_to_client, b"download while blocked".len());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resident_direct_async_relay_stops_without_timer_polling() {
        let inbound_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let inbound_client = TcpStream::connect(inbound_listener.local_addr().unwrap()).unwrap();
        let (inbound, _) = inbound_listener.accept().unwrap();
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let direct = TcpStream::connect(upstream_listener.local_addr().unwrap()).unwrap();
        let (upstream_peer, _) = upstream_listener.accept().unwrap();
        inbound.set_nonblocking(true).unwrap();
        direct.set_nonblocking(true).unwrap();
        let mut inbound = TokioTcpStream::from_std(inbound).unwrap();
        let mut direct = TokioTcpStream::from_std(direct).unwrap();
        let stop = ResidentStopSignal::shared();
        let metrics = ResidentDataplaneMetrics::default();
        let relay = relay_tcp_direct_async(
            &mut inbound,
            &mut direct,
            Arc::clone(&stop),
            Vec::new(),
            &metrics,
        );
        tokio::pin!(relay);

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut relay)
                .await
                .is_err()
        );
        stop.store(true, Ordering::Relaxed);
        let stats = tokio::time::timeout(Duration::from_millis(50), &mut relay)
            .await
            .expect("direct relay did not observe stop broadcast")
            .unwrap();
        assert_eq!(stats, DirectTcpRelayStats::default());
        drop((inbound_client, upstream_peer));
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "explicit high-concurrency direct TCP relay benchmark"]
    async fn direct_tcp_relay_high_concurrency_benchmark() {
        const PAYLOAD_BYTES: usize = 64 * 1024;
        const CONCURRENCY_LEVELS: [usize; 3] = [64, 256, 1_024];

        for concurrency in CONCURRENCY_LEVELS {
            let result = time::timeout(
                Duration::from_secs(30),
                benchmark_direct_tcp_relays(concurrency, PAYLOAD_BYTES),
            )
            .await
            .unwrap_or_else(|_| {
                panic!("{concurrency} direct TCP relays exceeded benchmark timeout")
            });
            let (mut flow_durations, batch_elapsed) = result.unwrap();
            flow_durations.sort_unstable();
            let elapsed = flow_durations.iter().copied().max().unwrap_or_default();
            let p99_index = flow_durations.len().saturating_sub(1).saturating_mul(99) / 100;
            let p99 = flow_durations[p99_index];
            let transferred_bytes = concurrency.saturating_mul(PAYLOAD_BYTES).saturating_mul(2);
            eprintln!(
                "direct_tcp_relay_concurrency_benchmark {}",
                serde_json::json!({
                    "concurrency": concurrency,
                    "payloadBytesPerDirection": PAYLOAD_BYTES,
                    "transferredBytes": transferred_bytes,
                    "batchElapsedNs": batch_elapsed.as_nanos(),
                    "bytesPerSecond": transferred_bytes as f64 / batch_elapsed.as_secs_f64(),
                    "maximumFlowNs": elapsed.as_nanos(),
                    "p99FlowNs": p99.as_nanos(),
                })
            );
        }
    }

    async fn benchmark_direct_tcp_relays(
        concurrency: usize,
        payload_bytes: usize,
    ) -> Result<(Vec<Duration>, Duration), String> {
        let stop = ResidentStopSignal::shared();
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let start_barrier = Arc::new(tokio::sync::Barrier::new(concurrency.saturating_add(1)));
        let mut flows = tokio::task::JoinSet::new();
        for _ in 0..concurrency {
            let (mut inbound, mut client) = tokio_tcp_pair()?;
            let (mut direct, mut upstream) = tokio_tcp_pair()?;
            let stop = Arc::clone(&stop);
            let metrics = Arc::clone(&metrics);
            let start_barrier = Arc::clone(&start_barrier);
            flows.spawn(async move {
                start_barrier.wait().await;
                let started = Instant::now();
                let initial_payload = vec![7_u8; payload_bytes];
                let relay = relay_tcp_direct_async(
                    &mut inbound,
                    &mut direct,
                    stop,
                    initial_payload,
                    metrics.as_ref(),
                );
                let client_exchange = async {
                    let mut response = vec![0_u8; payload_bytes];
                    client
                        .read_exact(&mut response)
                        .await
                        .map_err(|err| format!("read relayed response: {err}"))?;
                    if response.iter().any(|byte| *byte != 9) {
                        return Err("direct TCP relay response payload mismatch".to_owned());
                    }
                    client
                        .shutdown()
                        .await
                        .map_err(|err| format!("shutdown relay client: {err}"))?;
                    Ok::<(), String>(())
                };
                let upstream_exchange = async {
                    let mut request = vec![0_u8; payload_bytes];
                    upstream
                        .read_exact(&mut request)
                        .await
                        .map_err(|err| format!("read relayed request: {err}"))?;
                    if request.iter().any(|byte| *byte != 7) {
                        return Err("direct TCP relay request payload mismatch".to_owned());
                    }
                    let response = vec![9_u8; payload_bytes];
                    upstream
                        .write_all(&response)
                        .await
                        .map_err(|err| format!("write relay response: {err}"))?;
                    upstream
                        .shutdown()
                        .await
                        .map_err(|err| format!("shutdown relay upstream: {err}"))?;
                    Ok::<(), String>(())
                };
                let (stats, (), ()) = tokio::try_join!(relay, client_exchange, upstream_exchange)?;
                if stats.client_to_direct != payload_bytes
                    || stats.direct_to_client != payload_bytes
                {
                    return Err(format!("unexpected direct TCP relay stats: {stats:?}"));
                }
                Ok::<Duration, String>(started.elapsed())
            });
        }

        let mut durations = Vec::with_capacity(concurrency);
        let batch_started = Instant::now();
        start_barrier.wait().await;
        while let Some(result) = flows.join_next().await {
            durations.push(result.map_err(|err| format!("join direct TCP relay: {err}"))??);
        }
        Ok((durations, batch_started.elapsed()))
    }

    fn tokio_tcp_pair() -> Result<(TokioTcpStream, TokioTcpStream), String> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|err| format!("bind TCP relay benchmark listener: {err}"))?;
        let peer = TcpStream::connect(
            listener
                .local_addr()
                .map_err(|err| format!("read TCP relay benchmark listener address: {err}"))?,
        )
        .map_err(|err| format!("connect TCP relay benchmark peer: {err}"))?;
        let (relay, _) = listener
            .accept()
            .map_err(|err| format!("accept TCP relay benchmark peer: {err}"))?;
        peer.set_nonblocking(true)
            .map_err(|err| format!("set TCP relay benchmark peer nonblocking: {err}"))?;
        relay
            .set_nonblocking(true)
            .map_err(|err| format!("set TCP relay benchmark stream nonblocking: {err}"))?;
        Ok((
            TokioTcpStream::from_std(relay)
                .map_err(|err| format!("adopt TCP relay benchmark stream: {err}"))?,
            TokioTcpStream::from_std(peer)
                .map_err(|err| format!("adopt TCP relay benchmark peer: {err}"))?,
        ))
    }
}
