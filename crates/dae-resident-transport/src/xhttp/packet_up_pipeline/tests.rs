use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::oneshot;

#[tokio::test]
async fn post_wait_aggregates_later_arrivals_and_stops_at_post_bound() {
    use tokio::io::AsyncWriteExt;
    let (mut writer, mut reader) = tokio::io::duplex(128);
    let (ready_tx, ready_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        coalesce_until_ready(
            async {
                ready_rx.await.unwrap();
                Ok(())
            },
            &mut reader,
            Bytes::from_static(b"first"),
            10,
        )
        .await
        .unwrap()
    });
    tokio::task::yield_now().await;
    writer.write_all(b"second-and-tail").await.unwrap();
    tokio::task::yield_now().await;
    assert!(
        !task.is_finished(),
        "POST gate must remain authoritative when full"
    );
    ready_tx.send(()).unwrap();
    assert_eq!(task.await.unwrap(), Bytes::from_static(b"firstsecon"));
}

#[tokio::test]
async fn post_ready_does_not_wait_for_an_idle_reader_or_copy_the_payload() {
    let (_writer, mut reader) = tokio::io::duplex(128);
    let payload = Bytes::from_static(b"ready");
    let pointer = payload.as_ptr();
    let actual = time::timeout(
        Duration::from_millis(100),
        coalesce_until_ready(async { Ok(()) }, &mut reader, payload, 100),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(actual.as_ptr(), pointer);
}

#[tokio::test]
async fn post_wait_flushes_buffered_data_at_eof() {
    let (mut writer, mut reader) = tokio::io::duplex(128);
    writer.write_all(b"tail").await.unwrap();
    drop(writer);
    let actual = coalesce_until_ready(
        async {
            time::sleep(Duration::from_millis(5)).await;
            Ok(())
        },
        &mut reader,
        Bytes::from_static(b"head"),
        100,
    )
    .await
    .unwrap();
    assert_eq!(actual, Bytes::from_static(b"headtail"));
}

fn controlled_completion(
    receiver: oneshot::Receiver<Result<(), String>>,
) -> XhttpPacketUpCompletion {
    Box::pin(async move {
        receiver
            .await
            .map_err(|_| "test completion sender dropped".to_owned())?
    })
}

#[test]
fn packet_up_window_is_bounded_and_completion_order_is_independent() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut pipeline = XhttpPacketUpPipeline::for_test(2);
            let (first_tx, first_rx) = oneshot::channel();
            let (second_tx, second_rx) = oneshot::channel();
            pipeline.push_test_completion(controlled_completion(first_rx));
            pipeline.push_test_completion(controlled_completion(second_rx));

            assert!(
                time::timeout(Duration::from_millis(20), pipeline.wait_for_capacity())
                    .await
                    .is_err()
            );
            second_tx.send(Ok(())).unwrap();
            pipeline.wait_for_capacity().await.unwrap();
            assert_eq!(pipeline.completions.len(), 1);
            first_tx.send(Ok(())).unwrap();
            pipeline.finish().await.unwrap();
            assert!(!pipeline.has_in_flight());
        });
}

#[test]
fn packet_up_completion_error_is_terminal() {
    let mut pipeline = XhttpPacketUpPipeline::for_test(2);
    pipeline.push_test_completion(Box::pin(async { Err("post failed".to_owned()) }));
    assert_eq!(pipeline.poll_ready().unwrap_err(), "post failed");
}

#[test]
fn dropping_packet_up_pipeline_cancels_pending_completions() {
    struct DropGuard(Arc<AtomicBool>);

    impl Drop for DropGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    let dropped = Arc::new(AtomicBool::new(false));
    let guard = DropGuard(Arc::clone(&dropped));
    let pipeline = XhttpPacketUpPipeline::for_test(1);
    pipeline.push_test_completion(Box::pin(async move {
        let _guard = guard;
        std::future::pending::<Result<(), String>>().await
    }));
    drop(pipeline);
    assert!(dropped.load(Ordering::Relaxed));
}

#[test]
fn packet_up_payload_is_split_without_copying_the_backing_storage() {
    let pipeline = XhttpPacketUpPipeline {
        max_post_bytes: 3,
        ..XhttpPacketUpPipeline::for_test(2)
    };
    let mut payload = Bytes::from_static(b"abcdefgh");
    let original = payload.as_ptr();
    let first = pipeline.take_post_chunk(&mut payload);
    let second = pipeline.take_post_chunk(&mut payload);
    let third = pipeline.take_post_chunk(&mut payload);

    assert_eq!(first, Bytes::from_static(b"abc"));
    assert_eq!(second, Bytes::from_static(b"def"));
    assert_eq!(third, Bytes::from_static(b"gh"));
    assert_eq!(first.as_ptr(), original);
    assert_eq!(second.as_ptr() as usize, original as usize + 3);
    assert_eq!(third.as_ptr() as usize, original as usize + 6);
    assert!(payload.is_empty());
}

#[test]
fn packet_up_interval_gates_only_the_next_post_start() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut pipeline = XhttpPacketUpPipeline {
                min_post_interval_ms: (25, 25),
                last_post_started: Some(time::Instant::now()),
                ..XhttpPacketUpPipeline::for_test(2)
            };
            let (completion_tx, completion_rx) = oneshot::channel();
            pipeline.push_test_completion(controlled_completion(completion_rx));

            let started = time::Instant::now();
            pipeline.wait_post_interval().await;
            assert!(started.elapsed() >= Duration::from_millis(20));
            assert!(pipeline.has_in_flight());

            completion_tx.send(Ok(())).unwrap();
            pipeline.finish().await.unwrap();
        });
}
