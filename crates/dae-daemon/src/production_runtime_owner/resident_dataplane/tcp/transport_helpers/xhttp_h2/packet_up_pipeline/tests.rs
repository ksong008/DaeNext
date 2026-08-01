use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::oneshot;

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
