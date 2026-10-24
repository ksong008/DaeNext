use super::*;

#[tokio::test]
async fn udp_actor_seals_queue_and_releases_work_before_awaiting_shutdown() {
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let (sender, mut receiver) = mpsc::channel(2);
    sender
        .try_send((
            vec![0_u8; 17],
            ResidentUdpWorkGuard::new(Arc::clone(&metrics), ResidentUdpWorkStage::Session),
        ))
        .unwrap();
    let (release, released) = tokio::sync::oneshot::channel();
    let finish = finish_udp_actor_queue(&mut receiver, &metrics, |packet| packet.0.len(), async {
        released.await.unwrap();
    });
    tokio::pin!(finish);
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(finish.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert!(sender.is_closed());
    let rejected = sender.try_send((
        Vec::new(),
        ResidentUdpWorkGuard::new(Arc::clone(&metrics), ResidentUdpWorkStage::Session),
    ));
    assert!(matches!(
        rejected,
        Err(mpsc::error::TrySendError::Closed(_))
    ));
    drop(rejected);
    assert_eq!(metrics.snapshot()["udpSessionQueuedCurrent"], 0);
    assert_eq!(metrics.snapshot()["udpSessionQueuedDropped"], 1);
    assert_eq!(metrics.snapshot()["udpSessionQueuedDroppedBytes"], 17);
    release.send(()).unwrap();
    assert_eq!(finish.await, 1);
}

#[tokio::test]
async fn cancelling_a_dequeued_batch_accounts_only_for_uncompleted_members() {
    let metrics = ResidentDataplaneMetrics::default();
    let batch = [10, 20, 30].map(|bytes| UdpQueuedPacketGuard::new(&metrics, bytes));
    let mut execution = Box::pin(async move {
        for (index, mut packet) in batch.into_iter().enumerate() {
            if index == 1 {
                std::future::pending::<()>().await;
            }
            packet.complete();
        }
    });
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(execution.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    // Drop the real future, including its remaining iterator, before observing.
    drop(execution);
    assert_eq!(metrics.snapshot()["udpSessionQueuedDropped"], 2);
    assert_eq!(metrics.snapshot()["udpSessionQueuedDroppedBytes"], 50);
}
