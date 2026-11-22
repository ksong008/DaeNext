use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn spawned_logical_stream_is_bounded_and_duplex() {
    let mut stream = SpawnedLogicalStream::spawn(|mut transport| async move {
        let mut payload = [0_u8; 4];
        transport
            .read_exact(&mut payload)
            .await
            .map_err(|error| error.to_string())?;
        transport
            .write_all(&payload)
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    });
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"ping");
}

#[tokio::test]
async fn spawned_logical_stream_surfaces_driver_failure() {
    let mut stream =
        SpawnedLogicalStream::spawn(
            |_transport| async move { Err("wrapper driver failed".to_owned()) },
        );
    tokio::task::yield_now().await;
    let mut byte = [0_u8; 1];
    let error = stream.read(&mut byte).await.unwrap_err();
    assert!(error.to_string().contains("wrapper driver failed"));
}

#[tokio::test]
async fn timed_out_logical_stream_releases_driver_when_dropped() {
    struct DriverOwner(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DriverOwner {
        fn drop(&mut self) {
            if let Some(release) = self.0.take() {
                let _ = release.send(());
            }
        }
    }

    let (started, running) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let mut stream = SpawnedLogicalStream::spawn(|transport| async move {
        let _owner = DriverOwner(Some(release));
        started.send(()).unwrap();
        std::future::pending::<()>().await;
        drop(transport);
        Ok(())
    });
    running.await.unwrap();
    let mut byte = [0_u8; 1];
    assert!(
        tokio::time::timeout(std::time::Duration::ZERO, stream.read(&mut byte))
            .await
            .is_err()
    );
    drop(stream);
    tokio::time::timeout(std::time::Duration::from_secs(1), released)
        .await
        .unwrap()
        .unwrap();
}
