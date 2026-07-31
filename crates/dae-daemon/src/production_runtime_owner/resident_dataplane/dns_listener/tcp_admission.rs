use super::*;

pub(super) enum ResidentDnsTcpBindAdmission {
    Accepted {
        stream: TokioTcpStream,
        peer: SocketAddr,
        permit: tokio::sync::OwnedSemaphorePermit,
        waited: bool,
    },
    Stopped,
}

pub(super) async fn accept_resident_dns_tcp_bind_connection_async<F>(
    listener: &TokioTcpListener,
    semaphore: &Arc<Semaphore>,
    tasks: &mut tokio::task::JoinSet<()>,
    stop: &SharedResidentStopSignal,
    on_wait: F,
) -> io::Result<ResidentDnsTcpBindAdmission>
where
    F: FnOnce(),
{
    let mut stop_listener = stop.listener();
    let (permit, waited) = match Arc::clone(semaphore).try_acquire_owned() {
        Ok(permit) => (permit, false),
        Err(tokio::sync::TryAcquireError::Closed) => {
            return Ok(ResidentDnsTcpBindAdmission::Stopped);
        }
        Err(tokio::sync::TryAcquireError::NoPermits) => {
            on_wait();
            let permit = loop {
                tokio::select! {
                    biased;
                    _ = stop_listener.cancelled() => {
                        return Ok(ResidentDnsTcpBindAdmission::Stopped);
                    }
                    _ = tasks.join_next(), if !tasks.is_empty() => {}
                    permit = Arc::clone(semaphore).acquire_owned() => match permit {
                        Ok(permit) => break permit,
                        Err(_) => return Ok(ResidentDnsTcpBindAdmission::Stopped),
                    }
                }
            };
            (permit, true)
        }
    };

    let (stream, peer) = loop {
        tokio::select! {
            biased;
            _ = stop_listener.cancelled() => {
                return Ok(ResidentDnsTcpBindAdmission::Stopped);
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => break accepted,
        }
    }?;
    stream.set_nodelay(true)?;
    Ok(ResidentDnsTcpBindAdmission::Accepted {
        stream,
        peer,
        permit,
        waited,
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::atomic::AtomicUsize;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn saturated_admission_keeps_connections_in_the_kernel_backlog() {
        let listener = TokioTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let local_addr = listener.local_addr().unwrap();
        let semaphore = Arc::new(Semaphore::new(1));
        let held_permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
        let stop = ResidentStopSignal::shared();
        let mut tasks = tokio::task::JoinSet::new();
        let waits = Arc::new(AtomicUsize::new(0));
        let waits_for_admission = Arc::clone(&waits);
        let mut admission = Box::pin(accept_resident_dns_tcp_bind_connection_async(
            &listener,
            &semaphore,
            &mut tasks,
            &stop,
            move || {
                waits_for_admission.fetch_add(1, Ordering::Relaxed);
            },
        ));
        let mut client = TokioTcpStream::connect(local_addr).await.unwrap();
        client.write_all(b"pending").await.unwrap();

        assert!(
            time::timeout(Duration::from_millis(20), &mut admission)
                .await
                .is_err()
        );
        assert_eq!(waits.load(Ordering::Relaxed), 1);
        let mut byte = [0_u8; 1];
        assert!(
            time::timeout(Duration::from_millis(20), client.read(&mut byte))
                .await
                .is_err(),
            "saturated DNS TCP admission actively closed a backlogged connection"
        );

        drop(held_permit);
        let ResidentDnsTcpBindAdmission::Accepted {
            mut stream,
            permit,
            waited,
            ..
        } = time::timeout(Duration::from_secs(1), admission)
            .await
            .unwrap()
            .unwrap()
        else {
            panic!("DNS TCP admission stopped before accepting a backlogged connection");
        };
        assert!(waited);
        assert!(stream.nodelay().unwrap());
        let mut payload = [0_u8; 7];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"pending");
        drop(permit);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stop_cancels_a_saturated_admission_wait() {
        let listener = TokioTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let semaphore = Arc::new(Semaphore::new(1));
        let _held_permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
        let stop = ResidentStopSignal::shared();
        let stop_request = Arc::clone(&stop);
        let stopper = tokio::spawn(async move {
            tokio::task::yield_now().await;
            stop_request.store(true, Ordering::Release);
        });
        let mut tasks = tokio::task::JoinSet::new();

        let admission = time::timeout(
            Duration::from_secs(1),
            accept_resident_dns_tcp_bind_connection_async(
                &listener,
                &semaphore,
                &mut tasks,
                &stop,
                || {},
            ),
        )
        .await
        .expect("DNS TCP admission ignored the stop signal")
        .unwrap();
        assert!(matches!(admission, ResidentDnsTcpBindAdmission::Stopped));
        stopper.await.unwrap();
    }
}
