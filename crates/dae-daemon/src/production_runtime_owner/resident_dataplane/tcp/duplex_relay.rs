use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tokio::sync::watch;

use super::*;

mod raw_tcp;
pub(in crate::production_runtime_owner::resident_dataplane) use self::raw_tcp::*;

pub(in crate::production_runtime_owner::resident_dataplane) type ResidentDuplexDirectionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
pub(in crate::production_runtime_owner::resident_dataplane) type ResidentDuplexDirection<'a> =
    Pin<&'a mut (dyn Future<Output = Result<(), String>> + Send + 'a)>;

#[derive(Clone)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentDuplexProgress {
    inner: Arc<ResidentDuplexProgressInner>,
}

pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentDuplexActivity {
    receiver: watch::Receiver<u64>,
}

struct ResidentDuplexProgressInner {
    upload_bytes: AtomicUsize,
    download_bytes: AtomicUsize,
    activity_pending: AtomicBool,
    activity: watch::Sender<u64>,
}

pub(in crate::production_runtime_owner::resident_dataplane) fn resident_duplex_progress()
-> (ResidentDuplexProgress, ResidentDuplexActivity) {
    let (activity, receiver) = watch::channel(0_u64);
    (
        ResidentDuplexProgress {
            inner: Arc::new(ResidentDuplexProgressInner {
                upload_bytes: AtomicUsize::new(0),
                download_bytes: AtomicUsize::new(0),
                activity_pending: AtomicBool::new(false),
                activity,
            }),
        },
        ResidentDuplexActivity { receiver },
    )
}

impl ResidentDuplexProgress {
    pub(in crate::production_runtime_owner::resident_dataplane) fn record_upload(
        &self,
        bytes: usize,
    ) {
        self.inner.upload_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.note_activity();
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn record_download(
        &self,
        bytes: usize,
    ) {
        self.inner
            .download_bytes
            .fetch_add(bytes, Ordering::Relaxed);
        self.note_activity();
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn snapshot(
        &self,
    ) -> DirectTcpRelayStats {
        DirectTcpRelayStats {
            client_to_direct: self.inner.upload_bytes.load(Ordering::Relaxed),
            direct_to_client: self.inner.download_bytes.load(Ordering::Relaxed),
        }
    }

    fn note_activity(&self) {
        if !self.inner.activity_pending.load(Ordering::Acquire)
            && self
                .inner
                .activity_pending
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            self.inner
                .activity
                .send_modify(|sequence| *sequence = sequence.wrapping_add(1));
        }
    }

    fn acknowledge_activity(&self) {
        self.inner.activity_pending.store(false, Ordering::Release);
    }
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn run_resident_duplex_relay(
    mut upload: ResidentDuplexDirectionFuture<'_>,
    mut download: ResidentDuplexDirectionFuture<'_>,
    stop: SharedResidentStopSignal,
    progress: &ResidentDuplexProgress,
    activity: ResidentDuplexActivity,
    idle_error: &'static str,
    half_close_drain_timeout: Option<std::time::Duration>,
) -> Result<DirectTcpRelayStats, String> {
    run_resident_duplex_relay_borrowed(
        upload.as_mut(),
        download.as_mut(),
        stop,
        progress,
        activity,
        idle_error,
        half_close_drain_timeout,
    )
    .await
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn run_resident_duplex_relay_borrowed(
    mut upload: ResidentDuplexDirection<'_>,
    mut download: ResidentDuplexDirection<'_>,
    stop: SharedResidentStopSignal,
    progress: &ResidentDuplexProgress,
    mut activity: ResidentDuplexActivity,
    idle_error: &'static str,
    half_close_drain_timeout: Option<std::time::Duration>,
) -> Result<DirectTcpRelayStats, String> {
    let mut upload_done = false;
    let mut stop_listener = stop.listener();
    let idle_deadline = resident_relay_idle_deadline(RESIDENT_TCP_IDLE_TIMEOUT);
    let close_drain_deadline =
        resident_relay_idle_deadline(half_close_drain_timeout.unwrap_or(RESIDENT_TCP_IDLE_TIMEOUT));
    tokio::pin!(idle_deadline);
    tokio::pin!(close_drain_deadline);

    loop {
        tokio::select! {
            _ = stop_listener.cancelled() => return Ok(progress.snapshot()),
            result = &mut upload, if !upload_done => {
                result?;
                upload_done = true;
                reset_resident_relay_idle_deadline(
                    idle_deadline.as_mut(),
                    RESIDENT_TCP_IDLE_TIMEOUT,
                );
                if let Some(timeout) = half_close_drain_timeout {
                    reset_resident_relay_idle_deadline(close_drain_deadline.as_mut(), timeout);
                }
            }
            result = &mut download => {
                result?;
                return Ok(progress.snapshot());
            }
            changed = activity.receiver.changed() => {
                if changed.is_ok() {
                    progress.acknowledge_activity();
                    reset_resident_relay_idle_deadline(
                        idle_deadline.as_mut(),
                        RESIDENT_TCP_IDLE_TIMEOUT,
                    );
                    if upload_done
                        && let Some(timeout) = half_close_drain_timeout
                    {
                        reset_resident_relay_idle_deadline(
                            close_drain_deadline.as_mut(),
                            timeout,
                        );
                    }
                }
            }
            _ = &mut close_drain_deadline, if upload_done && half_close_drain_timeout.is_some() => {
                return Ok(progress.snapshot());
            }
            _ = &mut idle_deadline => return Err(idle_error.to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplex_activity_coalesces_until_the_relay_acknowledges_it() {
        let (progress, mut activity) = resident_duplex_progress();

        for _ in 0..64 {
            progress.record_upload(1);
        }
        assert!(activity.receiver.has_changed().unwrap());
        assert_eq!(*activity.receiver.borrow_and_update(), 1);
        assert_eq!(progress.snapshot().client_to_direct, 64);

        progress.acknowledge_activity();
        progress.record_download(7);
        assert!(activity.receiver.has_changed().unwrap());
        assert_eq!(*activity.receiver.borrow_and_update(), 2);
        assert_eq!(progress.snapshot().direct_to_client, 7);
    }

    #[tokio::test]
    async fn half_close_drain_deadline_tracks_continuing_download_progress() {
        let (progress, activity) = resident_duplex_progress();
        let download_progress = progress.clone();
        let upload = async { Ok(()) };
        let download = async move {
            for _ in 0..4 {
                tokio::time::sleep(std::time::Duration::from_millis(60)).await;
                download_progress.record_download(1);
            }
            Ok(())
        };

        let stats = run_resident_duplex_relay(
            Box::pin(upload),
            Box::pin(download),
            ResidentStopSignal::shared(),
            &progress,
            activity,
            "test relay idle timeout",
            Some(std::time::Duration::from_millis(100)),
        )
        .await
        .unwrap();

        assert_eq!(stats.direct_to_client, 4);
    }
}
