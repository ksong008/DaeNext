use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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
        self.inner
            .activity
            .send_modify(|sequence| *sequence = sequence.wrapping_add(1));
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
                    reset_resident_relay_idle_deadline(
                        idle_deadline.as_mut(),
                        RESIDENT_TCP_IDLE_TIMEOUT,
                    );
                }
            }
            _ = &mut close_drain_deadline, if upload_done && half_close_drain_timeout.is_some() => {
                return Ok(progress.snapshot());
            }
            _ = &mut idle_deadline => return Err(idle_error.to_owned()),
        }
    }
}
