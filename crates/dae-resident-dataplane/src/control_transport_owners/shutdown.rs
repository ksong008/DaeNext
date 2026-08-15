use super::*;
use futures_util::{StreamExt, stream::FuturesUnordered};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ControlTransportOwnerShutdown {
    pub(crate) joined: usize,
    pub(crate) cancelled: usize,
    pub(crate) panicked: usize,
    pub(crate) forced: usize,
}

impl ControlTransportOwnerShutdown {
    pub(crate) fn is_clean(self) -> bool {
        self.cancelled == 0 && self.panicked == 0 && self.forced == 0
    }
}

pub(super) async fn shutdown_control_transport_owner_tasks(
    tasks: &mut Vec<tokio::task::JoinHandle<()>>,
    timeout: Duration,
) -> ControlTransportOwnerShutdown {
    let abort_handles = tasks
        .iter()
        .map(tokio::task::JoinHandle::abort_handle)
        .collect::<Vec<_>>();
    let mut pending = tasks.drain(..).collect::<FuturesUnordered<_>>();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut shutdown = ControlTransportOwnerShutdown::default();
    loop {
        match tokio::time::timeout_at(deadline, pending.next()).await {
            Ok(Some(result)) => record_completion(&mut shutdown, result, false),
            Ok(None) => break,
            Err(_) => {
                shutdown.forced = shutdown.forced.saturating_add(pending.len());
                for handle in &abort_handles {
                    handle.abort();
                }
                while let Some(result) = pending.next().await {
                    record_completion(&mut shutdown, result, true);
                }
                break;
            }
        }
    }
    shutdown
}

fn record_completion(
    shutdown: &mut ControlTransportOwnerShutdown,
    result: Result<(), tokio::task::JoinError>,
    forced: bool,
) {
    match result {
        Ok(()) => shutdown.joined = shutdown.joined.saturating_add(1),
        Err(error) if error.is_cancelled() => {
            shutdown.cancelled = shutdown.cancelled.saturating_add(1);
            debug_assert!(
                forced,
                "control transport owner cancelled before forced shutdown"
            );
        }
        Err(_) => shutdown.panicked = shutdown.panicked.saturating_add(1),
    }
}
