use std::time::{Duration, Instant};

use tokio::sync::watch;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbsoluteDeadline(Instant);

impl AbsoluteDeadline {
    pub const fn at(instant: Instant) -> Self {
        Self(instant)
    }

    pub fn from_now(now: Instant, timeout: Duration) -> Self {
        Self(now.checked_add(timeout).unwrap_or(now))
    }

    pub const fn instant(self) -> Instant {
        self.0
    }

    pub fn remaining_at(self, now: Instant) -> Option<Duration> {
        self.0.checked_duration_since(now)
    }

    pub fn check_at(self, now: Instant) -> Result<(), OwnerCancellation> {
        if now >= self.0 {
            Err(OwnerCancellation::DeadlineElapsed)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerCancellation {
    CallerCancelled,
    DeadlineElapsed,
    GenerationDraining,
    OwnerFault,
    DependencyFailed,
}

#[derive(Clone, Debug)]
pub struct OwnerCancellationSignal {
    sender: watch::Sender<Option<OwnerCancellation>>,
}

impl Default for OwnerCancellationSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl OwnerCancellationSignal {
    pub fn new() -> Self {
        let (sender, _) = watch::channel(None);
        Self { sender }
    }

    pub fn cancel(&self, reason: OwnerCancellation) -> bool {
        self.sender.send_if_modified(|current| {
            if current.is_some() {
                false
            } else {
                *current = Some(reason);
                true
            }
        })
    }

    pub fn reason(&self) -> Option<OwnerCancellation> {
        *self.sender.borrow()
    }

    pub fn check(&self) -> Result<(), OwnerCancellation> {
        self.reason().map_or(Ok(()), Err)
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<Option<OwnerCancellation>> {
        self.sender.subscribe()
    }
}
