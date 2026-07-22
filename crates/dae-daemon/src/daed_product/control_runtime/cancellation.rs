use super::*;

#[derive(Clone, Debug)]
pub(in crate::daed_product) struct ProductControlCancellation {
    requested: Arc<AtomicBool>,
    notified: Arc<tokio::sync::Notify>,
}

impl ProductControlCancellation {
    pub(super) fn new() -> Self {
        Self {
            requested: Arc::new(AtomicBool::new(false)),
            notified: Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub(in crate::daed_product) fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    pub(super) fn request(&self) {
        if !self.requested.swap(true, Ordering::AcqRel) {
            self.notified.notify_waiters();
        }
    }

    pub(in crate::daed_product) async fn cancelled(&self) {
        loop {
            let notified = self.notified.notified();
            if self.is_requested() {
                return;
            }
            notified.await;
        }
    }
}
