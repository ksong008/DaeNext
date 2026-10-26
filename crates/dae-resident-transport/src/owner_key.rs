//! Entry liveness, separate from physical and stream capacity accounting.
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Notify;

pub(crate) struct OwnerKeyUsage {
    users: AtomicUsize,
    quiescent: Arc<Notify>,
}

impl OwnerKeyUsage {
    pub(crate) fn new(quiescent: Arc<Notify>) -> Arc<Self> {
        Arc::new(Self {
            users: AtomicUsize::new(0),
            quiescent,
        })
    }

    // A root pin must be acquired under the registry lock. After that, pins may
    // only be forked from a live pin. Registry removal checks quiescence under
    // that same lock, so an unregistered entry can never acquire a new user.
    pub(crate) fn pin(self: &Arc<Self>) -> OwnerKeyPin {
        self.users.fetch_add(1, Ordering::AcqRel);
        OwnerKeyPin(Arc::clone(self))
    }

    pub(crate) fn is_quiescent(&self) -> bool {
        self.users.load(Ordering::Acquire) == 0
    }
}

pub(crate) struct OwnerKeyPin(Arc<OwnerKeyUsage>);

impl Clone for OwnerKeyPin {
    fn clone(&self) -> Self {
        self.0.pin()
    }
}

impl Drop for OwnerKeyPin {
    fn drop(&mut self) {
        if self.0.users.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.quiescent.notify_one();
        }
    }
}
