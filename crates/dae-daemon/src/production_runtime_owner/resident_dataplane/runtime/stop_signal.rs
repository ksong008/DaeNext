use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use tokio::sync::watch;

pub(crate) type SharedResidentStopSignal = Arc<ResidentStopSignal>;

pub(crate) struct ResidentStopSignal {
    requested: AtomicBool,
    sender: watch::Sender<bool>,
}

impl ResidentStopSignal {
    pub(crate) fn shared() -> SharedResidentStopSignal {
        let (sender, _receiver) = watch::channel(false);
        Arc::new(Self {
            requested: AtomicBool::new(false),
            sender,
        })
    }

    pub(crate) fn load(&self, ordering: Ordering) -> bool {
        self.requested.load(ordering)
    }

    pub(crate) fn store(&self, requested: bool, ordering: Ordering) {
        if self.requested.swap(requested, ordering) != requested {
            self.sender.send_replace(requested);
        }
    }

    pub(crate) fn listener(&self) -> ResidentStopListener {
        ResidentStopListener {
            receiver: self.sender.subscribe(),
        }
    }
}

pub(crate) struct ResidentStopListener {
    receiver: watch::Receiver<bool>,
}

impl ResidentStopListener {
    pub(crate) async fn cancelled(&mut self) {
        loop {
            if *self.receiver.borrow() {
                return;
            }
            if self.receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn stop_signal_broadcasts_without_periodic_polling() {
        let stop = ResidentStopSignal::shared();
        let mut waiters = Vec::new();
        for _ in 0..32 {
            let mut listener = stop.listener();
            waiters.push(tokio::spawn(async move { listener.cancelled().await }));
        }

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(waiters.iter().all(|waiter| !waiter.is_finished()));

        stop.store(true, Ordering::Relaxed);
        for waiter in waiters {
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("stop listener timeout")
                .unwrap();
        }
        assert!(stop.load(Ordering::Relaxed));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn late_stop_listener_observes_existing_request() {
        let stop = ResidentStopSignal::shared();
        stop.store(true, Ordering::Release);
        let mut listener = stop.listener();
        tokio::time::timeout(Duration::from_millis(20), listener.cancelled())
            .await
            .expect("late listener must observe the stop request");
    }
}
