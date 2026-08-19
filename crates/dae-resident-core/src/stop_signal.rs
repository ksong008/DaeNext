use std::future::Future;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use tokio::sync::watch;

pub type SharedResidentStopSignal = Arc<ResidentStopSignal>;

pub struct ResidentStopSignal {
    requested: AtomicBool,
    sender: watch::Sender<bool>,
}

impl ResidentStopSignal {
    pub fn shared() -> SharedResidentStopSignal {
        let (sender, _receiver) = watch::channel(false);
        Arc::new(Self {
            requested: AtomicBool::new(false),
            sender,
        })
    }

    pub fn load(&self, ordering: Ordering) -> bool {
        self.requested.load(ordering)
    }

    pub fn store(&self, requested: bool, ordering: Ordering) {
        if self.requested.swap(requested, ordering) != requested {
            self.sender.send_replace(requested);
        }
    }

    pub fn listener(&self) -> ResidentStopListener {
        ResidentStopListener {
            receiver: self.sender.subscribe(),
        }
    }
}

pub struct ResidentStopListener {
    receiver: watch::Receiver<bool>,
}

impl ResidentStopListener {
    pub async fn cancelled(&mut self) {
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

pub async fn run_until_resident_stop<F>(
    stop: &SharedResidentStopSignal,
    future: F,
) -> Option<F::Output>
where
    F: Future,
{
    if stop.load(Ordering::Acquire) {
        return None;
    }
    let mut listener = stop.listener();
    tokio::select! {
        biased;
        _ = listener.cancelled() => None,
        output = future => Some(output),
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

    #[tokio::test(flavor = "current_thread")]
    async fn scoped_future_is_cancelled_by_stop_signal() {
        let stop = ResidentStopSignal::shared();
        let task_stop = Arc::clone(&stop);
        let task = tokio::spawn(async move {
            run_until_resident_stop(&task_stop, std::future::pending::<()>()).await
        });

        stop.store(true, Ordering::Release);

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("scoped future cancellation timeout")
                .unwrap(),
            None
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stopped_scope_does_not_poll_a_ready_future() {
        let stop = ResidentStopSignal::shared();
        stop.store(true, Ordering::Release);

        assert_eq!(run_until_resident_stop(&stop, async { 7 }).await, None);
    }
}
