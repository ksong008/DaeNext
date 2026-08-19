use std::time::Instant;

#[derive(Clone)]
pub struct XhttpXmuxStateSignal {
    sender: tokio::sync::watch::Sender<()>,
}

pub struct XhttpXmuxStateWait {
    receiver: tokio::sync::watch::Receiver<()>,
    deadline: Option<Instant>,
}

impl XhttpXmuxStateSignal {
    pub fn new() -> Self {
        let (sender, _) = tokio::sync::watch::channel(());
        Self { sender }
    }

    pub fn waiter(&self, deadline: Option<Instant>) -> XhttpXmuxStateWait {
        XhttpXmuxStateWait {
            receiver: self.sender.subscribe(),
            deadline,
        }
    }

    pub fn notify(&self) {
        self.sender.send_modify(|_| {});
    }
}

impl XhttpXmuxStateWait {
    pub async fn wait(mut self) {
        if let Some(deadline) = self.deadline {
            tokio::select! {
                _ = self.receiver.changed() => {}
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {}
            }
        } else {
            let _ = self.receiver.changed().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(flavor = "current_thread")]
    async fn xmux_waiter_observes_state_change_without_polling() {
        let signal = XhttpXmuxStateSignal::new();
        let waiter = signal.waiter(None);
        signal.notify();
        tokio::time::timeout(Duration::from_millis(50), waiter.wait())
            .await
            .expect("xmux state change was lost before waiter polling");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn xmux_waiter_observes_reuse_deadline() {
        let signal = XhttpXmuxStateSignal::new();
        let waiter = signal.waiter(Some(Instant::now() + Duration::from_millis(10)));
        tokio::time::timeout(Duration::from_millis(50), waiter.wait())
            .await
            .expect("xmux reuse deadline did not wake waiter");
    }
}
