use super::*;

const RESIDENT_EVENT_WRITER_SEND_RETRY_INTERVAL: Duration = Duration::from_millis(1);

impl ResidentEventWriterHandle {
    pub(super) fn control(
        &self,
        build: impl FnOnce(ResidentEventWriterAck) -> ResidentEventWriterCommand,
    ) -> std::io::Result<()> {
        self.control_until(build, deadline_after(RESIDENT_EVENT_WRITER_CONTROL_TIMEOUT))
    }

    #[cfg(test)]
    pub(super) fn control_with_timeout(
        &self,
        build: impl FnOnce(ResidentEventWriterAck) -> ResidentEventWriterCommand,
        timeout: Duration,
    ) -> std::io::Result<()> {
        self.control_until(build, deadline_after(timeout))
    }

    pub(super) fn control_until(
        &self,
        build: impl FnOnce(ResidentEventWriterAck) -> ResidentEventWriterCommand,
        deadline: Instant,
    ) -> std::io::Result<()> {
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        self.inner.metrics.command_enqueued();
        if let Err(err) = send_command_until(&self.inner.sender, build(ack_tx), deadline) {
            self.inner.metrics.command_rejected();
            let message = format!("send resident event writer control command: {err}");
            self.inner.metrics.record_error(message.clone());
            return Err(std::io::Error::new(err.kind(), message));
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return receive_control_ack(&ack_rx, None);
        }
        receive_control_ack(&ack_rx, Some(remaining))
    }
}

pub(super) fn deadline_after(timeout: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(timeout).unwrap_or(now)
}

pub(super) fn send_command_until(
    sender: &SyncSender<ResidentEventWriterCommand>,
    mut command: ResidentEventWriterCommand,
    deadline: Instant,
) -> std::io::Result<()> {
    loop {
        match sender.try_send(command) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Full(returned)) => command = returned,
            Err(TrySendError::Disconnected(_)) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "resident event writer channel disconnected",
                ));
            }
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "resident event writer command queue remained full until deadline",
            ));
        }
        thread::park_timeout(remaining.min(RESIDENT_EVENT_WRITER_SEND_RETRY_INTERVAL));
    }
}

fn receive_control_ack(
    ack_rx: &Receiver<Result<(), String>>,
    timeout: Option<Duration>,
) -> std::io::Result<()> {
    let result = match timeout {
        Some(timeout) => ack_rx.recv_timeout(timeout),
        None => match ack_rx.try_recv() {
            Ok(result) => return result.map_err(std::io::Error::other),
            Err(mpsc::TryRecvError::Empty) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "resident event writer control command timed out",
                ));
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "resident event writer control acknowledgement disconnected",
                ));
            }
        },
    };
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(std::io::Error::other(err)),
        Err(RecvTimeoutError::Timeout) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "resident event writer control command timed out",
        )),
        Err(RecvTimeoutError::Disconnected) => Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "resident event writer control acknowledgement disconnected",
        )),
    }
}
