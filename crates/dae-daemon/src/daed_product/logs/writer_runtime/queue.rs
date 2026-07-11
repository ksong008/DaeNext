use super::*;
use std::sync::Condvar;

struct ProductLogQueueState {
    commands: VecDeque<ProductLogCommand>,
    closed: bool,
}

pub(super) struct ProductLogQueue {
    capacity: usize,
    state: Mutex<ProductLogQueueState>,
    not_empty: Condvar,
    not_full: Condvar,
}

impl ProductLogQueue {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            state: Mutex::new(ProductLogQueueState {
                commands: VecDeque::with_capacity(capacity.max(1)),
                closed: false,
            }),
            not_empty: Condvar::new(),
            not_full: Condvar::new(),
        }
    }

    pub(super) fn submit(&self, command: ProductLogCommand, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("product log queue is unavailable"))?;
        while state.commands.len() >= self.capacity && !state.closed {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "product log queue admission timed out",
                ));
            }
            let (next, wait) = self
                .not_full
                .wait_timeout(state, remaining)
                .map_err(|_| io::Error::other("product log queue is unavailable"))?;
            state = next;
            if wait.timed_out() && state.commands.len() >= self.capacity {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "product log queue admission timed out",
                ));
            }
        }
        if state.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "product log writer is unavailable",
            ));
        }
        state.commands.push_back(command);
        self.not_empty.notify_one();
        Ok(())
    }

    pub(super) fn receive(&self) -> Option<ProductLogCommand> {
        let mut state = self.state.lock().ok()?;
        loop {
            if let Some(command) = state.commands.pop_front() {
                self.not_full.notify_one();
                return Some(command);
            }
            if state.closed {
                return None;
            }
            state = self.not_empty.wait(state).ok()?;
        }
    }

    pub(super) fn close(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.closed = true;
        self.not_empty.notify_all();
        self.not_full.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_capacity_and_close_are_bounded() {
        let queue = ProductLogQueue::new(1);
        queue
            .submit(test_command(), Duration::from_millis(10))
            .unwrap();
        let started = Instant::now();
        let error = queue
            .submit(test_command(), Duration::from_millis(20))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(queue.receive().is_some());
        queue.close();
        assert!(queue.receive().is_none());
        assert_eq!(
            queue
                .submit(test_command(), Duration::from_millis(10))
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    fn test_command() -> ProductLogCommand {
        let (completion, _) = mpsc::sync_channel(1);
        ProductLogCommand {
            action: ProductLogAction::Clear,
            completion,
        }
    }
}
