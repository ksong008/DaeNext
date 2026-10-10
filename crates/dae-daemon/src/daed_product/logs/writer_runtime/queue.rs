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
        let mut state = log_lock(&self.state)?;
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

    pub(super) fn take_append_batch(&self, first: ProductLogCommand) -> Vec<ProductLogCommand> {
        let mut batch = vec![first];
        let Ok(mut state) = self.state.lock() else {
            return batch;
        };
        while batch.len() < 32
            && state
                .commands
                .front()
                .is_some_and(|command| matches!(command.action, ProductLogAction::Append(_)))
        {
            batch.push(state.commands.pop_front().expect("queue front"));
        }
        self.not_full.notify_all();
        batch
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
#[path = "queue_tests.rs"]
mod tests;
