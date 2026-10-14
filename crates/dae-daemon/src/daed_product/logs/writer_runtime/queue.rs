use super::*;
use std::sync::{Condvar, LockResult, MutexGuard, PoisonError};

type QueueStateGuard<'a> = MutexGuard<'a, ProductLogQueueState>;

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
        let mut state = self.guard(self.state.lock());
        while state.commands.len() >= self.capacity && !state.closed {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "product log queue admission timed out",
                ));
            }
            state = self.guard(
                self.not_full
                    .wait_timeout(state, remaining)
                    .map(|(state, _)| state)
                    .map_err(|poisoned| PoisonError::new(poisoned.into_inner().0)),
            );
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
        let mut state = self.guard(self.state.lock());
        loop {
            if let Some(command) = state.commands.pop_front() {
                self.not_full.notify_one();
                return Some(command);
            }
            if state.closed {
                return None;
            }
            state = self.guard(self.not_empty.wait(state));
        }
    }

    pub(super) fn take_append_batch(&self, first: ProductLogCommand) -> Vec<ProductLogCommand> {
        let mut batch = vec![first];
        let mut state = self.guard(self.state.lock());
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
        let mut state = self.guard(self.state.lock());
        state.closed = true;
        self.not_empty.notify_all();
        self.not_full.notify_all();
    }

    fn guard<'a>(&self, result: LockResult<QueueStateGuard<'a>>) -> QueueStateGuard<'a> {
        result.unwrap_or_else(|poisoned| {
            let mut state = poisoned.into_inner();
            state.closed = true;
            // Fail queued completions and wake both wait sets; keep poison so
            // this queue cannot accept more work after an interrupted mutation.
            state.commands.clear();
            self.not_empty.notify_all();
            self.not_full.notify_all();
            state
        })
    }
}

#[cfg(test)]
#[path = "queue_tests.rs"]
mod tests;
