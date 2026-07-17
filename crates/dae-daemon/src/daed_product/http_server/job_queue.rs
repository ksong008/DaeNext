use super::*;
use std::sync::Condvar;

struct ProductHttpJobQueueState<T> {
    jobs: VecDeque<T>,
    closed: bool,
}

pub(super) struct ProductHttpJobQueue<T> {
    capacity: usize,
    state: Mutex<ProductHttpJobQueueState<T>>,
    not_empty: Condvar,
}

#[derive(Debug)]
pub(super) enum ProductHttpQueueSendError<T> {
    Full(T),
    Closed(T),
}

#[derive(Debug)]
pub(super) enum ProductHttpQueueReceiveError {
    Timeout,
    Closed,
}

impl<T> ProductHttpJobQueue<T> {
    pub(super) fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            state: Mutex::new(ProductHttpJobQueueState {
                jobs: VecDeque::with_capacity(capacity),
                closed: false,
            }),
            not_empty: Condvar::new(),
        }
    }

    pub(super) fn try_submit(
        &self,
        job: T,
        admitted: impl FnOnce(),
    ) -> Result<(), ProductHttpQueueSendError<T>> {
        let Ok(mut state) = self.state.lock() else {
            return Err(ProductHttpQueueSendError::Closed(job));
        };
        if state.closed {
            return Err(ProductHttpQueueSendError::Closed(job));
        }
        if state.jobs.len() >= self.capacity {
            return Err(ProductHttpQueueSendError::Full(job));
        }
        admitted();
        state.jobs.push_back(job);
        self.not_empty.notify_one();
        Ok(())
    }

    pub(super) fn receive_timeout(
        &self,
        timeout: Duration,
    ) -> Result<T, ProductHttpQueueReceiveError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let Ok(mut state) = self.state.lock() else {
            return Err(ProductHttpQueueReceiveError::Closed);
        };
        loop {
            if let Some(job) = state.jobs.pop_front() {
                return Ok(job);
            }
            if state.closed {
                return Err(ProductHttpQueueReceiveError::Closed);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ProductHttpQueueReceiveError::Timeout);
            }
            let Ok((next, wait)) = self.not_empty.wait_timeout(state, remaining) else {
                return Err(ProductHttpQueueReceiveError::Closed);
            };
            state = next;
            if wait.timed_out() && state.jobs.is_empty() {
                return Err(ProductHttpQueueReceiveError::Timeout);
            }
        }
    }

    pub(super) fn close(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.closed = true;
        self.not_empty.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn queue_preserves_capacity_order_and_close() {
        let queue = ProductHttpJobQueue::new(2);
        queue.try_submit(1, || {}).unwrap();
        queue.try_submit(2, || {}).unwrap();
        assert!(matches!(
            queue.try_submit(3, || {}),
            Err(ProductHttpQueueSendError::Full(3))
        ));
        assert_eq!(queue.receive_timeout(Duration::ZERO).unwrap(), 1);
        assert_eq!(queue.receive_timeout(Duration::ZERO).unwrap(), 2);
        queue.close();
        assert!(matches!(
            queue.try_submit(4, || {}),
            Err(ProductHttpQueueSendError::Closed(4))
        ));
        assert!(matches!(
            queue.receive_timeout(Duration::ZERO),
            Err(ProductHttpQueueReceiveError::Closed)
        ));
    }

    #[test]
    fn idle_consumers_reach_their_maintenance_deadline_independently() {
        const CONSUMERS: usize = 4;
        let queue = Arc::new(ProductHttpJobQueue::<usize>::new(CONSUMERS));
        let barrier = Arc::new(Barrier::new(CONSUMERS + 1));
        let (completed, observed) = mpsc::sync_channel(CONSUMERS);
        let mut workers = Vec::with_capacity(CONSUMERS);
        for _ in 0..CONSUMERS {
            let queue = Arc::clone(&queue);
            let barrier = Arc::clone(&barrier);
            let completed = completed.clone();
            workers.push(thread::spawn(move || {
                barrier.wait();
                let result = queue.receive_timeout(Duration::from_millis(20));
                completed.send(result).unwrap();
            }));
        }
        barrier.wait();
        drop(completed);
        for _ in 0..CONSUMERS {
            assert!(matches!(
                observed.recv_timeout(Duration::from_secs(1)).unwrap(),
                Err(ProductHttpQueueReceiveError::Timeout)
            ));
        }
        for worker in workers {
            worker.join().unwrap();
        }
    }

    #[test]
    fn admission_is_recorded_before_a_consumer_can_receive() {
        let queue = Arc::new(ProductHttpJobQueue::new(1));
        let admitted = Arc::new(AtomicBool::new(false));
        let worker_queue = Arc::clone(&queue);
        let worker_admitted = Arc::clone(&admitted);
        let worker = thread::spawn(move || {
            assert_eq!(
                worker_queue
                    .receive_timeout(Duration::from_secs(1))
                    .unwrap(),
                7
            );
            worker_admitted.load(Ordering::Acquire)
        });
        queue
            .try_submit(7, || admitted.store(true, Ordering::Release))
            .unwrap();
        assert!(worker.join().unwrap());
    }
}
