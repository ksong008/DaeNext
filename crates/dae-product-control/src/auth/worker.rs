use super::*;

pub(super) struct ProductAuthJob {
    pub(super) action: Option<ProductAuthAction>,
    pub(super) response: std::sync::mpsc::SyncSender<HttpResponse>,
    pub(super) lease: ProductAuthAdmissionLease,
}

pub(super) struct ProductAuthWorkerHandle {
    join: Option<thread::JoinHandle<()>>,
    completed: std::sync::mpsc::Receiver<()>,
}

impl ProductAuthWorkerHandle {
    pub(super) fn join_if_finished(mut self) {
        if self.completed.try_recv().is_ok()
            && let Some(join) = self.join.take()
        {
            let _ = join.join();
        }
    }

    pub(super) fn join_until(mut self, deadline: Instant) -> bool {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || self.completed.recv_timeout(remaining).is_err() {
            return false;
        }
        self.join.take().is_none_or(|join| join.join().is_ok())
    }
}

pub(super) fn start_product_auth_worker(
    index: usize,
    config: ProductAuthRuntimeConfig,
    receiver: Arc<Mutex<std::sync::mpsc::Receiver<ProductAuthJob>>>,
    metrics: Arc<ProductAuthMetrics>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
) -> io::Result<ProductAuthWorkerHandle> {
    let (completed_sender, completed) = std::sync::mpsc::sync_channel(1);
    let join = thread::Builder::new()
        .name(format!("daed-auth-{index}"))
        .stack_size(config.worker_stack_bytes)
        .spawn(move || {
            let _completion = ProductAuthWorkerCompletion(completed_sender);
            product_auth_worker_loop(config, receiver, metrics, stopping);
        })?;
    Ok(ProductAuthWorkerHandle {
        join: Some(join),
        completed,
    })
}

struct ProductAuthWorkerCompletion(std::sync::mpsc::SyncSender<()>);

impl Drop for ProductAuthWorkerCompletion {
    fn drop(&mut self) {
        let _ = self.0.try_send(());
    }
}

fn product_auth_worker_loop(
    config: ProductAuthRuntimeConfig,
    receiver: Arc<Mutex<std::sync::mpsc::Receiver<ProductAuthJob>>>,
    metrics: Arc<ProductAuthMetrics>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
) {
    while !stopping.load(Ordering::Acquire) {
        let received = {
            let Ok(receiver) = receiver.lock() else {
                return;
            };
            receiver.recv_timeout(config.worker_recv_timeout)
        };
        let mut job = match received {
            Ok(job) => job,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        };
        metrics.dequeued();
        if stopping.load(Ordering::Acquire) {
            metrics.completed();
            return;
        }
        let Some(action) = job.action.take() else {
            metrics.completed();
            continue;
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action));
        match outcome {
            Ok(outcome) => {
                job.lease.complete(outcome.attempt);
                metrics.completed();
                let _ = job.response.send(outcome.response);
            }
            Err(_) => {
                metrics.worker_panicked();
                job.lease.complete(ProductAuthAttemptOutcome::Neutral);
                metrics.completed();
                let _ = job.response.send(HttpResponse::json(
                    500,
                    json!({"error": "authentication worker failed"}),
                ));
            }
        }
    }
}
