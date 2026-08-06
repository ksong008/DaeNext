use super::super::update_admission::ProductGeodataUpdateLease;
use super::*;

pub(super) struct ProductGeodataUpdateJob {
    pub(super) stream: TcpStream,
    pub(super) request: HttpRequest,
    pub(super) kind: GeodataKind,
    pub(super) generation: u64,
    pub(super) lease: ProductGeodataUpdateLease,
    pub(super) http_metrics: Arc<ProductHttpMetrics>,
}

impl ProductGeodataUpdateJob {
    pub(super) fn into_submission_error(
        self,
        status: u16,
        message: &str,
    ) -> Box<ProductGeodataUpdateSubmissionError> {
        let Self {
            stream,
            request,
            lease,
            ..
        } = self;
        drop(lease);
        Box::new(ProductGeodataUpdateSubmissionError {
            stream,
            request,
            response: HttpResponse::json(status, json!({"error": message})),
        })
    }
}

pub(super) struct ProductGeodataUpdateWorkerHandle {
    join: Option<thread::JoinHandle<()>>,
    completed: std::sync::mpsc::Receiver<()>,
}

impl ProductGeodataUpdateWorkerHandle {
    pub(super) fn join_if_finished(mut self) {
        if !matches!(
            self.completed.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ) && let Some(join) = self.join.take()
        {
            let _ = join.join();
        }
    }

    fn try_join(&mut self) -> bool {
        if matches!(
            self.completed.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ) {
            return false;
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        true
    }
}

pub(super) fn join_product_geodata_update_workers(
    mut workers: Vec<ProductGeodataUpdateWorkerHandle>,
    deadline: Instant,
    metrics: &ProductGeodataUpdateMetrics,
) {
    while !workers.is_empty() {
        let mut index = 0;
        let mut joined_any = false;
        while index < workers.len() {
            if workers[index].try_join() {
                workers.swap_remove(index);
                metrics.worker_joined();
                joined_any = true;
            } else {
                index += 1;
            }
        }
        if workers.is_empty() || Instant::now() >= deadline {
            break;
        }
        if !joined_any {
            thread::sleep(
                Duration::from_millis(1).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
    for _ in workers {
        metrics.worker_detached();
    }
}

pub(super) fn start_product_geodata_update_worker(
    index: usize,
    config: ProductGeodataUpdateRuntimeConfig,
    context: ProductGeodataUpdateContext,
    receiver: Arc<Mutex<std::sync::mpsc::Receiver<ProductGeodataUpdateJob>>>,
    metrics: Arc<ProductGeodataUpdateMetrics>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
) -> io::Result<ProductGeodataUpdateWorkerHandle> {
    let (completed_sender, completed) = std::sync::mpsc::sync_channel(1);
    let join = thread::Builder::new()
        .name(format!("daed-geodata-update-{index}"))
        .stack_size(config.worker_stack_bytes)
        .spawn(move || {
            let _completion = ProductGeodataUpdateWorkerCompletion(completed_sender);
            product_geodata_update_worker_loop(config, context, receiver, metrics, stopping);
        })?;
    Ok(ProductGeodataUpdateWorkerHandle {
        join: Some(join),
        completed,
    })
}

struct ProductGeodataUpdateWorkerCompletion(std::sync::mpsc::SyncSender<()>);

impl Drop for ProductGeodataUpdateWorkerCompletion {
    fn drop(&mut self) {
        let _ = self.0.try_send(());
    }
}

fn product_geodata_update_worker_loop(
    config: ProductGeodataUpdateRuntimeConfig,
    context: ProductGeodataUpdateContext,
    receiver: Arc<Mutex<std::sync::mpsc::Receiver<ProductGeodataUpdateJob>>>,
    metrics: Arc<ProductGeodataUpdateMetrics>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut allocator_worker = allocator_register_reclaim_worker(AllocatorWorkerKind::ControlAux);
    loop {
        allocator_worker.poll();
        let received = {
            let Ok(receiver) = receiver.lock() else {
                return;
            };
            receiver.recv_timeout(config.worker_recv_timeout)
        };
        let job = match received {
            Ok(job) => job,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if stopping.load(Ordering::Acquire) {
                    return;
                }
                // Receiver is shared behind a mutex because std::mpsc::Receiver is not Sync.
                // Give a worker already waiting for that mutex a deterministic chance to take
                // ownership after the bounded receive. Without this handoff one worker can
                // repeatedly reacquire the receiver while its peer cannot poll a process-wide
                // allocator reclaim request before the acknowledgement deadline.
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        };
        run_product_geodata_update_job(&context, &metrics, &stopping, config.preparation_mode, job);
        allocator_worker.poll();
    }
}

fn run_product_geodata_update_job(
    context: &ProductGeodataUpdateContext,
    metrics: &Arc<ProductGeodataUpdateMetrics>,
    stopping: &std::sync::atomic::AtomicBool,
    preparation_mode: GeodataPreparationMode,
    job: ProductGeodataUpdateJob,
) {
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Geodata);
    let ProductGeodataUpdateJob {
        mut stream,
        request,
        kind,
        generation,
        lease,
        http_metrics,
    } = job;
    metrics.dequeued(kind, generation);
    let _completion = ProductGeodataUpdateJobCompletion {
        kind,
        generation,
        geodata_metrics: Arc::clone(metrics),
        http_metrics,
    };
    let response = if stopping.load(Ordering::Acquire) {
        drop(lease);
        HttpResponse::json(503, json!({"error": "geodata update runtime is stopping"}))
    } else {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            update_geodata_with_lease_using(context, kind, lease, preparation_mode)
        })) {
            Ok(result) => geodata_update_http_response(kind, result),
            Err(_) => {
                metrics.worker_panicked();
                HttpResponse::json(500, json!({"error": "geodata update worker failed"}))
            }
        }
    };
    let _ = write_http_response_for_request(&mut stream, &request, &response, false);
}

struct ProductGeodataUpdateJobCompletion {
    kind: GeodataKind,
    generation: u64,
    geodata_metrics: Arc<ProductGeodataUpdateMetrics>,
    http_metrics: Arc<ProductHttpMetrics>,
}

impl Drop for ProductGeodataUpdateJobCompletion {
    fn drop(&mut self) {
        self.geodata_metrics.completed(self.kind, self.generation);
        self.http_metrics.closed();
    }
}
