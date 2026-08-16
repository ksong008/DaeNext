use super::*;

pub(super) struct ProductSseWorkerHandle {
    join: Option<thread::JoinHandle<()>>,
    completed: std::sync::mpsc::Receiver<()>,
}

impl ProductSseWorkerHandle {
    pub(super) fn join_until(mut self, deadline: Instant) -> bool {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || self.completed.recv_timeout(remaining).is_err() {
            return false;
        }
        self.join.take().is_none_or(|join| join.join().is_ok())
    }
}

pub(super) fn start_product_sse_worker(
    config: ProductSseRuntimeConfig,
    app: std::sync::Weak<AppState>,
    receiver: tokio::sync::mpsc::Receiver<ProductSseJob>,
    stop: tokio::sync::watch::Receiver<bool>,
    metrics: Arc<ProductHttpMetrics>,
    overview: tokio::sync::broadcast::Sender<Arc<ProductRuntimeOverviewTick>>,
    overview_full_cache: Arc<ProductRuntimeOverviewFullCache>,
) -> io::Result<ProductSseWorkerHandle> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (completed_sender, completed) = std::sync::mpsc::sync_channel(1);
    let join = thread::Builder::new()
        .name("daed-sse-rt".to_owned())
        .stack_size(config.worker_stack_bytes)
        .spawn(move || {
            let _completion = ProductSseWorkerCompletion(completed_sender);
            let mut allocator_worker = allocator_register_reclaim_worker(AllocatorWorkerKind::Sse);
            let mut reclaim_worker = app
                .upgrade()
                .map(|app| app.ui_runtime.register_reclaim_worker());
            runtime.block_on(run_product_sse_runtime(
                app,
                receiver,
                stop,
                metrics,
                &mut reclaim_worker,
                &mut allocator_worker,
                overview,
                overview_full_cache,
            ));
        })?;
    Ok(ProductSseWorkerHandle {
        join: Some(join),
        completed,
    })
}

struct ProductSseWorkerCompletion(std::sync::mpsc::SyncSender<()>);

impl Drop for ProductSseWorkerCompletion {
    fn drop(&mut self) {
        let _ = self.0.try_send(());
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_product_sse_runtime(
    app: std::sync::Weak<AppState>,
    mut receiver: tokio::sync::mpsc::Receiver<ProductSseJob>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    metrics: Arc<ProductHttpMetrics>,
    reclaim_worker: &mut Option<ProductUiReclaimWorker>,
    allocator_worker: &mut AllocatorReclaimWorker,
    overview: tokio::sync::broadcast::Sender<Arc<ProductRuntimeOverviewTick>>,
    overview_full_cache: Arc<ProductRuntimeOverviewFullCache>,
) {
    let mut tasks = tokio::task::JoinSet::new();
    let mut maintenance = tokio::time::interval(PRODUCT_HTTP_WORKER_RECV_TIMEOUT);
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut overview_interval = tokio::time::interval(Duration::from_secs(1));
    overview_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut overview_sequence = 0_u64;
    loop {
        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
            }
            job = receiver.recv() => {
                let Some(job) = job else {
                    break;
                };
                let Some(app) = app.upgrade() else {
                    metrics.sse_submission_rollback();
                    job.close_queued();
                    continue;
                };
                let task_stop = stop.clone();
                let task_metrics = Arc::clone(&metrics);
                let task_overview_full_cache = Arc::clone(&overview_full_cache);
                tasks.spawn(async move {
                    run_product_sse_job(app, job, task_stop, task_metrics, task_overview_full_cache).await;
                });
            }
            completed = tasks.join_next(), if !tasks.is_empty() => {
                drop(completed);
            }
            _ = maintenance.tick() => {
                allocator_worker.poll();
                if let (Some(app), Some(worker)) = (app.upgrade(), reclaim_worker.as_mut()) {
                    app.ui_runtime.maintain(&metrics, worker);
                }
            }
            _ = overview_interval.tick() => {
                if overview.receiver_count() > 0
                    && let Some(app) = app.upgrade()
                {
                    overview_sequence = overview_sequence.saturating_add(1);
                    if let Ok(tick) = runtime_overview_tick(&app, overview_sequence) {
                        let _ = overview.send(tick);
                    }
                }
            }
        }
    }
    receiver.close();
    while let Ok(job) = receiver.try_recv() {
        metrics.sse_submission_rollback();
        job.close_queued();
    }
    while tasks.join_next().await.is_some() {}
}

async fn run_product_sse_job(
    app: Arc<AppState>,
    job: ProductSseJob,
    stop: tokio::sync::watch::Receiver<bool>,
    metrics: Arc<ProductHttpMetrics>,
    overview_full_cache: Arc<ProductRuntimeOverviewFullCache>,
) {
    let ProductSseJob {
        stream,
        request,
        kind,
        admission,
        ui_session,
        overview,
        http_metrics,
    } = job;
    metrics.sse_dequeued();
    let _completion = ProductSseJobCompletion {
        admission,
        ui_session,
        http_metrics,
        metrics,
    };
    if stream.set_nonblocking(true).is_err() {
        return;
    }
    let Ok(mut stream) = tokio::net::TcpStream::from_std(stream) else {
        return;
    };
    let _ = match kind {
        ProductSseStreamKind::Logs => {
            stream_log_events_async(&mut stream, &app, &request, stop).await
        }
        ProductSseStreamKind::Runtime => {
            let Some(overview) = overview else {
                return;
            };
            stream_runtime_events_async(
                &mut stream,
                &app,
                &request,
                stop,
                overview,
                overview_full_cache,
            )
            .await
        }
    };
}

struct ProductSseJobCompletion {
    admission: ProductSseAdmissionLease,
    ui_session: Option<ProductUiStreamLease>,
    http_metrics: Arc<ProductHttpMetrics>,
    metrics: Arc<ProductHttpMetrics>,
}

impl Drop for ProductSseJobCompletion {
    fn drop(&mut self) {
        let _ = &self.admission;
        let _ = &self.ui_session;
        self.metrics.sse_completed();
        self.http_metrics.closed();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_completion_releases_metrics_and_admission_during_unwind() {
        let config = ProductSseRuntimeConfig::for_test();
        let admission = Arc::new(ProductSseAdmission::new(config));
        let lease = admission.acquire(7).unwrap();
        let metrics = Arc::new(ProductHttpMetrics::default());
        metrics.opened();
        metrics.sse_enqueued();
        metrics.sse_dequeued();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _completion = ProductSseJobCompletion {
                admission: lease,
                ui_session: None,
                http_metrics: Arc::clone(&metrics),
                metrics: Arc::clone(&metrics),
            };
            panic!("exercise SSE completion unwind");
        }));
        assert!(result.is_err());

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot["activeConnections"], json!(0));
        assert_eq!(snapshot["activeSseConnections"], json!(0));
        assert_eq!(snapshot["sseRuntime"]["queueDepth"], json!(0));
        assert_eq!(snapshot["sseRuntime"]["completedTotal"], json!(1));
        let first = admission.acquire(7).unwrap();
        let second = admission.acquire(7).unwrap();
        drop((first, second));
    }
}
