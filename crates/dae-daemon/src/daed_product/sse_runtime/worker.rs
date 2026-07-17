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
            runtime.block_on(run_product_sse_runtime(app, receiver, stop, metrics));
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

async fn run_product_sse_runtime(
    app: std::sync::Weak<AppState>,
    mut receiver: tokio::sync::mpsc::Receiver<ProductSseJob>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    metrics: Arc<ProductHttpMetrics>,
) {
    let mut tasks = tokio::task::JoinSet::new();
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
                tasks.spawn(async move {
                    run_product_sse_job(app, job, task_stop, task_metrics).await;
                });
            }
            completed = tasks.join_next(), if !tasks.is_empty() => {
                drop(completed);
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
) {
    let ProductSseJob {
        stream,
        request,
        kind,
        admission,
        ui_session,
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
            stream_runtime_events_async(&mut stream, &app, &request, stop).await
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
