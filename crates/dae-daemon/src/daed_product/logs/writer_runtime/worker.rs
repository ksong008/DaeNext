use super::*;

pub(super) struct ProductLogWorkerHandle {
    join: Option<thread::JoinHandle<()>>,
    completed: mpsc::Receiver<()>,
}

impl ProductLogWorkerHandle {
    pub(super) fn join_until(mut self, deadline: Instant) -> bool {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || self.completed.recv_timeout(remaining).is_err() {
            return false;
        }
        self.join.take().is_none_or(|join| join.join().is_ok())
    }
}

pub(super) fn start_product_log_worker(
    config: ProductLogRuntimeConfig,
    config_dir: PathBuf,
    policy: ProductLogPolicy,
    queue: Arc<ProductLogQueue>,
    metrics: Arc<ProductLogRuntimeMetrics>,
    updates: tokio::sync::watch::Sender<u64>,
) -> io::Result<ProductLogWorkerHandle> {
    let (ready_sender, ready) = mpsc::sync_channel(1);
    let (completed_sender, completed) = mpsc::sync_channel(1);
    let worker_queue = Arc::clone(&queue);
    let join = thread::Builder::new()
        .name("daed-log-writer".to_owned())
        .stack_size(config.worker_stack_bytes)
        .spawn(move || {
            let _completion = ProductLogWorkerCompletion(completed_sender);
            let writer = ProductLogWriter::open(config_dir, policy);
            match writer {
                Ok(writer) => {
                    let _ = ready_sender.send(Ok(()));
                    run_product_log_worker(writer, worker_queue, metrics, updates);
                }
                Err(error) => {
                    let _ = ready_sender.send(Err(error));
                }
            }
        })?;
    match ready.recv_timeout(config.completion_timeout) {
        Ok(Ok(())) => Ok(ProductLogWorkerHandle {
            join: Some(join),
            completed,
        }),
        Ok(Err(error)) => {
            let _ = join.join();
            Err(error)
        }
        Err(RecvTimeoutError::Timeout) => {
            queue.close();
            drop(join);
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "start product log writer timed out",
            ))
        }
        Err(RecvTimeoutError::Disconnected) => {
            queue.close();
            let _ = join.join();
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "product log writer stopped during startup",
            ))
        }
    }
}

struct ProductLogWorkerCompletion(mpsc::SyncSender<()>);

impl Drop for ProductLogWorkerCompletion {
    fn drop(&mut self) {
        let _ = self.0.try_send(());
    }
}

fn run_product_log_worker(
    mut writer: ProductLogWriter,
    queue: Arc<ProductLogQueue>,
    metrics: Arc<ProductLogRuntimeMetrics>,
    updates: tokio::sync::watch::Sender<u64>,
) {
    while let Some(command) = queue.receive() {
        if matches!(command.action, ProductLogAction::Append(_)) {
            let batch = queue.take_append_batch(command);
            let mut requests = Vec::with_capacity(batch.len());
            let mut completions = Vec::with_capacity(batch.len());
            for command in batch {
                metrics.dequeued();
                let ProductLogAction::Append(request) = command.action else {
                    unreachable!();
                };
                requests.push(request);
                completions.push(command.completion);
            }
            let mut notify = false;
            for (result, completion) in writer.append_batch(requests).into_iter().zip(completions) {
                let result = match result {
                    Ok(ProductLogAppendOutcome::Filtered) => {
                        metrics.filtered();
                        Ok(())
                    }
                    Ok(ProductLogAppendOutcome::Appended { pruned }) => {
                        metrics.appended();
                        if pruned {
                            metrics.pruned();
                        }
                        notify = true;
                        Ok(())
                    }
                    Err(error) => {
                        metrics.failed();
                        Err(error)
                    }
                };
                metrics.completed();
                let _ = completion.send(result);
            }
            if notify {
                updates.send_modify(|generation| *generation = generation.saturating_add(1));
            }
            continue;
        }
        metrics.dequeued();
        let ProductLogCommand { action, completion } = command;
        let mut notify = false;
        let result = match action {
            ProductLogAction::Append(_) => unreachable!("append handled by batch branch"),
            ProductLogAction::Clear => writer.clear().inspect(|_| notify = true),
            ProductLogAction::ClearPreservingLifecycle => {
                writer.clear_preserving_lifecycle().map(|pruned| {
                    if pruned {
                        metrics.pruned();
                    }
                    notify = true;
                })
            }
            ProductLogAction::ReplacePolicy(policy) => {
                writer.replace_policy(policy).map(|pruned| {
                    if pruned {
                        metrics.pruned();
                        notify = true;
                    }
                })
            }
            ProductLogAction::ApplyLimits {
                max_entries,
                max_bytes,
            } => writer.apply_limits(max_entries, max_bytes).map(|pruned| {
                if pruned {
                    metrics.pruned();
                    notify = true;
                }
            }),
        };
        if result.is_err() {
            metrics.failed();
        }
        if notify {
            updates.send_modify(|generation| *generation = generation.saturating_add(1));
        }
        metrics.completed();
        let _ = completion.send(result);
    }
}
