use super::*;
pub(super) fn serve_forever(
    listen: &str,
    app: AppState,
    startup_started_at: Instant,
) -> io::Result<()> {
    let listen_started_at = Instant::now();
    let listener = TcpListener::bind(listen)?;
    let app = Arc::new(app);
    spawn_allocator_idle_reclaim_monitor(&app);
    let runtime_config = app.runtime.current_config();
    let config = ProductHttpWorkerConfig::from_config(runtime_config.as_ref());
    app.http_metrics.configure(config);
    let (sender, receiver) = mpsc::sync_channel(config.queue_capacity);
    let receiver = Arc::new(Mutex::new(receiver));
    let mut handles: Vec<thread::JoinHandle<()>> = Vec::with_capacity(config.worker_count);
    for index in 0..config.worker_count {
        let receiver = Arc::clone(&receiver);
        let app = Arc::clone(&app);
        let metrics = Arc::clone(&app.http_metrics);
        let handle = match thread::Builder::new()
            .name(format!("daed-http-{index}"))
            .stack_size(config.worker_stack_bytes)
            .spawn(move || product_http_worker_loop(index, receiver, app, metrics))
        {
            Ok(handle) => handle,
            Err(err) => {
                drop(sender);
                for handle in handles {
                    let _ = handle.join();
                }
                return Err(err);
            }
        };
        handles.push(handle);
    }
    let mut http_fields = BTreeMap::new();
    http_fields.insert("workers".to_owned(), config.worker_count.to_string());
    http_fields.insert(
        "queueCapacity".to_owned(),
        config.queue_capacity.to_string(),
    );
    http_fields.insert(
        "workerStackBytes".to_owned(),
        config.worker_stack_bytes.to_string(),
    );
    http_fields.insert("sources".to_owned(), config.sources_json().to_string());
    let _ = append_startup_step_completed_for_config(
        &app.config_dir,
        &app.state,
        "product.http-listener",
        listen_started_at,
        http_fields,
    );
    let mut fields = BTreeMap::new();
    fields.insert(
        "elapsed".to_owned(),
        format!("{:?}", startup_started_at.elapsed()),
    );
    let _ = append_lifecycle_log_fields_for_config(
        &app.config_dir,
        &app.state,
        "info",
        "[Startup] Finished",
        fields,
    );
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                app.http_metrics.accepted();
                match sender.try_send(ProductHttpJob { stream }) {
                    Ok(()) => app.http_metrics.enqueued(),
                    Err(TrySendError::Full(job)) => {
                        app.http_metrics.rejected();
                        let _ = write_http_rejected(job.stream);
                    }
                    Err(TrySendError::Disconnected(job)) => {
                        app.http_metrics.rejected();
                        let _ = write_http_rejected(job.stream);
                        break;
                    }
                }
            }
            Err(err) => {
                drop(sender);
                for handle in handles {
                    let _ = handle.join();
                }
                return Err(err);
            }
        }
    }
    drop(sender);
    for handle in handles {
        let _ = handle.join();
    }
    Ok(())
}

pub(super) struct ProductHttpJob {
    pub(super) stream: TcpStream,
}

pub(super) fn product_http_worker_loop(
    _index: usize,
    receiver: Arc<Mutex<Receiver<ProductHttpJob>>>,
    app: Arc<AppState>,
    metrics: Arc<ProductHttpMetrics>,
) {
    loop {
        let recv_result = {
            let Ok(receiver) = receiver.lock() else {
                break;
            };
            receiver.recv_timeout(PRODUCT_HTTP_WORKER_RECV_TIMEOUT)
        };
        match recv_result {
            Ok(job) => {
                metrics.dequeued();
                metrics.opened();
                let _ = handle_stream(job.stream, &app);
                metrics.closed();
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

pub(super) fn write_http_rejected(mut stream: TcpStream) -> io::Result<()> {
    let response = HttpResponse::json(
        503,
        json!({"error": "daed HTTP worker queue is full; retry later"}),
    );
    write_http_response(&mut stream, &response, false)
}

pub(super) fn handle_stream(mut stream: TcpStream, app: &AppState) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let request = match read_http_request(&mut stream) {
        Ok(request) => request,
        Err(err) => {
            let response = HttpResponse::json(
                400,
                json!({
                    "error": format!("bad request: {err}")
                }),
            );
            return write_http_response(&mut stream, &response, false);
        }
    };
    let head_only = request.method == "HEAD";
    if request.method == "GET"
        && (request.path == "/api/events/logs" || request.path == "/api/events/runtime")
    {
        let Some(_user) = authenticate_request(app, &request) else {
            let response = HttpResponse::json(401, json!({"error": "authentication required"}));
            return write_http_response_for_request(&mut stream, &request, &response, head_only);
        };
        if request.path == "/api/events/logs" {
            return stream_log_events(&mut stream, app, &request);
        }
        return stream_runtime_events(&mut stream, app, &request);
    }
    let response = route_request(app, &request);
    write_http_response_for_request(&mut stream, &request, &response, head_only)
}
