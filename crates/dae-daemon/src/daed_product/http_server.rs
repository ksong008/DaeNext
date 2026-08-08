use super::*;

mod job_queue;
mod listener_readiness;
use job_queue::{ProductHttpJobQueue, ProductHttpQueueReceiveError, ProductHttpQueueSendError};
use listener_readiness::{LISTENER_SHUTDOWN_CHECK_INTERVAL, wait_for_listener_readiness};

pub(super) fn serve_forever(
    listen: &str,
    app: Arc<AppState>,
    startup_started_at: Instant,
) -> io::Result<()> {
    let listen_started_at = Instant::now();
    let listener = TcpListener::bind(listen)?;
    listener.set_nonblocking(true)?;
    if let Some(config) = app.runtime.current_config() {
        app.runtime
            .configure_pprof_port(config.global.pprof_port)
            .map_err(io::Error::other)?;
    }
    let local_control = spawn_local_control_socket(Arc::clone(&app))?;
    let allocator_monitor = match spawn_allocator_idle_reclaim_monitor(&app) {
        Ok(monitor) => monitor,
        Err(err) => {
            app.shutdown.request(0);
            let _ = local_control.shutdown();
            return Err(err);
        }
    };
    let runtime_config = app.runtime.current_config();
    let config = ProductHttpWorkerConfig::from_config(runtime_config.as_deref());
    app.http_metrics.configure(config);
    let sse_runtime =
        match ProductSseRuntime::start(config, Arc::downgrade(&app), Arc::clone(&app.http_metrics))
        {
            Ok(runtime) => runtime,
            Err(err) => {
                app.shutdown.request(0);
                if let Some(monitor) = allocator_monitor {
                    let _ = monitor.shutdown();
                }
                let _ = local_control.shutdown();
                return Err(err);
            }
        };
    let queue = Arc::new(ProductHttpJobQueue::new(config.queue_capacity));
    let connections = Arc::new(ProductHttpConnectionRegistry::default());
    let mut handles: Vec<thread::JoinHandle<()>> = Vec::with_capacity(config.worker_count);
    for index in 0..config.worker_count {
        let worker_queue = Arc::clone(&queue);
        let worker_app = Arc::clone(&app);
        let metrics = Arc::clone(&app.http_metrics);
        let worker_sse_runtime = Arc::clone(&sse_runtime);
        let worker_connections = Arc::clone(&connections);
        let handle = match thread::Builder::new()
            .name(format!("daed-http-{index}"))
            .stack_size(config.worker_stack_bytes)
            .spawn(move || {
                product_http_worker_loop(
                    index,
                    worker_queue,
                    worker_app,
                    metrics,
                    worker_sse_runtime,
                    worker_connections,
                )
            }) {
            Ok(handle) => handle,
            Err(err) => {
                app.shutdown.request(0);
                queue.close();
                for handle in handles {
                    let _ = handle.join();
                }
                drop(sse_runtime);
                if let Some(monitor) = allocator_monitor {
                    let _ = monitor.shutdown();
                }
                let _ = local_control.shutdown();
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
    http_fields.extend(app.auth_runtime.startup_fields());
    http_fields.extend(app.control_runtime.startup_fields());
    if let Some(runtime) = app.geodata_update_runtime.as_ref() {
        http_fields.extend(runtime.startup_fields());
    }
    http_fields.extend(sse_runtime.startup_fields());
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
    if !app.shutdown.mark_ready() {
        queue.close();
        for handle in handles {
            let _ = handle.join();
        }
        drop(sse_runtime);
        if let Some(monitor) = allocator_monitor {
            monitor.shutdown()?;
        }
        local_control.shutdown()?;
        return Ok(());
    }

    let mut accept_error = None;
    while !app.shutdown.is_requested() {
        match listener.accept() {
            Ok((stream, _)) => {
                if app.shutdown.is_requested() {
                    let _ = write_http_shutting_down(stream);
                    break;
                }
                app.http_metrics.accepted();
                match queue.try_submit(ProductHttpJob { stream }, || app.http_metrics.enqueued()) {
                    Ok(()) => {}
                    Err(ProductHttpQueueSendError::Full(job)) => {
                        app.http_metrics.rejected();
                        let _ = write_http_rejected(job.stream);
                    }
                    Err(ProductHttpQueueSendError::Closed(job)) => {
                        app.http_metrics.rejected();
                        let _ = write_http_rejected(job.stream);
                        app.shutdown.request(0);
                        break;
                    }
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) =
                    wait_for_listener_readiness(&listener, LISTENER_SHUTDOWN_CHECK_INTERVAL)
                {
                    accept_error = Some(err);
                    app.shutdown.request(0);
                    break;
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                accept_error = Some(err);
                app.shutdown.request(0);
                break;
            }
        }
    }
    let connection_shutdown = connections.shutdown_all();
    queue.close();
    let mut worker_panicked = false;
    for handle in handles {
        worker_panicked |= handle.join().is_err();
    }
    drop(sse_runtime);
    let allocator_result = match allocator_monitor {
        Some(monitor) => monitor.shutdown(),
        None => Ok(()),
    };
    let local_control_result = local_control.shutdown();
    if let Some(err) = accept_error {
        return Err(err);
    }
    if worker_panicked {
        return Err(io::Error::other("one or more HTTP workers panicked"));
    }
    connection_shutdown?;
    allocator_result?;
    local_control_result?;
    Ok(())
}

struct ProductHttpJob {
    stream: TcpStream,
}

fn product_http_worker_loop(
    _index: usize,
    queue: Arc<ProductHttpJobQueue<ProductHttpJob>>,
    app: Arc<AppState>,
    metrics: Arc<ProductHttpMetrics>,
    sse_runtime: Arc<ProductSseRuntime>,
    connections: Arc<ProductHttpConnectionRegistry>,
) {
    let mut reclaim_worker = app.ui_runtime.register_reclaim_worker();
    let mut allocator_worker = allocator_register_reclaim_worker(AllocatorWorkerKind::Http);
    loop {
        match queue.receive_timeout(PRODUCT_HTTP_WORKER_RECV_TIMEOUT) {
            Ok(job) => {
                metrics.dequeued();
                metrics.opened();
                if app.shutdown.is_requested() {
                    let _ = write_http_shutting_down(job.stream);
                    metrics.closed();
                    continue;
                }
                let _connection = match connections.register(&job.stream) {
                    Ok(connection) => connection,
                    Err(_) => {
                        let _ = write_http_shutting_down(job.stream);
                        metrics.closed();
                        continue;
                    }
                };
                if matches!(
                    handle_stream(
                        job.stream,
                        Arc::clone(&app),
                        Arc::clone(&metrics),
                        Some(Arc::clone(&sse_runtime)),
                    ),
                    Ok(ProductHttpConnectionResult::Detached)
                ) {
                    continue;
                }
                metrics.closed();
            }
            Err(ProductHttpQueueReceiveError::Timeout) => {}
            Err(ProductHttpQueueReceiveError::Closed) => break,
        }
        allocator_worker.poll();
        app.ui_runtime.maintain(&metrics, &mut reclaim_worker);
    }
}

pub(super) enum ProductHttpConnectionResult {
    Closed,
    Detached,
}

pub(super) fn write_http_rejected(mut stream: TcpStream) -> io::Result<()> {
    let response = HttpResponse::json(
        503,
        json!({"error": "daed HTTP worker queue is full; retry later"}),
    );
    write_http_response_with_timeout(
        &mut stream,
        &response,
        false,
        PRODUCT_HTTP_REJECT_WRITE_TIMEOUT,
    )
}

fn write_http_shutting_down(mut stream: TcpStream) -> io::Result<()> {
    let response = HttpResponse::json(503, json!({"error": "daed is shutting down"}));
    write_http_response_with_timeout(
        &mut stream,
        &response,
        false,
        PRODUCT_HTTP_REJECT_WRITE_TIMEOUT,
    )
}

pub(super) fn handle_stream(
    mut stream: TcpStream,
    app: Arc<AppState>,
    metrics: Arc<ProductHttpMetrics>,
    sse_runtime: Option<Arc<ProductSseRuntime>>,
) -> io::Result<ProductHttpConnectionResult> {
    if app.shutdown.is_requested() {
        write_http_shutting_down(stream)?;
        return Ok(ProductHttpConnectionResult::Closed);
    }
    let context = ProductHttpRequestContext {
        peer_ip: stream.peer_addr().ok().map(|peer| peer.ip()),
    };
    let request = match read_http_request(&mut stream) {
        Ok(request) => request,
        Err(err) => {
            metrics.request_read.record(err.kind());
            if let Some(response) = http_request_read_error_response(&err) {
                write_http_response(&mut stream, &response, false)?;
            }
            return Ok(ProductHttpConnectionResult::Closed);
        }
    };
    let _ui_request = app.ui_runtime.request_lease(&request);
    let head_only = request.method == "HEAD";
    if !app.api_only && is_static_request(&request) {
        write_static_file_response(&mut stream, &app.web_root, &request, head_only)?;
        return Ok(ProductHttpConnectionResult::Closed);
    }
    if request.method == "GET"
        && (request.path == "/api/events/logs" || request.path == "/api/events/runtime")
    {
        let user = match authenticate_request(&app, &request) {
            Ok(Some(user)) => user,
            Ok(None) => {
                let response = HttpResponse::json(401, json!({"error": "authentication required"}));
                write_http_response_for_request(&mut stream, &request, &response, head_only)?;
                return Ok(ProductHttpConnectionResult::Closed);
            }
            Err(err) => {
                let response = HttpResponse::json(500, json!({"error": err.to_string()}));
                write_http_response_for_request(&mut stream, &request, &response, head_only)?;
                return Ok(ProductHttpConnectionResult::Closed);
            }
        };
        let Some(sse_runtime) = sse_runtime.as_deref() else {
            let response = HttpResponse::json(503, json!({"error": "SSE runtime is unavailable"}));
            write_http_response_for_request(&mut stream, &request, &response, false)?;
            return Ok(ProductHttpConnectionResult::Closed);
        };
        return detach_sse_stream(
            stream,
            metrics,
            request,
            user.id,
            sse_runtime,
            &app.ui_runtime,
        );
    }
    if let Some(kind) = geodata_update_kind_for_request(&request)
        && let Some(runtime) = app.geodata_update_runtime.as_ref()
    {
        match authenticate_request(&app, &request) {
            Ok(Some(_user)) => {}
            Ok(None) => {
                let response = HttpResponse::json(401, json!({"error": "authentication required"}));
                write_http_response_for_request(&mut stream, &request, &response, false)?;
                return Ok(ProductHttpConnectionResult::Closed);
            }
            Err(err) => {
                let response = HttpResponse::json(500, json!({"error": err.to_string()}));
                write_http_response_for_request(&mut stream, &request, &response, false)?;
                return Ok(ProductHttpConnectionResult::Closed);
            }
        }
        return detach_geodata_update_stream(stream, request, kind, runtime, metrics);
    }
    let response = route_request_with_context(&app, &request, context);
    write_http_response_for_request(&mut stream, &request, &response, head_only)?;
    Ok(ProductHttpConnectionResult::Closed)
}

fn is_static_request(request: &HttpRequest) -> bool {
    request.path != "/health" && !request.path.starts_with("/api")
}

fn detach_geodata_update_stream(
    stream: TcpStream,
    request: HttpRequest,
    kind: GeodataKind,
    runtime: &ProductGeodataUpdateRuntime,
    metrics: Arc<ProductHttpMetrics>,
) -> io::Result<ProductHttpConnectionResult> {
    match runtime.submit(kind, stream, request, metrics) {
        Ok(()) => Ok(ProductHttpConnectionResult::Detached),
        Err(mut rejection) => {
            write_http_response_for_request(
                &mut rejection.stream,
                &rejection.request,
                &rejection.response,
                false,
            )?;
            Ok(ProductHttpConnectionResult::Closed)
        }
    }
}

fn detach_sse_stream(
    mut stream: TcpStream,
    metrics: Arc<ProductHttpMetrics>,
    request: HttpRequest,
    user_id: i64,
    runtime: &ProductSseRuntime,
    ui_runtime: &Arc<ProductUiRuntime>,
) -> io::Result<ProductHttpConnectionResult> {
    let stream_kind = if request.path == "/api/events/logs" {
        if let Err(error) = log_level_filter_from_request(&request)
            .and_then(|_| log_event_after_id_from_request(&request).map(|_| ()))
        {
            let response = HttpResponse::json(400, json!({"error": error}));
            write_http_response_for_request(&mut stream, &request, &response, false)?;
            return Ok(ProductHttpConnectionResult::Closed);
        }
        ProductSseStreamKind::Logs
    } else {
        ProductSseStreamKind::Runtime
    };
    match runtime.submit(user_id, stream_kind, stream, request, metrics, ui_runtime) {
        Ok(()) => Ok(ProductHttpConnectionResult::Detached),
        Err(mut rejection) => {
            write_http_response_for_request(
                &mut rejection.stream,
                &rejection.request,
                &rejection.response,
                false,
            )?;
            Ok(ProductHttpConnectionResult::Closed)
        }
    }
}

#[cfg(test)]
mod shutdown_tests;
