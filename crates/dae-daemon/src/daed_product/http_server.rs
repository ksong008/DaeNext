use super::*;
pub(super) fn serve_forever(
    listen: &str,
    app: AppState,
    startup_started_at: Instant,
) -> io::Result<()> {
    let listen_started_at = Instant::now();
    let listener = TcpListener::bind(listen)?;
    let app = Arc::new(app);
    spawn_local_control_socket(Arc::clone(&app))?;
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
    http_fields.extend(app.auth_runtime.startup_fields());
    if let Some(runtime) = app.geodata_update_runtime.as_ref() {
        http_fields.extend(runtime.startup_fields());
    }
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
                if matches!(
                    handle_stream(job.stream, Arc::clone(&app), Arc::clone(&metrics)),
                    Ok(ProductHttpConnectionResult::Detached)
                ) {
                    continue;
                }
                metrics.closed();
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
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

pub(super) fn handle_stream(
    mut stream: TcpStream,
    app: Arc<AppState>,
    metrics: Arc<ProductHttpMetrics>,
) -> io::Result<ProductHttpConnectionResult> {
    let context = ProductHttpRequestContext {
        peer_ip: stream.peer_addr().ok().map(|peer| peer.ip()),
    };
    let request = match read_http_request(&mut stream) {
        Ok(request) => request,
        Err(err) => {
            let response = HttpResponse::json(
                400,
                json!({
                    "error": format!("bad request: {err}")
                }),
            );
            write_http_response(&mut stream, &response, false)?;
            return Ok(ProductHttpConnectionResult::Closed);
        }
    };
    let head_only = request.method == "HEAD";
    if request.method == "GET"
        && (request.path == "/api/events/logs" || request.path == "/api/events/runtime")
    {
        match authenticate_request(&app, &request) {
            Ok(Some(_user)) => {}
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
        return detach_sse_stream(stream, app, metrics, request);
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
    app: Arc<AppState>,
    metrics: Arc<ProductHttpMetrics>,
    request: HttpRequest,
) -> io::Result<ProductHttpConnectionResult> {
    let stream_kind = if request.path == "/api/events/logs" {
        "logs"
    } else {
        "runtime"
    };
    stream.set_write_timeout(Some(PRODUCT_HTTP_SSE_WRITE_TIMEOUT))?;
    let thread_name = format!("daed-sse-{stream_kind}");
    metrics.sse_opened();
    let thread_metrics = Arc::clone(&metrics);
    match thread::Builder::new()
        .name(thread_name)
        .stack_size(PRODUCT_HTTP_LOW_MEMORY_WORKER_STACK_BYTES_DEFAULT)
        .spawn(move || {
            if request.path == "/api/events/logs" {
                let _ = stream_log_events(&mut stream, &app, &request);
            } else {
                let _ = stream_runtime_events(&mut stream, &app, &request);
            }
            thread_metrics.sse_closed();
            thread_metrics.closed();
        }) {
        Ok(_) => Ok(ProductHttpConnectionResult::Detached),
        Err(err) => {
            metrics.sse_closed();
            Err(err)
        }
    }
}
