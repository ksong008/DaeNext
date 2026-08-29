use super::*;

#[cfg(target_os = "linux")]
static SSE_RUNTIME_THREAD_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn sse_admission_is_bounded_globally_and_per_user() {
    let config = ProductSseRuntimeConfig::for_test();
    let admission = Arc::new(ProductSseAdmission::new(config));
    let first = admission.acquire(1).unwrap();
    let second = admission.acquire(1).unwrap();
    assert_eq!(
        admission.acquire(1).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    let third = admission.acquire(2).unwrap();
    let fourth = admission.acquire(2).unwrap();
    assert_eq!(
        admission.acquire(3).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    drop((first, second, third, fourth));
    assert!(admission.acquire(3).is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn multiple_sse_connections_share_one_runtime_thread() {
    let _thread_guard = SSE_RUNTIME_THREAD_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = std::env::temp_dir().join(format!("daed-product-sse-runtime-{}", fastrand::u64(..)));
    fs::create_dir_all(&dir).unwrap();
    let app = Arc::new(test_app(&dir));
    let metrics = Arc::clone(&app.http_metrics);
    let baseline_threads = named_thread_count("daed-sse-rt");
    let runtime = ProductSseRuntime::start_with_config(
        ProductSseRuntimeConfig::for_test(),
        Arc::downgrade(&app),
        Arc::clone(&metrics),
    )
    .unwrap();
    assert_eq!(named_thread_count("daed-sse-rt"), baseline_threads);

    let mut clients = Vec::new();
    for user_id in [1_i64, 1, 2, 2] {
        let (server, mut client) = connected_streams();
        metrics.opened();
        runtime
            .submit(
                user_id,
                ProductSseStreamKind::Runtime,
                server,
                runtime_request(),
                Arc::clone(&metrics),
                &app.ui_runtime,
            )
            .unwrap();
        wait_until(Duration::from_secs(1), || {
            named_thread_count("daed-sse-rt") == baseline_threads + 1
        });
        read_until(&mut client, "event: runtime.overview");
        clients.push(client);
    }

    assert_eq!(named_thread_count("daed-sse-rt"), baseline_threads + 1);
    assert_eq!(metrics.snapshot()["activeSseConnections"], json!(4));
    drop(clients);
    wait_until(Duration::from_secs(3), || {
        metrics.snapshot()["activeSseConnections"] == json!(0)
    });
    drop(runtime);
    wait_until(Duration::from_secs(1), || {
        named_thread_count("daed-sse-rt") == baseline_threads
    });
    assert_eq!(
        metrics.snapshot()["sseRuntime"]["runtimeJoinedTotal"],
        json!(1)
    );
    drop(app);
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn runtime_shutdown_closes_active_streams_and_releases_metrics() {
    let _thread_guard = SSE_RUNTIME_THREAD_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = std::env::temp_dir().join(format!(
        "daed-product-sse-runtime-shutdown-{}",
        fastrand::u64(..)
    ));
    fs::create_dir_all(&dir).unwrap();
    let app = Arc::new(test_app(&dir));
    let metrics = Arc::clone(&app.http_metrics);
    let baseline_threads = named_thread_count("daed-sse-rt");
    let runtime = ProductSseRuntime::start_with_config(
        ProductSseRuntimeConfig::for_test(),
        Arc::downgrade(&app),
        Arc::clone(&metrics),
    )
    .unwrap();

    let mut clients = Vec::new();
    for user_id in [1_i64, 1, 2, 2] {
        let (server, client) = connected_streams();
        metrics.opened();
        runtime
            .submit(
                user_id,
                ProductSseStreamKind::Runtime,
                server,
                runtime_request(),
                Arc::clone(&metrics),
                &app.ui_runtime,
            )
            .unwrap();
        clients.push(client);
    }
    wait_until(Duration::from_secs(2), || {
        metrics.snapshot()["activeSseConnections"] == json!(4)
    });

    drop(runtime);
    wait_until(Duration::from_secs(1), || {
        named_thread_count("daed-sse-rt") == baseline_threads
    });
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot["activeConnections"], json!(0));
    assert_eq!(snapshot["activeSseConnections"], json!(0));
    assert_eq!(snapshot["sseRuntime"]["queueDepth"], json!(0));
    assert_eq!(snapshot["sseRuntime"]["completedTotal"], json!(4));
    assert_eq!(snapshot["sseRuntime"]["runtimeJoinedTotal"], json!(1));

    drop(clients);
    drop(app);
    fs::remove_dir_all(dir).unwrap();
}

fn test_app(dir: &Path) -> AppState {
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    AppState {
        config_dir: dir.to_path_buf(),
        state,
        web_root: dir.join("web"),
        api_only: true,
        control_socket: dir.join("control.sock"),
        shutdown: Arc::new(ProductShutdown::default()),
        runtime: Arc::new(ProductRuntimeManager::new()),
        runtime_sampler: None,
        latency_jobs: Arc::new(LatencyJobManager::default()),
        http_metrics: Arc::new(ProductHttpMetrics::default()),
        ui_runtime: product_ui_runtime(),
        auth_runtime: product_test_auth_runtime(),
        geodata_updates: Arc::new(geodata::ProductGeodataUpdateCoordinator::default()),
        geodata_status_cache: Arc::new(Mutex::new(GeodataStatusCache::default())),
        geodata_update_runtime: None,
        control_runtime: product_test_control_runtime(),
    }
}

fn connected_streams() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (server, client)
}

fn runtime_request() -> HttpRequest {
    HttpRequest {
        method: "GET".to_owned(),
        path: "/api/events/runtime".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: Vec::new(),
    }
}

fn read_until(stream: &mut TcpStream, needle: &str) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut response = String::new();
    let mut buffer = [0_u8; 4096];
    while !response.contains(needle) {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0);
        response.push_str(&String::from_utf8_lossy(&buffer[..read]));
    }
}

fn named_thread_count(name: &str) -> usize {
    fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_to_string(entry.path().join("comm")).ok())
        .filter(|thread_name| thread_name.trim() == name)
        .count()
}

fn wait_until(timeout: Duration, predicate: impl Fn() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(predicate(), "condition did not become true before timeout");
}
