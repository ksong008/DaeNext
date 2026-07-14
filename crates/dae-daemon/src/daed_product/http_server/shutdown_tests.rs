use super::*;
use std::io::{Read, Write};

struct TestProductServer {
    root: PathBuf,
    listen: String,
    control_socket: PathBuf,
    shutdown: Arc<ProductShutdown>,
    app: Arc<AppState>,
    server: thread::JoinHandle<io::Result<()>>,
}

fn start_test_product_server(scope: &str) -> TestProductServer {
    let root = std::env::temp_dir().join(format!(
        "daed-http-{scope}-{}-{}",
        std::process::id(),
        fastrand::u64(..)
    ));
    fs::create_dir_all(&root).unwrap();
    let state = root.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = probe.local_addr().unwrap().to_string();
    drop(probe);
    let control_socket = root.join("control.sock");
    let shutdown = Arc::new(ProductShutdown::default());
    let app = Arc::new(AppState {
        config_dir: root.clone(),
        state,
        web_root: root.clone(),
        api_only: true,
        control_socket: control_socket.clone(),
        shutdown: Arc::clone(&shutdown),
        runtime: Arc::new(ProductRuntimeManager::new()),
        runtime_sampler: None,
        latency_jobs: Arc::new(LatencyJobManager::default()),
        http_metrics: Arc::new(ProductHttpMetrics::default()),
        auth_runtime: product_test_auth_runtime(),
        geodata_updates: Arc::new(geodata::ProductGeodataUpdateCoordinator::default()),
        geodata_status_cache: Arc::new(Mutex::new(GeodataStatusCache::default())),
        geodata_update_runtime: None,
    });
    let server_app = Arc::clone(&app);
    let server_listen = listen.clone();
    let server = thread::spawn(move || serve_forever(&server_listen, server_app, Instant::now()));
    let deadline = Instant::now() + Duration::from_secs(2);
    while !shutdown.is_ready() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(shutdown.is_ready());
    assert!(control_socket.exists());
    TestProductServer {
        root,
        listen,
        control_socket,
        shutdown,
        app,
        server,
    }
}

fn finish_test_product_server(fixture: TestProductServer) {
    fixture.server.join().unwrap().unwrap();
    assert!(!fixture.control_socket.exists());
    assert_eq!(Arc::strong_count(&fixture.app), 1);
    drop(fixture.app);
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn product_shutdown_wakes_accept_loop_joins_workers_and_removes_control_socket() {
    let fixture = start_test_product_server("shutdown");
    assert!(fixture.shutdown.request(libc::SIGTERM));
    finish_test_product_server(fixture);
}

#[test]
fn product_shutdown_interrupts_an_active_http_body_read() {
    let fixture = start_test_product_server("active-body-shutdown");
    let mut client = TcpStream::connect(&fixture.listen).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client
        .write_all(
            b"POST /api/auth/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n{",
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while fixture
        .app
        .http_metrics
        .active_connections
        .load(Ordering::Relaxed)
        == 0
        && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        fixture
            .app
            .http_metrics
            .active_connections
            .load(Ordering::Relaxed),
        1
    );
    let shutdown_started = Instant::now();
    assert!(fixture.shutdown.request(libc::SIGTERM));
    finish_test_product_server(fixture);
    assert!(shutdown_started.elapsed() < Duration::from_secs(2));
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response);
}
