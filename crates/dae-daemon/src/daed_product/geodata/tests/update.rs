use super::super::update::update_geodata;
use super::*;

#[test]
fn concurrent_same_kind_update_is_rejected_before_a_second_download() {
    let dir = std::env::temp_dir().join(format!(
        "daed-product-geodata-concurrent-update-{}",
        fastrand::u64(..)
    ));
    fs::create_dir_all(&dir).unwrap();
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let source_url = format!("http://{}/geosite.dat", listener.local_addr().unwrap());
    let state = dir.join("daed.db");
    set_geodata_source_url(&state, GeodataKind::Geosite, &source_url).unwrap();
    let app = AppState {
        config_dir: dir.clone(),
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
        geodata_updates: Arc::new(ProductGeodataUpdateCoordinator::default()),
        geodata_status_cache: Arc::new(Mutex::new(GeodataStatusCache::default())),
        geodata_update_runtime: None,
        control_runtime: product_test_control_runtime(),
    };
    let body = message([field_message(
        1,
        message([
            field_string(1, "geosite:fixture"),
            field_message(2, message([field_string(2, "fixture.example")])),
        ]),
    )]);
    let (first_accepted_sender, first_accepted_receiver) = std::sync::mpsc::sync_channel(1);
    let (release_first_sender, release_first_receiver) = std::sync::mpsc::sync_channel(1);
    let request_count = Arc::new(AtomicU64::new(0));
    let server_request_count = Arc::clone(&request_count);
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut idle_deadline = None;
        let mut first = true;
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    server_request_count.fetch_add(1, Ordering::Relaxed);
                    read_request_head(&mut stream);
                    if first {
                        first = false;
                        first_accepted_sender.send(()).unwrap();
                        release_first_receiver
                            .recv_timeout(Duration::from_secs(1))
                            .unwrap();
                    }
                    write_response(&mut stream, &body);
                    idle_deadline = Some(Instant::now() + Duration::from_millis(200));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if idle_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept geodata fixture request: {error}"),
            }
        }
    });
    let first_app = app.clone();
    let first = thread::spawn(move || update_geodata(&first_app, GeodataKind::Geosite));
    first_accepted_receiver
        .recv_timeout(Duration::from_secs(1))
        .unwrap();
    let second_app = app.clone();
    let second = thread::spawn(move || update_geodata(&second_app, GeodataKind::Geosite));
    thread::sleep(Duration::from_millis(20));
    release_first_sender.send(()).unwrap();

    assert!(first.join().unwrap().is_ok());
    let second_error = second.join().unwrap().unwrap_err();
    assert_eq!(second_error.kind(), io::ErrorKind::WouldBlock);
    assert!(second_error.to_string().contains("already in progress"));
    server.join().unwrap();
    assert_eq!(request_count.load(Ordering::Relaxed), 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn geodata_update_api_reports_same_kind_conflict_truthfully() {
    let dir = std::env::temp_dir().join(format!(
        "daed-product-geodata-update-conflict-{}",
        fastrand::u64(..)
    ));
    fs::create_dir_all(&dir).unwrap();
    let app = AppState {
        config_dir: dir.clone(),
        state: dir.join("daed.db"),
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
        geodata_updates: Arc::new(ProductGeodataUpdateCoordinator::default()),
        geodata_status_cache: Arc::new(Mutex::new(GeodataStatusCache::default())),
        geodata_update_runtime: None,
        control_runtime: product_test_control_runtime(),
    };
    let _lease = app.geodata_updates.acquire(GeodataKind::Geosite).unwrap();

    let response = api_update_geodata(&app, GeodataKind::Geosite);

    assert_eq!(response.status, 409);
    assert_eq!(status_reason(response.status), "Conflict");
    fs::remove_dir_all(dir).unwrap();
}

fn read_request_head(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    while find_subsequence(&request, b"\r\n\r\n").is_none() {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0);
        request.extend_from_slice(&buffer[..read]);
    }
}

fn write_response(stream: &mut TcpStream, body: &[u8]) {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();
}
