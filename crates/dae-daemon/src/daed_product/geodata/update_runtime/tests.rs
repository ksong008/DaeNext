use super::super::source::{geodata_source, set_geodata_source_url};
use super::*;

#[test]
fn geodata_update_runtime_is_bounded_by_the_two_resource_kinds() {
    let config = ProductGeodataUpdateRuntimeConfig::for_test();
    assert_eq!(config.worker_count, 2);
    assert_eq!(config.queue_capacity, 2);
    assert_eq!(config.worker_stack_bytes, 512 * 1024);
}

#[test]
fn geodata_update_runtime_detaches_slow_work_and_rejects_same_kind_immediately() {
    let fixture = GeodataUpdateRuntimeFixture::new("detach");
    let runtime = fixture.start_runtime();
    let http_metrics = Arc::new(ProductHttpMetrics::default());
    let (first_server_stream, mut first_client_stream) = connected_streams();
    http_metrics.opened();

    runtime
        .submit(
            GeodataKind::Geosite,
            first_server_stream,
            update_request(GeodataKind::Geosite),
            Arc::clone(&http_metrics),
        )
        .unwrap();
    fixture.wait_until_download_started();

    let (second_server_stream, _second_client_stream) = connected_streams();
    let rejected = runtime
        .submit(
            GeodataKind::Geosite,
            second_server_stream,
            update_request(GeodataKind::Geosite),
            Arc::clone(&http_metrics),
        )
        .unwrap_err();
    assert_eq!(rejected.response.status, 409);
    assert_eq!(runtime.snapshot()["rejectedSameKindTotal"], json!(1));

    fixture.release_download();
    let response = read_http_response(&mut first_client_stream);
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    wait_until(Duration::from_secs(2), || {
        runtime.snapshot()["completedTotal"] == json!(1)
    });
    assert_eq!(http_metrics.snapshot()["activeConnections"], json!(0));

    drop(rejected);
    drop(runtime);
    fixture.finish();
}

#[test]
fn authenticated_http_geodata_update_releases_the_general_worker_before_download_finishes() {
    let fixture = GeodataUpdateRuntimeFixture::new("http-detach");
    let token = create_user(&fixture.state, "admin", "abc12345").unwrap();
    let mut app = fixture.test_app();
    let runtime = ProductGeodataUpdateRuntime::start_with_config(
        ProductGeodataUpdateRuntimeConfig::for_test(),
        ProductGeodataUpdateContext::from_app(&app),
    )
    .unwrap();
    app.geodata_update_runtime = Some(Arc::clone(&runtime));
    let app = Arc::new(app);
    let metrics = Arc::clone(&app.http_metrics);
    let (server_stream, mut client_stream) = connected_streams();
    write!(
        client_stream,
        "POST /api/geodata/geosite/update HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    client_stream.flush().unwrap();
    metrics.opened();

    let started = Instant::now();
    let result =
        handle_stream(server_stream, Arc::clone(&app), Arc::clone(&metrics), None).unwrap();
    assert!(matches!(result, ProductHttpConnectionResult::Detached));
    assert!(started.elapsed() < Duration::from_secs(1));
    fixture.wait_until_download_started();
    assert_eq!(metrics.snapshot()["activeConnections"], json!(1));

    fixture.release_download();
    let response = read_http_response(&mut client_stream);
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    wait_until(Duration::from_secs(2), || {
        metrics.snapshot()["activeConnections"] == json!(0)
    });

    drop(app);
    drop(runtime);
    fixture.finish();
}

#[test]
fn geodata_update_runtime_shutdown_detaches_a_bounded_blocking_worker_truthfully() {
    let fixture = GeodataUpdateRuntimeFixture::new("shutdown");
    let runtime = fixture.start_runtime();
    let http_metrics = Arc::new(ProductHttpMetrics::default());
    let (server_stream, mut client_stream) = connected_streams();
    http_metrics.opened();
    runtime
        .submit(
            GeodataKind::Geosite,
            server_stream,
            update_request(GeodataKind::Geosite),
            Arc::clone(&http_metrics),
        )
        .unwrap();
    fixture.wait_until_download_started();

    let started = Instant::now();
    drop(runtime);
    assert!(started.elapsed() < Duration::from_secs(1));

    fixture.release_download();
    let response = read_http_response(&mut client_stream);
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    wait_until(Duration::from_secs(2), || {
        http_metrics.snapshot()["activeConnections"] == json!(0)
    });
    fixture.finish();
}

struct GeodataUpdateRuntimeFixture {
    dir: PathBuf,
    state: PathBuf,
    source_url: String,
    download_started: std::sync::mpsc::Receiver<()>,
    release_download: std::sync::mpsc::SyncSender<()>,
    server: thread::JoinHandle<()>,
}

impl GeodataUpdateRuntimeFixture {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "daed-product-geodata-update-runtime-{label}-{}",
            fastrand::u64(..)
        ));
        fs::create_dir_all(&dir).unwrap();
        let state = dir.join("daed.db");
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let source_url = format!("http://{}/geosite.dat", listener.local_addr().unwrap());
        set_geodata_source_url(&state, GeodataKind::Geosite, &source_url).unwrap();
        let (started_sender, download_started) = std::sync::mpsc::sync_channel(1);
        let (release_download, release_receiver) = std::sync::mpsc::sync_channel(1);
        let body = geosite_fixture_body();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request_head(&mut stream);
            started_sender.send(()).unwrap();
            release_receiver
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
            stream.flush().unwrap();
        });
        Self {
            dir,
            state,
            source_url,
            download_started,
            release_download,
            server,
        }
    }

    fn start_runtime(&self) -> Arc<ProductGeodataUpdateRuntime> {
        assert_eq!(
            geodata_source(&self.state, GeodataKind::Geosite)
                .unwrap()
                .url
                .as_str(),
            self.source_url
        );
        let context = ProductGeodataUpdateContext::new(
            self.state.clone(),
            &self.dir.join("web"),
            Arc::new(ProductRuntimeManager::new()),
            Arc::new(ProductGeodataUpdateCoordinator::default()),
            Arc::new(Mutex::new(GeodataStatusCache::default())),
        );
        ProductGeodataUpdateRuntime::start_with_config(
            ProductGeodataUpdateRuntimeConfig::for_test(),
            context,
        )
        .unwrap()
    }

    fn test_app(&self) -> AppState {
        AppState {
            config_dir: self.dir.clone(),
            state: self.state.clone(),
            web_root: self.dir.join("web"),
            api_only: true,
            control_socket: self.dir.join("control.sock"),
            shutdown: Arc::new(ProductShutdown::default()),
            runtime: Arc::new(ProductRuntimeManager::new()),
            runtime_sampler: None,
            latency_jobs: Arc::new(LatencyJobManager::default()),
            http_metrics: Arc::new(ProductHttpMetrics::default()),
            auth_runtime: product_test_auth_runtime(),
            geodata_updates: Arc::new(ProductGeodataUpdateCoordinator::default()),
            geodata_status_cache: Arc::new(Mutex::new(GeodataStatusCache::default())),
            geodata_update_runtime: None,
        }
    }

    fn wait_until_download_started(&self) {
        self.download_started
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
    }

    fn release_download(&self) {
        self.release_download.send(()).unwrap();
    }

    fn finish(self) {
        self.server.join().unwrap();
        fs::remove_dir_all(self.dir).unwrap();
    }
}

fn connected_streams() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (server, client)
}

fn update_request(kind: GeodataKind) -> HttpRequest {
    HttpRequest {
        method: "POST".to_owned(),
        path: format!("/api/geodata/{}/update", kind.response_key()),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: Vec::new(),
    }
}

fn read_http_response(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn read_request_head(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    while find_subsequence(&request, b"\r\n\r\n").is_none() {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0);
        request.extend_from_slice(&buffer[..read]);
    }
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

fn geosite_fixture_body() -> Vec<u8> {
    message([field_message(
        1,
        message([
            field_string(1, "geosite:fixture"),
            field_message(2, message([field_string(2, "fixture.example")])),
        ]),
    )])
}

fn message(fields: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    fields.into_iter().flatten().collect()
}

fn field_string(field: u64, value: &str) -> Vec<u8> {
    field_bytes(field, value.as_bytes())
}

fn field_message(field: u64, value: Vec<u8>) -> Vec<u8> {
    field_bytes(field, &value)
}

fn field_bytes(field: u64, value: &[u8]) -> Vec<u8> {
    let mut out = field_varint_bytes(field, 2);
    write_varint(value.len() as u64, &mut out);
    out.extend_from_slice(value);
    out
}

fn field_varint_bytes(field: u64, wire: u64) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint((field << 3) | wire, &mut out);
    out
}

fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}
