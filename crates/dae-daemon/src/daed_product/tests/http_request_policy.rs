use super::*;

fn read_request_bytes(raw: Vec<u8>) -> Result<HttpRequest, HttpRequestReadError> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let writer = thread::spawn(move || {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.write_all(&raw).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
    });
    let (mut stream, _) = listener.accept().unwrap();
    let request = read_http_request(&mut stream);
    writer.join().expect("HTTP request writer panicked");
    request
}

fn read_delayed_request(
    chunks: Vec<(Duration, Vec<u8>)>,
    policy: HttpRequestReadPolicy,
) -> Result<HttpRequest, HttpRequestReadError> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer_cancelled = Arc::clone(&cancelled);
    let writer = thread::spawn(move || {
        let Ok(mut stream) = TcpStream::connect(address) else {
            return;
        };
        for (delay, chunk) in chunks {
            if writer_cancelled.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(delay);
            if writer_cancelled.load(Ordering::Relaxed) {
                return;
            }
            if stream.write_all(&chunk).is_err() {
                return;
            }
        }
        let _ = stream.shutdown(std::net::Shutdown::Write);
    });
    let (mut stream, _) = listener.accept().unwrap();
    let request = read_http_request_with_policy(&mut stream, policy);
    cancelled.store(true, Ordering::Relaxed);
    writer.join().expect("delayed HTTP request writer panicked");
    request
}

fn read_idle_request(policy: HttpRequestReadPolicy) -> (HttpRequestReadError, Duration) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer_cancelled = Arc::clone(&cancelled);
    let writer = thread::spawn(move || {
        let _stream = TcpStream::connect(address).unwrap();
        while !writer_cancelled.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(1));
        }
    });
    let (mut stream, _) = listener.accept().unwrap();
    let started = Instant::now();
    let error = read_http_request_with_policy(&mut stream, policy).unwrap_err();
    let elapsed = started.elapsed();
    cancelled.store(true, Ordering::Relaxed);
    writer.join().unwrap();
    (error, elapsed)
}

#[test]
fn overload_status_lines_use_truthful_reason_phrases() {
    assert_eq!(status_reason(429), "Too Many Requests");
    assert_eq!(status_reason(503), "Service Unavailable");
    assert_eq!(status_reason(408), "Request Timeout");
    assert_ne!(status_reason(599), "OK");
}

#[test]
fn request_parser_rejects_excessive_header_count() {
    let mut request = String::from("GET / HTTP/1.1\r\n");
    for index in 0..=MAX_HTTP_HEADER_COUNT {
        request.push_str(&format!("X-Fixture-{index}: value\r\n"));
    }
    request.push_str("\r\n");

    let error = read_request_bytes(request.into_bytes()).unwrap_err();
    assert!(error.to_string().contains("too many request headers"));
}

#[test]
fn request_parser_rejects_malformed_header_lines() {
    let error = read_request_bytes(b"GET / HTTP/1.1\r\nnot-a-header\r\n\r\n".to_vec()).unwrap_err();
    assert!(error.to_string().contains("malformed request header"));
}

#[test]
fn request_parser_rejects_malformed_request_lines() {
    for raw in [
        b"GET /\r\nHost: localhost\r\n\r\n".as_slice(),
        b"GET  / HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
        b"GET\t/ HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
        b"GET / HTTP/2\r\nHost: localhost\r\n\r\n".as_slice(),
    ] {
        assert!(read_request_bytes(raw.to_vec()).is_err());
    }
}

#[test]
fn request_parser_rejects_oversized_headers() {
    let oversized = "x".repeat(MAX_HTTP_HEADER_BYTES);
    let request = format!("GET / HTTP/1.1\r\nX-Fixture: {oversized}\r\n\r\n");

    let error = read_request_bytes(request.into_bytes()).unwrap_err();
    assert!(error.to_string().contains("request headers are too large"));
}

#[test]
fn request_header_uses_one_absolute_deadline_across_progress() {
    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let chunks = request
        .iter()
        .map(|byte| (Duration::from_millis(20), vec![*byte]))
        .collect();
    let policy = HttpRequestReadPolicy {
        header_timeout: Duration::from_millis(120),
        header_rate_grace: Duration::from_secs(1),
        header_min_bytes_per_second: 0,
        body_idle_timeout: Duration::from_secs(1),
        body_timeout: Duration::from_secs(1),
        bundle_body_timeout: Duration::from_secs(1),
    };
    let started_at = Instant::now();

    let error = read_delayed_request(chunks, policy).unwrap_err();

    assert_eq!(error.io_kind(), io::ErrorKind::TimedOut);
    assert!(error.to_string().contains("header read deadline"));
    assert!(started_at.elapsed() < Duration::from_millis(500));
}

#[test]
fn request_header_minimum_rate_rejects_a_drip_feed_before_absolute_timeout() {
    let chunks = vec![
        (Duration::ZERO, b"G".to_vec()),
        (
            Duration::from_millis(150),
            b"ET / HTTP/1.1\r\n\r\n".to_vec(),
        ),
    ];
    let policy = HttpRequestReadPolicy {
        header_timeout: Duration::from_secs(2),
        header_rate_grace: Duration::from_millis(50),
        header_min_bytes_per_second: 1_000,
        body_idle_timeout: Duration::from_secs(1),
        body_timeout: Duration::from_secs(1),
        bundle_body_timeout: Duration::from_secs(1),
    };

    let error = read_delayed_request(chunks, policy).unwrap_err();

    assert_eq!(error.io_kind(), io::ErrorKind::TimedOut);
    assert!(error.to_string().contains("header read deadline"));
}

#[test]
fn valid_request_completed_near_the_header_deadline_is_accepted() {
    let policy = HttpRequestReadPolicy {
        header_timeout: Duration::from_millis(500),
        header_rate_grace: Duration::from_millis(20),
        header_min_bytes_per_second: 0,
        body_idle_timeout: Duration::from_secs(1),
        body_timeout: Duration::from_secs(1),
        bundle_body_timeout: Duration::from_secs(1),
    };
    let request = read_delayed_request(
        vec![
            (
                Duration::from_millis(150),
                b"GET /api/general HTTP/1.1\r\n".to_vec(),
            ),
            (
                Duration::from_millis(150),
                b"Host: localhost\r\n\r\n".to_vec(),
            ),
        ],
        policy,
    )
    .unwrap();

    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/api/general");
}

#[test]
fn request_body_has_an_independent_idle_budget() {
    let chunks = vec![
        (
            Duration::ZERO,
            b"POST /api/auth/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n"
                .to_vec(),
        ),
        (Duration::from_millis(100), b"body".to_vec()),
    ];
    let policy = HttpRequestReadPolicy {
        header_timeout: Duration::from_millis(50),
        header_rate_grace: Duration::from_millis(50),
        header_min_bytes_per_second: 0,
        body_idle_timeout: Duration::from_millis(300),
        body_timeout: Duration::from_millis(300),
        bundle_body_timeout: Duration::from_millis(300),
    };

    let request = read_delayed_request(chunks, policy).unwrap();

    assert_eq!(request.body, b"body");
}

#[test]
fn request_body_drip_feed_cannot_extend_its_absolute_deadline() {
    let mut chunks = vec![(
        Duration::ZERO,
        b"POST /api/auth/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 20\r\n\r\n".to_vec(),
    )];
    chunks.extend((0..20).map(|_| (Duration::from_millis(20), vec![b'x'])));
    let policy = HttpRequestReadPolicy {
        header_timeout: Duration::from_secs(1),
        header_rate_grace: Duration::from_secs(1),
        header_min_bytes_per_second: 0,
        body_idle_timeout: Duration::from_secs(1),
        body_timeout: Duration::from_millis(120),
        bundle_body_timeout: Duration::from_secs(1),
    };

    let error = read_delayed_request(chunks, policy).unwrap_err();

    assert_eq!(error.io_kind(), io::ErrorKind::TimedOut);
    assert!(error.to_string().contains("body read deadline"));
}

#[test]
fn zero_byte_header_idle_uses_the_full_absolute_timeout() {
    let policy = HttpRequestReadPolicy {
        header_timeout: Duration::from_millis(100),
        header_rate_grace: Duration::from_millis(10),
        header_min_bytes_per_second: 100_000,
        body_idle_timeout: Duration::from_secs(1),
        body_timeout: Duration::from_secs(1),
        bundle_body_timeout: Duration::from_secs(1),
    };

    let (error, elapsed) = read_idle_request(policy);

    assert_eq!(error.kind(), HttpRequestReadErrorKind::IdleHeaderTimeout);
    assert!(elapsed >= Duration::from_millis(80), "elapsed={elapsed:?}");
    assert!(elapsed < Duration::from_secs(1), "elapsed={elapsed:?}");
    assert!(http_request_read_error_response(&error).is_none());
}

#[test]
fn partial_header_timeout_returns_a_typed_retryable_408() {
    let policy = HttpRequestReadPolicy {
        header_timeout: Duration::from_secs(1),
        header_rate_grace: Duration::from_millis(40),
        header_min_bytes_per_second: 100_000,
        body_idle_timeout: Duration::from_secs(1),
        body_timeout: Duration::from_secs(1),
        bundle_body_timeout: Duration::from_secs(1),
    };
    let error = read_delayed_request(
        vec![
            (Duration::ZERO, b"G".to_vec()),
            (Duration::from_millis(120), Vec::new()),
        ],
        policy,
    )
    .unwrap_err();

    assert_eq!(error.kind(), HttpRequestReadErrorKind::PartialHeaderTimeout);
    let response = http_request_read_error_response(&error).unwrap();
    assert_eq!(response.status, 408);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["errorCode"], "request_header_timeout");
    assert_eq!(body["retryable"], true);
}

#[test]
fn partial_body_timeout_returns_a_typed_retryable_408() {
    let policy = HttpRequestReadPolicy {
        header_timeout: Duration::from_secs(1),
        header_rate_grace: Duration::from_secs(1),
        header_min_bytes_per_second: 0,
        body_idle_timeout: Duration::from_millis(40),
        body_timeout: Duration::from_secs(1),
        bundle_body_timeout: Duration::from_secs(1),
    };
    let error = read_delayed_request(
        vec![
            (
                Duration::ZERO,
                b"POST /api/auth/login HTTP/1.1\r\nContent-Length: 4\r\n\r\nx".to_vec(),
            ),
            (Duration::from_millis(120), Vec::new()),
        ],
        policy,
    )
    .unwrap_err();

    assert_eq!(error.kind(), HttpRequestReadErrorKind::BodyTimeout);
    let response = http_request_read_error_response(&error).unwrap();
    assert_eq!(response.status, 408);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["errorCode"], "request_body_timeout");
    assert_eq!(body["retryable"], true);
}

#[test]
fn request_read_metrics_count_typed_failures_without_logs() {
    let metrics = ProductHttpRequestReadMetrics::default();
    metrics.record(HttpRequestReadErrorKind::IdleHeaderTimeout);
    metrics.record(HttpRequestReadErrorKind::PartialHeaderTimeout);
    metrics.record(HttpRequestReadErrorKind::BodyTimeout);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot["idleHeaderTimeoutTotal"], 1);
    assert_eq!(snapshot["partialHeaderTimeoutTotal"], 1);
    assert_eq!(snapshot["bodyTimeoutTotal"], 1);
    assert_eq!(snapshot["invalidRequestTotal"], 0);
}

#[test]
fn bundle_upload_uses_its_independent_body_budget() {
    let policy = HttpRequestReadPolicy {
        header_timeout: Duration::from_secs(1),
        header_rate_grace: Duration::from_secs(1),
        header_min_bytes_per_second: 0,
        body_idle_timeout: Duration::from_secs(1),
        body_timeout: Duration::from_secs(2),
        bundle_body_timeout: Duration::from_secs(7),
    };

    assert_eq!(
        policy.body_timeout_for("PUT", DAE_BUNDLE_IMPORT_PATH),
        Duration::from_secs(7)
    );
    assert_eq!(
        policy.body_timeout_for("POST", DAE_BUNDLE_IMPORT_PATH),
        Duration::from_secs(2)
    );
}

#[test]
fn invalid_or_ambiguous_body_framing_is_rejected() {
    for raw in [
        b"POST / HTTP/1.1\r\nContent-Length: invalid\r\n\r\n".as_slice(),
        b"POST / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".as_slice(),
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
    ] {
        assert!(read_request_bytes(raw.to_vec()).is_err());
    }
}

#[test]
fn queue_rejection_writes_service_unavailable_status_line() {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let writer = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        write_http_rejected(stream).unwrap();
    });
    let mut client = TcpStream::connect(address).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    writer.join().unwrap();

    assert_eq!(
        response.lines().next(),
        Some("HTTP/1.1 503 Service Unavailable")
    );
}
