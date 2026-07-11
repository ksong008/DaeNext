use super::*;

fn read_request_bytes(raw: Vec<u8>) -> io::Result<HttpRequest> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let writer = thread::spawn(move || -> io::Result<()> {
        let mut stream = TcpStream::connect(address)?;
        stream.write_all(&raw)?;
        stream.shutdown(std::net::Shutdown::Write)
    });
    let (mut stream, _) = listener.accept()?;
    let request = read_http_request(&mut stream);
    writer
        .join()
        .map_err(|_| io::Error::other("HTTP request writer panicked"))??;
    request
}

fn read_delayed_request(
    chunks: Vec<(Duration, Vec<u8>)>,
    policy: HttpRequestReadPolicy,
) -> io::Result<HttpRequest> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
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
    let (mut stream, _) = listener.accept()?;
    let request = read_http_request_with_policy(&mut stream, policy);
    cancelled.store(true, Ordering::Relaxed);
    writer
        .join()
        .map_err(|_| io::Error::other("delayed HTTP request writer panicked"))?;
    request
}

#[test]
fn overload_status_lines_use_truthful_reason_phrases() {
    assert_eq!(status_reason(429), "Too Many Requests");
    assert_eq!(status_reason(503), "Service Unavailable");
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

    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
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

    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(error.to_string().contains("header read deadline"));
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

    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(error.to_string().contains("body read deadline"));
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
