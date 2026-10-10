use super::*;

#[test]
fn exhausted_snapshot_returns_retryable_http_response_and_recovers() {
    let dir = std::env::temp_dir().join(format!("daed-log-snapshot-http-{}", fastrand::u64(..)));
    fs::create_dir_all(product_log_dir(&dir)).unwrap();
    let path = product_log_file(&dir);
    fs::write(&path, b"old\n").unwrap();
    let mut attempts = 0;
    let result = with_product_log_snapshot(&dir, |_| {
        attempts += 1;
        let replacement = path.with_extension("replacement");
        fs::write(&replacement, b"new\n").unwrap();
        fs::rename(replacement, &path).unwrap();
        Ok(())
    });
    assert_eq!(attempts, 3);
    let response = log_query_error_response(result.unwrap_err());
    assert_eq!(response.status, 503);
    let payload: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(payload["errorCode"], "log_snapshot_unstable");
    assert_eq!(payload["retryable"], true);
    assert!(
        response
            .extra_headers
            .contains(&("Retry-After".to_owned(), "1".to_owned()))
    );
    assert!(with_product_log_snapshot(&dir, |_| Ok(())).is_ok());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unstable_snapshot_preserves_real_scan_errors() {
    let dir = std::env::temp_dir().join(format!("daed-log-snapshot-error-{}", fastrand::u64(..)));
    fs::create_dir_all(product_log_dir(&dir)).unwrap();
    let path = product_log_file(&dir);
    fs::write(&path, b"old\n").unwrap();
    let mut attempts = 0;
    let result = with_product_log_snapshot::<()>(&dir, |_| {
        attempts += 1;
        let replacement = path.with_extension("replacement");
        fs::write(&replacement, b"new\n").unwrap();
        fs::rename(replacement, &path).unwrap();
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "scan denied",
        ))
    });
    assert_eq!(attempts, 1);
    let error = result.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    let response = log_query_error_response(error);
    assert_eq!(response.status, 500);
    let payload: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(payload["error"], "scan denied");
    assert!(payload.get("retryable").is_none());
    assert!(
        response
            .extra_headers
            .iter()
            .all(|(key, _)| key != "Retry-After")
    );
    fs::remove_dir_all(dir).unwrap();
}
