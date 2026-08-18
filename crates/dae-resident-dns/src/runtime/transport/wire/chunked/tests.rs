use super::*;

#[test]
fn final_crlf_is_required_after_last_chunk() {
    let error = decode_http_chunked_body_with_consumed(b"3\r\ndns\r\n0\r\n").unwrap_err();

    assert!(error.is_incomplete());
}

#[test]
fn trailers_are_consumed_but_not_returned_as_body() {
    let raw = b"3\r\ndns\r\n0\r\nX-Trace: fixture\r\nX-State: complete\r\n\r\n";
    let (body, consumed) = decode_http_chunked_body_with_consumed(raw).unwrap();

    assert_eq!(body, b"dns");
    assert_eq!(consumed, raw.len());
}

#[test]
fn malformed_trailer_is_rejected() {
    let error = decode_http_chunked_body_with_consumed(b"0\r\nnot-a-header\r\n\r\n").unwrap_err();

    assert!(!error.is_incomplete());
    assert!(error.to_string().contains("trailer is malformed"));
}
