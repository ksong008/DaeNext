use super::http1::xhttp_request_path;
use super::options::XHttpLifecycleOptions;

pub(super) fn xhttp_request_headers_payload(options: &XHttpLifecycleOptions) -> Vec<u8> {
    let mut payload = vec![0x83, 0x87];
    push_hpack_literal_indexed_name(&mut payload, 4, xhttp_request_path(options).as_bytes());
    push_hpack_literal_indexed_name(&mut payload, 1, options.host.as_bytes());
    push_hpack_literal_new_name(&mut payload, b"content-type", b"application/octet-stream");
    push_hpack_literal_new_name(&mut payload, b"x-dae-xhttp-mode", options.mode.as_bytes());
    push_hpack_literal_new_name(&mut payload, b"x-dae-xhttp-alpn", options.alpn.as_bytes());
    payload
}

pub(super) fn xhttp_response_headers_payload() -> Vec<u8> {
    let mut payload = vec![0x88];
    push_hpack_literal_new_name(&mut payload, b"content-type", b"application/octet-stream");
    payload
}

fn push_hpack_literal_indexed_name(out: &mut Vec<u8>, name_index: u8, value: &[u8]) {
    out.push(name_index & 0x0f);
    push_hpack_string(out, value);
}

fn push_hpack_literal_new_name(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.push(0);
    push_hpack_string(out, name);
    push_hpack_string(out, value);
}

fn push_hpack_string(out: &mut Vec<u8>, value: &[u8]) {
    assert!(
        value.len() < 128,
        "xhttp hpack helper only supports short literals"
    );
    out.push(value.len() as u8);
    out.extend_from_slice(value);
}
