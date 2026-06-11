use super::*;

pub(in crate::tests) fn read_socks5_addr_for_test(stream: &mut TcpStream) -> Vec<u8> {
    let mut atyp = [0_u8; 1];
    stream.read_exact(&mut atyp).unwrap();
    let mut out = atyp.to_vec();
    match atyp[0] {
        1 => {
            let mut rest = [0_u8; 6];
            stream.read_exact(&mut rest).unwrap();
            out.extend_from_slice(&rest);
        }
        3 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).unwrap();
            out.extend_from_slice(&len);
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream.read_exact(&mut rest).unwrap();
            out.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0_u8; 18];
            stream.read_exact(&mut rest).unwrap();
            out.extend_from_slice(&rest);
        }
        _ => {}
    }
    out
}

pub(in crate::tests) fn read_http_head_for_test(stream: &mut TcpStream) -> String {
    read_http_head_and_leftover_for_test(stream).0
}

pub(in crate::tests) fn read_http_head_and_leftover_for_test(
    stream: &mut TcpStream,
) -> (String, Vec<u8>) {
    let mut data = Vec::new();
    let mut buf = [0_u8; 256];
    loop {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        data.extend_from_slice(&buf[..n]);
        if let Some(index) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            let body_start = index + 4;
            let leftover = data[body_start..].to_vec();
            data.truncate(body_start);
            return (String::from_utf8(data).unwrap(), leftover);
        }
    }
}

pub(in crate::tests) fn read_http_body_for_test(
    stream: &mut TcpStream,
    request: &str,
    mut leftover: Vec<u8>,
) -> Vec<u8> {
    let content_length = content_length_for_test(request);
    while leftover.len() < content_length {
        let mut buf = vec![0_u8; content_length - leftover.len()];
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        leftover.extend_from_slice(&buf[..n]);
    }
    leftover.truncate(content_length);
    leftover
}

pub(in crate::tests) fn write_http_response_for_test(stream: &mut TcpStream, body: &[u8]) {
    stream
        .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes())
        .unwrap();
    stream.write_all(body).unwrap();
}

pub(in crate::tests) fn read_grpc_hunk_frame_for_test(
    stream: &mut TcpStream,
    mut data: Vec<u8>,
) -> Vec<u8> {
    while data.len() < 5 {
        let mut buf = [0_u8; 64];
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        data.extend_from_slice(&buf[..n]);
    }
    assert_eq!(data[0], 0);
    let payload_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
    while data.len() < 5 + payload_len {
        let mut buf = vec![0_u8; 5 + payload_len - data.len()];
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        data.extend_from_slice(&buf[..n]);
    }
    shared_transport::grpc_hunk_payload(&data[5..5 + payload_len]).unwrap()
}

pub(in crate::tests) fn content_length_for_test(request: &str) -> usize {
    request
        .split("\r\n")
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0)
}

pub(in crate::tests) fn echo_one_payload_with_leftover(
    stream: &mut TcpStream,
    mut leftover: Vec<u8>,
) {
    if leftover.is_empty() {
        let mut payload = [0_u8; 64];
        let n = stream.read(&mut payload).unwrap();
        assert!(n > 0);
        leftover.extend_from_slice(&payload[..n]);
    }
    stream.write_all(&leftover).unwrap();
}

pub(in crate::tests) fn echo_one_payload(stream: &mut TcpStream) {
    let mut payload = [0_u8; 64];
    let n = stream.read(&mut payload).unwrap();
    assert!(n > 0);
    stream.write_all(&payload[..n]).unwrap();
}
