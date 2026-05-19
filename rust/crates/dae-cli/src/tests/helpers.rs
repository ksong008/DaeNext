use super::*;

pub(super) fn assert_commands(got: &[CommandSpec], want: &[Value]) {
    assert_eq!(got.len(), want.len());
    for (got, want) in got.iter().zip(want.iter()) {
        assert_eq!(got.name, want["name"].as_str().unwrap());
        assert_eq!(got.use_line, want["use"].as_str().unwrap());
        assert_eq!(got.short, want["short"].as_str().unwrap());
        assert_eq!(got.hidden, want["hidden"].as_bool().unwrap());
        assert_eq!(
            got.valid_args,
            want["valid_args"]
                .as_array()
                .map(|values| values
                    .iter()
                    .map(|value| value.as_str().unwrap())
                    .collect::<Vec<_>>())
                .unwrap_or_default()
                .as_slice()
        );
        assert_eq!(
            got.flags,
            want["flags"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect::<Vec<_>>()
                .as_slice()
        );
        let empty = Vec::new();
        let children = want["children"].as_array().unwrap_or(&empty);
        assert_commands(&got.children, children);
    }
}

pub(super) fn load(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}

pub(super) fn temp_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "dae-cli-test-{}-{nanos}-{name}",
        std::process::id()
    ))
}

pub(super) fn write_config(content: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "dae-cli-optin-test-{}-{nanos}.dae",
        std::process::id()
    ));
    fs::write(&path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

pub(super) fn spawn_fake_socks5_server(
    require_auth: bool,
    expected_cmd: u8,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut head = [0_u8; 2];
        stream.read_exact(&mut head).unwrap();
        assert_eq!(head[0], 5);
        let mut methods = vec![0_u8; head[1] as usize];
        stream.read_exact(&mut methods).unwrap();
        let selected = if require_auth { 2 } else { 0 };
        assert!(methods.contains(&selected));
        stream.write_all(&[5, selected]).unwrap();

        if require_auth {
            let mut auth_head = [0_u8; 2];
            stream.read_exact(&mut auth_head).unwrap();
            assert_eq!(auth_head, [1, 4]);
            let mut user = vec![0_u8; auth_head[1] as usize];
            stream.read_exact(&mut user).unwrap();
            let mut pass_len = [0_u8; 1];
            stream.read_exact(&mut pass_len).unwrap();
            let mut pass = vec![0_u8; pass_len[0] as usize];
            stream.read_exact(&mut pass).unwrap();
            assert_eq!(user, b"user");
            assert_eq!(pass, b"pass");
            stream.write_all(&[1, 0]).unwrap();
        }

        let mut request_head = [0_u8; 3];
        stream.read_exact(&mut request_head).unwrap();
        assert_eq!(request_head, [5, expected_cmd, 0]);
        let _ = read_socks5_addr_for_test(&mut stream);
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x14, 0xb4])
            .unwrap();
    });
    (addr, handle)
}

pub(super) fn read_socks5_addr_for_test(stream: &mut TcpStream) -> Vec<u8> {
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

pub(super) fn spawn_fake_http_proxy(
    expected_request_line: &'static str,
    expected_auth: Option<&'static str>,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut data = Vec::new();
        let mut buf = [0_u8; 256];
        loop {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0);
            data.extend_from_slice(&buf[..n]);
            if data.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(data).unwrap();
        let mut lines = request.split("\r\n");
        assert_eq!(lines.next().unwrap(), expected_request_line);
        if let Some(expected_auth) = expected_auth {
            assert!(request.contains(&format!("Proxy-Authorization: {expected_auth}\r\n")));
        }
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });
    (addr, handle)
}
