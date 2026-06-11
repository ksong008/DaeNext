use super::*;

pub(in crate::tests) fn spawn_socks5_echo_proxy() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut head = [0_u8; 2];
        stream.read_exact(&mut head).unwrap();
        assert_eq!(head[0], 5);
        let mut methods = vec![0_u8; head[1] as usize];
        stream.read_exact(&mut methods).unwrap();
        assert!(methods.contains(&2));
        stream.write_all(&[5, 2]).unwrap();

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

        let mut request_head = [0_u8; 3];
        stream.read_exact(&mut request_head).unwrap();
        assert_eq!(request_head, [5, 1, 0]);
        let _target = read_socks5_addr_for_test(&mut stream);
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x14, 0xb4])
            .unwrap();
        echo_one_payload(&mut stream);
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_http_connect_echo_proxy() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_head_for_test(&mut stream);
        assert!(request.starts_with("CONNECT front.fixture.invalid HTTP/1.1\r\n"));
        assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        echo_one_payload(&mut stream);
    });
    (addr, handle)
}

pub(in crate::tests) fn spawn_shadowsocks_aead_echo_server(
    cipher: String,
    password: String,
    server_salt: Vec<u8>,
) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (target, request_payload) =
            shadowsocks::read_client_initial_from_stream(&mut stream, &cipher, &password).unwrap();
        let response =
            shadowsocks::encode_server_payload(&cipher, &password, &server_salt, &request_payload)
                .unwrap();
        stream.write_all(&response).unwrap();
        target.authority()
    });
    (addr, handle)
}
