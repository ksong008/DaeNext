fn open_plain_proxy_tcp_stream(proxy: &ResidentProxyPlan) -> Result<TcpStream, String> {
    if let Some(parent) = proxy.chain_parent.as_deref() {
        return open_plain_proxy_tcp_stream_through_parent(proxy, parent);
    }
    let target = format!("{}:{}", proxy.server_host, proxy.server_port);
    let connection = open_direct_tcp_connection(&target, proxy.mark, proxy.mptcp)?;
    connection
        .stream
        .set_nonblocking(false)
        .map_err(|err| format!("set proxy TCP blocking for handshake: {err}"))?;
    connection
        .stream
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set proxy TCP read timeout: {err}"))?;
    connection
        .stream
        .set_write_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set proxy TCP write timeout: {err}"))?;
    Ok(connection.stream)
}

fn open_plain_proxy_tcp_stream_through_parent(
    proxy: &ResidentProxyPlan,
    parent: &ResidentProxyPlan,
) -> Result<TcpStream, String> {
    let parent_target = format!("{}:{}", parent.server_host, parent.server_port);
    let connection = open_direct_tcp_connection(&parent_target, parent.mark, parent.mptcp)?;
    connection
        .stream
        .set_nonblocking(false)
        .map_err(|err| format!("set parent proxy TCP blocking for chain handshake: {err}"))?;
    connection
        .stream
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set parent proxy TCP read timeout: {err}"))?;
    connection
        .stream
        .set_write_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set parent proxy TCP write timeout: {err}"))?;
    let mut stream = connection.stream;
    let child_target = format!("{}:{}", proxy.server_host, proxy.server_port);
    match &parent.handler {
        ResidentProxyProtocolPlan::Socks5Tcp { username, password } => {
            socks5_connect(&mut stream, &child_target, username, password)?;
        }
        ResidentProxyProtocolPlan::HttpProxyTcp {
            username, password, ..
        } if parent.tls == "none" => {
            http_proxy_connect(
                &mut stream,
                &child_target,
                username,
                password,
                false,
                "",
                "",
            )?;
        }
        _ => {
            return Err(format!(
                "resident chain parent {} is not backed by a plain parent CONNECT executor",
                parent.protocol
            ));
        }
    }
    stream
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set chained child TCP read timeout: {err}"))?;
    stream
        .set_write_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set chained child TCP write timeout: {err}"))?;
    Ok(stream)
}

fn read_http_head_and_leftover_from_stream(
    stream: &mut impl Read,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 256];
    loop {
        let n = stream
            .read(&mut buf)
            .map_err(|err| format!("read http head: {err}"))?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if let Some(index) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            let leftover = response[index + 4..].to_vec();
            response.truncate(index + 4);
            return Ok((response, leftover));
        }
        if response.len() > 8192 {
            return Err("http response header too large".to_owned());
        }
    }
    Err("incomplete http response header".to_owned())
}

fn validate_simple_obfs_http_response_status(response_head: &[u8]) -> Result<(), String> {
    if validate_http_status(response_head, 200).is_ok()
        || validate_http_status(response_head, 101).is_ok()
    {
        return Ok(());
    }
    validate_http_status(response_head, 200).map_err(|err| err.to_string())
}

fn read_simple_obfs_tls_response_payload_from_stream(
    stream: &mut impl Read,
) -> Result<Vec<u8>, String> {
    let mut discard = vec![0_u8; 105];
    stream
        .read_exact(&mut discard)
        .map_err(|err| format!("read simple-obfs TLS response prefix: {err}"))?;
    let mut len = [0_u8; 2];
    stream
        .read_exact(&mut len)
        .map_err(|err| format!("read simple-obfs TLS response payload length: {err}"))?;
    let payload_len = u16::from_be_bytes(len) as usize;
    let mut payload = vec![0_u8; payload_len];
    stream
        .read_exact(&mut payload)
        .map_err(|err| format!("read simple-obfs TLS response payload: {err}"))?;
    Ok(payload)
}

fn simple_obfs_tls_application_data_frame(payload: &[u8]) -> Result<Vec<u8>, String> {
    let len = u16::try_from(payload.len()).map_err(|_| {
        format!(
            "simple-obfs TLS application data too large: {}",
            payload.len()
        )
    })?;
    let mut out = Vec::with_capacity(5 + payload.len());
    out.extend_from_slice(&[0x17, 0x03, 0x03]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

struct PrefixTcpReader<'a> {
    prefix: VecDeque<u8>,
    stream: &'a mut TcpStream,
}

impl<'a> PrefixTcpReader<'a> {
    fn new(prefix: Vec<u8>, stream: &'a mut TcpStream) -> Self {
        Self {
            prefix: VecDeque::from(prefix),
            stream,
        }
    }

    fn shutdown_write(&mut self) -> std::io::Result<()> {
        self.stream.shutdown(Shutdown::Write)
    }
}

impl Read for PrefixTcpReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut written = 0;
        while written < buf.len() {
            let Some(byte) = self.prefix.pop_front() else {
                break;
            };
            buf[written] = byte;
            written += 1;
        }
        if written > 0 {
            return Ok(written);
        }
        self.stream.read(buf)
    }
}

struct SimpleObfsTlsAppDataReader<'a> {
    prefix: VecDeque<u8>,
    frame: VecDeque<u8>,
    stream: &'a mut TcpStream,
}

impl<'a> SimpleObfsTlsAppDataReader<'a> {
    fn new(prefix: Vec<u8>, stream: &'a mut TcpStream) -> Self {
        Self {
            prefix: VecDeque::from(prefix),
            frame: VecDeque::new(),
            stream,
        }
    }

    fn shutdown_write(&mut self) -> std::io::Result<()> {
        self.stream.shutdown(Shutdown::Write)
    }

    fn fill_frame(&mut self) -> std::io::Result<()> {
        let mut header = [0_u8; 5];
        self.stream.read_exact(&mut header)?;
        if header[..3] != [0x17, 0x03, 0x03] {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "simple-obfs TLS application data header mismatch: {:02x?}",
                    &header[..3]
                ),
            ));
        }
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if len > 16 * 1024 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("simple-obfs TLS application data too large: {len}"),
            ));
        }
        let mut payload = vec![0_u8; len];
        self.stream.read_exact(&mut payload)?;
        self.frame = VecDeque::from(payload);
        Ok(())
    }
}

impl Read for SimpleObfsTlsAppDataReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut written = 0;
        while written < buf.len() {
            if let Some(byte) = self.prefix.pop_front() {
                buf[written] = byte;
                written += 1;
                continue;
            }
            if let Some(byte) = self.frame.pop_front() {
                buf[written] = byte;
                written += 1;
                continue;
            }
            if written > 0 {
                return Ok(written);
            }
            self.fill_frame()?;
        }
        Ok(written)
    }
}

fn socks5_connect(
    stream: &mut TcpStream,
    target: &str,
    username: &str,
    password: &str,
) -> Result<(), String> {
    stream
        .write_all(&handshake::greeting(username, password))
        .map_err(|err| format!("write SOCKS5 greeting: {err}"))?;
    let mut method_selection = [0_u8; 2];
    stream
        .read_exact(&mut method_selection)
        .map_err(|err| format!("read SOCKS5 method selection: {err}"))?;
    let method = handshake::parse_method_selection(&method_selection)
        .map_err(|err| format!("parse SOCKS5 method selection: {err}"))?;
    if method == handshake::AUTH_PASSWORD {
        let auth = handshake::username_password_auth(username, password)
            .map_err(|err| format!("build SOCKS5 auth: {err}"))?;
        stream
            .write_all(&auth)
            .map_err(|err| format!("write SOCKS5 auth: {err}"))?;
        let mut auth_reply = [0_u8; 2];
        stream
            .read_exact(&mut auth_reply)
            .map_err(|err| format!("read SOCKS5 auth reply: {err}"))?;
        if auth_reply[0] != handshake::PASSWORD_AUTH_VERSION || auth_reply[1] != 0 {
            return Err(format!("SOCKS5 auth rejected: {:02x?}", auth_reply));
        }
    }
    let target =
        Socks5Address::parse(target).map_err(|err| format!("parse SOCKS5 target: {err}"))?;
    let request = handshake::request(handshake::Socks5Command::Connect, &target)
        .map_err(|err| format!("build SOCKS5 CONNECT: {err}"))?;
    stream
        .write_all(&request)
        .map_err(|err| format!("write SOCKS5 CONNECT: {err}"))?;
    let mut reply_head = [0_u8; 3];
    stream
        .read_exact(&mut reply_head)
        .map_err(|err| format!("read SOCKS5 CONNECT reply: {err}"))?;
    let mut reply = reply_head.to_vec();
    reply.extend(read_socks5_address_bytes(stream).map_err(|err| err.to_string())?);
    handshake::parse_server_reply(&reply)
        .map_err(|err| format!("parse SOCKS5 CONNECT reply: {err}"))?;
    Ok(())
}

fn http_proxy_connect(
    stream: &mut TcpStream,
    target: &str,
    username: &str,
    password: &str,
    transport: bool,
    transport_host: &str,
    transport_path: &str,
) -> Result<(), String> {
    let mut options = HttpConnectOptions::connect(target);
    options.username = username.to_owned();
    options.password = password.to_owned();
    options.transport.enabled = transport;
    options.host_override = transport_host.to_owned();
    options.transport.path = transport_path.to_owned();
    let request = http_request::connect_request(&options);
    stream
        .write_all(&request)
        .map_err(|err| format!("write HTTP CONNECT request: {err}"))?;
    let mut response = Vec::new();
    let mut buf = [0_u8; 512];
    loop {
        let read = stream
            .read(&mut buf)
            .map_err(|err| format!("read HTTP CONNECT response: {err}"))?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buf[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if response.len() > 8192 {
            return Err("HTTP CONNECT response too large".to_owned());
        }
    }
    let status = http_request::parse_connect_response(&response)
        .map_err(|err| format!("parse HTTP CONNECT response: {err}"))?;
    if status != 200 {
        return Err(format!("HTTP CONNECT status: {status}"));
    }
    Ok(())
}

fn read_socks5_address_bytes(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut atyp = [0_u8; 1];
    stream.read_exact(&mut atyp)?;
    let mut out = atyp.to_vec();
    match atyp[0] {
        1 => {
            let mut rest = [0_u8; 6];
            stream.read_exact(&mut rest)?;
            out.extend_from_slice(&rest);
        }
        3 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len)?;
            out.extend_from_slice(&len);
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream.read_exact(&mut rest)?;
            out.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0_u8; 18];
            stream.read_exact(&mut rest)?;
            out.extend_from_slice(&rest);
        }
        _ => {}
    }
    Ok(out)
}
