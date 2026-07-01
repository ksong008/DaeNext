use super::*;
pub(in crate::production_runtime_owner::resident_dataplane) async fn open_plain_proxy_tcp_stream_async(
    selection: &TcpProxySelection,
) -> Result<TokioTcpStream, String> {
    let proxy = selection.proxy.as_ref();
    if let Some(parent) = proxy.chain_parent.as_deref() {
        return open_plain_proxy_tcp_stream_through_parent_async(proxy, parent).await;
    }
    let target = format!("{}:{}", proxy.server_host, proxy.server_port);
    let connection =
        open_direct_tcp_connection_async(target, selection.mark, selection.mptcp).await?;
    TokioTcpStream::from_std(connection.stream)
        .map_err(|err| format!("adopt async proxy TCP stream: {err}"))
}

pub(super) async fn open_plain_proxy_tcp_stream_through_parent_async(
    proxy: &ResidentProxyPlan,
    parent: &ResidentProxyPlan,
) -> Result<TokioTcpStream, String> {
    let mut parent_chain = Vec::new();
    let mut current = Some(parent);
    while let Some(parent) = current {
        parent_chain.push(parent);
        current = parent.chain_parent.as_deref();
    }
    let first_parent = parent_chain
        .first()
        .ok_or_else(|| "resident chain has no parent".to_owned())?;
    let parent_target = format!("{}:{}", first_parent.server_host, first_parent.server_port);
    let connection =
        open_direct_tcp_connection_async(parent_target, first_parent.mark, first_parent.mptcp)
            .await?;
    let mut stream = TokioTcpStream::from_std(connection.stream)
        .map_err(|err| format!("adopt async parent proxy TCP stream: {err}"))?;
    for window in parent_chain.windows(2) {
        let current_parent = window[0];
        let next_parent = window[1];
        let next_target = format!("{}:{}", next_parent.server_host, next_parent.server_port);
        connect_plain_parent_to_target_async(&mut stream, current_parent, &next_target).await?;
    }
    let final_parent = parent_chain
        .last()
        .ok_or_else(|| "resident chain has no final parent".to_owned())?;
    let final_target = format!("{}:{}", proxy.server_host, proxy.server_port);
    connect_plain_parent_to_target_async(&mut stream, final_parent, &final_target).await?;
    Ok(stream)
}

async fn connect_plain_parent_to_target_async(
    stream: &mut TokioTcpStream,
    parent: &ResidentProxyPlan,
    target: &str,
) -> Result<(), String> {
    match &parent.handler {
        ResidentProxyProtocolPlan::Socks5Tcp { username, password } => {
            socks5_connect_async(stream, target, username, password).await?;
        }
        ResidentProxyProtocolPlan::HttpProxyTcp {
            username, password, ..
        } if parent.tls == "none" => {
            http_proxy_connect_plain_async(stream, target, username, password, false, "", "")
                .await?;
        }
        _ => {
            return Err(format!(
                "resident chain parent {} is not backed by a plain parent CONNECT executor",
                parent.protocol
            ));
        }
    }
    Ok(())
}

pub(crate) async fn read_http_head_and_leftover_from_async_stream<S>(
    stream: &mut S,
) -> Result<(Vec<u8>, Vec<u8>), String>
where
    S: AsyncRead + Unpin,
{
    let mut response = Vec::new();
    let mut buf = [0_u8; 256];
    loop {
        let n = stream
            .read(&mut buf)
            .await
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

pub(crate) fn validate_simple_obfs_http_response_status(
    response_head: &[u8],
) -> Result<(), String> {
    if validate_http_status(response_head, 200).is_ok()
        || validate_http_status(response_head, 101).is_ok()
    {
        return Ok(());
    }
    validate_http_status(response_head, 200).map_err(|err| err.to_string())
}

pub(super) async fn read_simple_obfs_tls_response_payload_from_async_stream<S>(
    stream: &mut S,
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut discard = vec![0_u8; 105];
    stream
        .read_exact(&mut discard)
        .await
        .map_err(|err| format!("read simple-obfs TLS response prefix: {err}"))?;
    let mut len = [0_u8; 2];
    stream
        .read_exact(&mut len)
        .await
        .map_err(|err| format!("read simple-obfs TLS response payload length: {err}"))?;
    let payload_len = u16::from_be_bytes(len) as usize;
    let mut payload = vec![0_u8; payload_len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|err| format!("read simple-obfs TLS response payload: {err}"))?;
    Ok(payload)
}

pub(super) fn simple_obfs_tls_application_data_frame(payload: &[u8]) -> Result<Vec<u8>, String> {
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

pub(super) struct AsyncPrefixTcpReader<'a, S> {
    pub(super) prefix: CursorBytes,
    pub(super) stream: &'a mut S,
}

impl<'a, S> AsyncPrefixTcpReader<'a, S> {
    pub(super) fn new(prefix: Vec<u8>, stream: &'a mut S) -> Self {
        Self {
            prefix: CursorBytes::new(prefix),
            stream,
        }
    }
}

impl<S> AsyncRead for AsyncPrefixTcpReader<'_, S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.prefix.drain_to_read_buf(buf);
        if buf.remaining() == 0 || !self.prefix.is_empty() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut *self.stream).poll_read(cx, buf)
    }
}

pub(super) struct AsyncSimpleObfsTlsAppDataReader<'a, S> {
    pub(super) prefix: CursorBytes,
    pub(super) frame: CursorBytes,
    pub(super) state: AsyncSimpleObfsTlsReadState,
    pub(super) stream: &'a mut S,
}

pub(super) enum AsyncSimpleObfsTlsReadState {
    Header { buf: [u8; 5], filled: usize },
    Payload { buf: Vec<u8>, filled: usize },
}

impl Default for AsyncSimpleObfsTlsReadState {
    fn default() -> Self {
        Self::Header {
            buf: [0_u8; 5],
            filled: 0,
        }
    }
}

impl<'a, S> AsyncSimpleObfsTlsAppDataReader<'a, S> {
    pub(super) fn new(prefix: Vec<u8>, stream: &'a mut S) -> Self {
        Self {
            prefix: CursorBytes::new(prefix),
            frame: CursorBytes::default(),
            state: AsyncSimpleObfsTlsReadState::default(),
            stream,
        }
    }
}

impl<S> AsyncRead for AsyncSimpleObfsTlsAppDataReader<'_, S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let initial_filled = out.filled().len();
        loop {
            self.prefix.drain_to_read_buf(out);
            if out.remaining() > 0 {
                self.frame.drain_to_read_buf(out);
            }
            if out.filled().len() > initial_filled || out.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            let state = std::mem::take(&mut self.state);
            match state {
                AsyncSimpleObfsTlsReadState::Header {
                    mut buf,
                    mut filled,
                } => {
                    while filled < buf.len() {
                        let before = filled;
                        let mut read_buf = ReadBuf::new(&mut buf[filled..]);
                        match Pin::new(&mut *self.stream).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let read = read_buf.filled().len();
                                if read == 0 {
                                    if before == 0 {
                                        return Poll::Ready(Ok(()));
                                    }
                                    return Poll::Ready(Err(std::io::Error::new(
                                        ErrorKind::UnexpectedEof,
                                        "simple-obfs TLS application data header eof",
                                    )));
                                }
                                filled += read;
                            }
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                            Poll::Pending => {
                                self.state = AsyncSimpleObfsTlsReadState::Header { buf, filled };
                                return Poll::Pending;
                            }
                        }
                    }
                    if buf[..3] != [0x17, 0x03, 0x03] {
                        return Poll::Ready(Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            format!(
                                "simple-obfs TLS application data header mismatch: {:02x?}",
                                &buf[..3]
                            ),
                        )));
                    }
                    let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
                    if len > 16 * 1024 {
                        return Poll::Ready(Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            format!("simple-obfs TLS application data too large: {len}"),
                        )));
                    }
                    self.state = AsyncSimpleObfsTlsReadState::Payload {
                        buf: vec![0_u8; len],
                        filled: 0,
                    };
                }
                AsyncSimpleObfsTlsReadState::Payload {
                    mut buf,
                    mut filled,
                } => {
                    while filled < buf.len() {
                        let mut read_buf = ReadBuf::new(&mut buf[filled..]);
                        match Pin::new(&mut *self.stream).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let read = read_buf.filled().len();
                                if read == 0 {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        ErrorKind::UnexpectedEof,
                                        "simple-obfs TLS application data payload eof",
                                    )));
                                }
                                filled += read;
                            }
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                            Poll::Pending => {
                                self.state = AsyncSimpleObfsTlsReadState::Payload { buf, filled };
                                return Poll::Pending;
                            }
                        }
                    }
                    self.frame = CursorBytes::new(buf);
                    self.state = AsyncSimpleObfsTlsReadState::default();
                }
            }
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct CursorBytes {
    bytes: Vec<u8>,
    offset: usize,
}

impl CursorBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset >= self.bytes.len()
    }

    fn drain_to_read_buf(&mut self, out: &mut ReadBuf<'_>) -> bool {
        if self.is_empty() || out.remaining() == 0 {
            return false;
        }
        let available = &self.bytes[self.offset..];
        let len = available.len().min(out.remaining());
        out.put_slice(&available[..len]);
        self.offset += len;
        if self.offset >= self.bytes.len() {
            self.bytes.clear();
            self.offset = 0;
        }
        true
    }
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn socks5_connect_async(
    stream: &mut TokioTcpStream,
    target: &str,
    username: &str,
    password: &str,
) -> Result<(), String> {
    time::timeout(RESIDENT_CONNECT_TIMEOUT, async {
        stream
            .write_all(&handshake::greeting(username, password))
            .await
            .map_err(|err| format!("write SOCKS5 greeting: {err}"))?;
        let mut method_selection = [0_u8; 2];
        stream
            .read_exact(&mut method_selection)
            .await
            .map_err(|err| format!("read SOCKS5 method selection: {err}"))?;
        let method = handshake::parse_method_selection(&method_selection)
            .map_err(|err| format!("parse SOCKS5 method selection: {err}"))?;
        if method == handshake::AUTH_PASSWORD {
            let auth = handshake::username_password_auth(username, password)
                .map_err(|err| format!("build SOCKS5 auth: {err}"))?;
            stream
                .write_all(&auth)
                .await
                .map_err(|err| format!("write SOCKS5 auth: {err}"))?;
            let mut auth_reply = [0_u8; 2];
            stream
                .read_exact(&mut auth_reply)
                .await
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
            .await
            .map_err(|err| format!("write SOCKS5 CONNECT: {err}"))?;
        let mut reply_head = [0_u8; 3];
        stream
            .read_exact(&mut reply_head)
            .await
            .map_err(|err| format!("read SOCKS5 CONNECT reply: {err}"))?;
        let mut reply = reply_head.to_vec();
        reply.extend(
            read_socks5_address_bytes_async(stream)
                .await
                .map_err(|err| err.to_string())?,
        );
        handshake::parse_server_reply(&reply)
            .map_err(|err| format!("parse SOCKS5 CONNECT reply: {err}"))?;
        Ok(())
    })
    .await
    .map_err(|_| "SOCKS5 CONNECT timeout".to_owned())?
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn http_proxy_connect_plain_async(
    stream: &mut TokioTcpStream,
    target: &str,
    username: &str,
    password: &str,
    transport: bool,
    transport_host: &str,
    transport_path: &str,
) -> Result<(), String> {
    time::timeout(RESIDENT_CONNECT_TIMEOUT, async {
        let mut options = HttpConnectOptions::connect(target);
        options.username = username.to_owned();
        options.password = password.to_owned();
        options.transport.enabled = transport;
        options.host_override = transport_host.to_owned();
        options.transport.path = transport_path.to_owned();
        let request = http_request::connect_request(&options);
        stream
            .write_all(&request)
            .await
            .map_err(|err| format!("write HTTP CONNECT request: {err}"))?;
        let mut response = Vec::new();
        let mut buf = [0_u8; 512];
        loop {
            let read = stream
                .read(&mut buf)
                .await
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
    })
    .await
    .map_err(|_| "HTTP CONNECT timeout".to_owned())?
}

pub(super) async fn read_socks5_address_bytes_async(
    stream: &mut TokioTcpStream,
) -> std::io::Result<Vec<u8>> {
    let mut atyp = [0_u8; 1];
    stream.read_exact(&mut atyp).await?;
    let mut out = atyp.to_vec();
    match atyp[0] {
        1 => {
            let mut rest = [0_u8; 6];
            stream.read_exact(&mut rest).await?;
            out.extend_from_slice(&rest);
        }
        3 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            out.extend_from_slice(&len);
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream.read_exact(&mut rest).await?;
            out.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0_u8; 18];
            stream.read_exact(&mut rest).await?;
            out.extend_from_slice(&rest);
        }
        _ => {}
    }
    Ok(out)
}
