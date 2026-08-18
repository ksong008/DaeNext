use super::*;

const VMESS_HTTP_HEADER_LIMIT: usize = 8 * 1024;

pub struct VmessHttpHeaderStream<S> {
    inner: S,
    response_head: Vec<u8>,
    buffered_payload: VecDeque<u8>,
    response_head_received: bool,
}

pub async fn open_vmess_http_header_stream<S>(
    mut inner: S,
    host: &str,
    path: &str,
) -> Result<VmessHttpHeaderStream<S>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = vmess_http_header_request(host, path);
    inner
        .write_all(&request)
        .await
        .map_err(|error| format!("write VMess TCP HTTP header: {error}"))?;
    inner
        .flush()
        .await
        .map_err(|error| format!("flush VMess TCP HTTP header: {error}"))?;
    Ok(VmessHttpHeaderStream {
        inner,
        response_head: Vec::new(),
        buffered_payload: VecDeque::new(),
        response_head_received: false,
    })
}

fn vmess_http_header_request(host: &str, path: &str) -> Vec<u8> {
    let path = if path.is_empty() {
        "/"
    } else if path.starts_with('/') {
        path
    } else {
        return format!("GET /{path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n")
            .into_bytes();
    };
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n").into_bytes()
}

impl<S> AsyncRead for VmessHttpHeaderStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.buffered_payload.is_empty() {
            let copied = self.buffered_payload.len().min(output.remaining());
            for byte in self.buffered_payload.drain(..copied) {
                output.put_slice(&[byte]);
            }
            return Poll::Ready(Ok(()));
        }
        if self.response_head_received {
            return Pin::new(&mut self.inner).poll_read(cx, output);
        }
        loop {
            let mut incoming = [0_u8; 2048];
            let mut incoming_buf = ReadBuf::new(&mut incoming);
            match Pin::new(&mut self.inner).poll_read(cx, &mut incoming_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if incoming_buf.filled().is_empty() => {
                    return Poll::Ready(Err(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "VMess TCP HTTP header stream closed before response head",
                    )));
                }
                Poll::Ready(Ok(())) => {}
            }
            self.response_head.extend_from_slice(incoming_buf.filled());
            if self.response_head.len() > VMESS_HTTP_HEADER_LIMIT {
                return Poll::Ready(Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "VMess TCP HTTP response head exceeded 8192 bytes",
                )));
            }
            let Some(end) = self
                .response_head
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|offset| offset + 4)
            else {
                continue;
            };
            if !self.response_head.starts_with(b"HTTP/1.") {
                return Poll::Ready(Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "VMess TCP HTTP camouflage returned a non-HTTP/1 response",
                )));
            }
            let payload = self.response_head.split_off(end);
            self.response_head.clear();
            self.response_head_received = true;
            if payload.is_empty() {
                return Pin::new(&mut self.inner).poll_read(cx, output);
            }
            let copied = payload.len().min(output.remaining());
            output.put_slice(&payload[..copied]);
            if copied < payload.len() {
                self.buffered_payload.extend(&payload[copied..]);
            }
            return Poll::Ready(Ok(()));
        }
    }
}

impl<S> AsyncWrite for VmessHttpHeaderStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_normalizes_path_without_changing_host() {
        assert_eq!(
            vmess_http_header_request("header.fixture.invalid", "resource"),
            b"GET /resource HTTP/1.1\r\nHost: header.fixture.invalid\r\nConnection: keep-alive\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn response_head_is_removed_without_losing_coalesced_payload() {
        let (client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                server.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            assert!(request.starts_with(b"GET /vmess HTTP/1.1\r\n"));
            server
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\nvmess-payload")
                .await
                .unwrap();
        });
        let mut stream = open_vmess_http_header_stream(client, "header.fixture.invalid", "/vmess")
            .await
            .unwrap();
        let mut payload = [0_u8; 13];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"vmess-payload");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn response_head_without_coalesced_payload_waits_for_body() {
        let (client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                server.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            server
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n")
                .await
                .unwrap();
            server.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            server.write_all(b"vmess-payload").await.unwrap();
        });
        let mut stream = open_vmess_http_header_stream(client, "header.fixture.invalid", "/vmess")
            .await
            .unwrap();
        let mut payload = [0_u8; 13];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"vmess-payload");
        server_task.await.unwrap();
    }
}
