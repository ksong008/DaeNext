use super::*;
use tokio::io::AsyncWriteExt;

pub(super) async fn wait_sse_peer_closed(stream: &tokio::net::TcpStream) -> io::Result<()> {
    loop {
        stream.readable().await?;
        let mut byte = [0_u8; 1];
        match stream.try_read(&mut byte) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSE connection received unexpected client data",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
    }
}

pub(super) async fn write_sse_headers(
    stream: &mut tokio::net::TcpStream,
    request: &HttpRequest,
) -> io::Result<()> {
    let mut headers = String::from(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nX-Accel-Buffering: no\r\n",
    );
    if let Some(origin) = allowed_cors_origin(request) {
        headers.push_str(&format!(
            "Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\nAccess-Control-Allow-Headers: Authorization, Content-Type, X-Daed-Page-Id\r\nAccess-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD\r\nAccess-Control-Max-Age: 300\r\n"
        ));
    }
    headers.push_str("\r\n");
    write_sse_bytes(stream, headers.as_bytes()).await
}

pub(super) async fn write_sse_serialized_runtime_delta(
    stream: &mut tokio::net::TcpStream,
    payload: &[u8],
) -> io::Result<()> {
    tokio::time::timeout(PRODUCT_HTTP_SSE_WRITE_TIMEOUT, async {
        stream
            .write_all(b"event: runtime.overview.delta\ndata: ")
            .await?;
        stream.write_all(payload).await?;
        stream.write_all(b"\n\n").await?;
        stream.flush().await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SSE write timed out"))?
}

pub(super) async fn write_sse_retry(stream: &mut tokio::net::TcpStream) -> io::Result<()> {
    write_sse_bytes(
        stream,
        format!("retry: {LOG_STREAM_RETRY_MS}\n\n").as_bytes(),
    )
    .await
}

pub(super) async fn write_sse_event(
    stream: &mut tokio::net::TcpStream,
    event: &str,
    payload: &Value,
) -> io::Result<()> {
    let data = serde_json::to_string(payload)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut frame = format!("event: {event}\n");
    for line in data.lines() {
        frame.push_str("data: ");
        frame.push_str(line);
        frame.push('\n');
    }
    frame.push('\n');
    write_sse_bytes(stream, frame.as_bytes()).await
}

pub(super) async fn write_sse_heartbeat(stream: &mut tokio::net::TcpStream) -> io::Result<()> {
    write_sse_bytes(stream, b": heartbeat\n\n").await
}

async fn write_sse_bytes(stream: &mut tokio::net::TcpStream, bytes: &[u8]) -> io::Result<()> {
    tokio::time::timeout(PRODUCT_HTTP_SSE_WRITE_TIMEOUT, stream.write_all(bytes))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SSE write timed out"))??;
    tokio::time::timeout(PRODUCT_HTTP_SSE_WRITE_TIMEOUT, stream.flush())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SSE flush timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let connect = tokio::spawn(tokio::net::TcpStream::connect(address));
        let (server, _) = listener.accept().await.unwrap();
        let client = connect.await.unwrap().unwrap();
        (server, client)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn peer_close_observer_detects_read_half_eof() {
        let (server, client) = tcp_pair().await;
        drop(client);
        tokio::time::timeout(Duration::from_secs(1), wait_sse_peer_closed(&server))
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn peer_close_observer_rejects_client_payload() {
        use tokio::io::AsyncWriteExt as _;

        let (server, mut client) = tcp_pair().await;
        client.write_all(b"x").await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), wait_sse_peer_closed(&server))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
