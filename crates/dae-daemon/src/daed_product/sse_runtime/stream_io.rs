use super::*;
use tokio::io::AsyncWriteExt;

pub(super) async fn write_sse_headers(
    stream: &mut tokio::net::TcpStream,
    request: &HttpRequest,
) -> io::Result<()> {
    let mut headers = String::from(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nX-Accel-Buffering: no\r\n",
    );
    if let Some(origin) = allowed_cors_origin(request) {
        headers.push_str(&format!(
            "Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\nAccess-Control-Allow-Headers: Authorization, Content-Type\r\nAccess-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD\r\nAccess-Control-Max-Age: 300\r\n"
        ));
    }
    headers.push_str("\r\n");
    write_sse_bytes(stream, headers.as_bytes()).await
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
