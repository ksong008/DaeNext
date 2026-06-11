use super::*;
pub(crate) fn is_graceful_shadowsocks_response_message(message: &str) -> bool {
    message.contains("early eof")
        || message.contains("failed to fill whole buffer")
        || message.contains("Connection reset")
        || message.contains("connection reset")
        || message.contains("timed out")
        || message.contains("broken pipe")
        || message.contains("close_notify")
}

pub(crate) fn is_graceful_vmess_response_message(message: &str) -> bool {
    message.contains("early eof")
        || message.contains("failed to fill whole buffer")
        || message.contains("Connection reset")
        || message.contains("connection reset")
        || message.contains("timed out")
        || message.contains("unexpected EOF")
        || message.contains("peer closed connection")
}

pub(crate) fn is_graceful_stream_close_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected
    )
}

pub(crate) fn is_graceful_stream_close_message(message: &str) -> bool {
    message.contains("Broken pipe")
        || message.contains("Connection reset")
        || message.contains("Connection aborted")
        || message.contains("Not connected")
        || message.contains("broken pipe")
        || message.contains("connection reset")
        || message.contains("connection aborted")
        || message.contains("not connected")
}

pub(crate) fn is_graceful_tls_plain_close_error(err: &std::io::Error) -> bool {
    if is_graceful_stream_close_error(err) {
        return true;
    }
    let message = err.to_string();
    is_graceful_stream_close_message(&message)
        || message.contains("peer closed connection without sending TLS close_notify")
        || message.contains("without sending TLS close_notify")
}
