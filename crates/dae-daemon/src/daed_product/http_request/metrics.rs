use super::*;

#[derive(Debug, Default)]
pub(in crate::daed_product) struct ProductHttpRequestReadMetrics {
    idle_header_timeout_total: AtomicU64,
    partial_header_timeout_total: AtomicU64,
    body_timeout_total: AtomicU64,
    connection_closed_total: AtomicU64,
    invalid_request_total: AtomicU64,
    io_error_total: AtomicU64,
}

impl ProductHttpRequestReadMetrics {
    pub(in crate::daed_product) fn record(&self, kind: HttpRequestReadErrorKind) {
        let counter = match kind {
            HttpRequestReadErrorKind::IdleHeaderTimeout => &self.idle_header_timeout_total,
            HttpRequestReadErrorKind::PartialHeaderTimeout => &self.partial_header_timeout_total,
            HttpRequestReadErrorKind::BodyTimeout => &self.body_timeout_total,
            HttpRequestReadErrorKind::ConnectionClosed => &self.connection_closed_total,
            HttpRequestReadErrorKind::InvalidRequest => &self.invalid_request_total,
            HttpRequestReadErrorKind::Io => &self.io_error_total,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(in crate::daed_product) fn snapshot(&self) -> Value {
        json!({
            "idleHeaderTimeoutTotal": self.idle_header_timeout_total.load(Ordering::Relaxed),
            "partialHeaderTimeoutTotal": self.partial_header_timeout_total.load(Ordering::Relaxed),
            "bodyTimeoutTotal": self.body_timeout_total.load(Ordering::Relaxed),
            "connectionClosedTotal": self.connection_closed_total.load(Ordering::Relaxed),
            "invalidRequestTotal": self.invalid_request_total.load(Ordering::Relaxed),
            "ioErrorTotal": self.io_error_total.load(Ordering::Relaxed),
        })
    }
}
