use super::*;

#[derive(Clone, Copy, Debug)]
pub(in crate::daed_product) struct HttpRequestReadPolicy {
    pub(in crate::daed_product) header_timeout: Duration,
    pub(in crate::daed_product) header_rate_grace: Duration,
    pub(in crate::daed_product) header_min_bytes_per_second: usize,
    pub(in crate::daed_product) body_idle_timeout: Duration,
    pub(in crate::daed_product) body_timeout: Duration,
    pub(in crate::daed_product) bundle_body_timeout: Duration,
}

impl HttpRequestReadPolicy {
    pub(in crate::daed_product) const fn production() -> Self {
        Self {
            header_timeout: PRODUCT_HTTP_HEADER_READ_TIMEOUT,
            header_rate_grace: PRODUCT_HTTP_HEADER_RATE_GRACE,
            header_min_bytes_per_second: PRODUCT_HTTP_HEADER_MIN_BYTES_PER_SECOND,
            body_idle_timeout: PRODUCT_HTTP_BODY_READ_IDLE_TIMEOUT,
            body_timeout: PRODUCT_HTTP_BODY_READ_TIMEOUT,
            bundle_body_timeout: PRODUCT_HTTP_BUNDLE_BODY_READ_TIMEOUT,
        }
    }

    pub(in crate::daed_product) fn header_deadline(
        self,
        started_at: Instant,
        received: usize,
    ) -> Instant {
        let absolute = started_at
            .checked_add(self.header_timeout)
            .unwrap_or(started_at);
        if self.header_min_bytes_per_second == 0 {
            return absolute;
        }
        let rate_millis = received
            .saturating_mul(1_000)
            .checked_div(self.header_min_bytes_per_second)
            .unwrap_or(0);
        let rate_budget = self.header_rate_grace.saturating_add(Duration::from_millis(
            u64::try_from(rate_millis).unwrap_or(u64::MAX),
        ));
        let rate_deadline = started_at.checked_add(rate_budget).unwrap_or(absolute);
        absolute.min(rate_deadline)
    }

    pub(in crate::daed_product) fn body_timeout_for(
        self,
        method: &str,
        raw_path: &str,
    ) -> Duration {
        if is_bundle_import_request(method, raw_path) {
            self.bundle_body_timeout
        } else {
            self.body_timeout
        }
    }
}

pub(in crate::daed_product) fn is_bundle_import_request(method: &str, raw_path: &str) -> bool {
    let path = raw_path
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(raw_path);
    method == "PUT" && path == DAE_BUNDLE_IMPORT_PATH
}

pub(in crate::daed_product) fn socket_timeout_until(
    deadline: Instant,
    timeout_message: &'static str,
) -> io::Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(io::ErrorKind::TimedOut, timeout_message));
    }
    Ok(remaining.max(Duration::from_millis(1)))
}

pub(in crate::daed_product) fn is_socket_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}
