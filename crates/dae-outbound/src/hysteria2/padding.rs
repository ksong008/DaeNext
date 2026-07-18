use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const PADDING_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

pub const HYSTERIA2_AUTH_PADDING_MIN: usize = 256;
pub const HYSTERIA2_AUTH_PADDING_MAX_EXCLUSIVE: usize = 2_048;
pub const HYSTERIA2_TCP_REQUEST_PADDING_MIN: usize = 64;
pub const HYSTERIA2_TCP_REQUEST_PADDING_MAX_EXCLUSIVE: usize = 512;

static AUTH_PADDING_SAMPLES: AtomicU64 = AtomicU64::new(0);
static AUTH_PADDING_BYTES: AtomicU64 = AtomicU64::new(0);
static AUTH_PADDING_MIN_OBSERVED: AtomicUsize = AtomicUsize::new(usize::MAX);
static AUTH_PADDING_MAX_OBSERVED: AtomicUsize = AtomicUsize::new(0);
static TCP_PADDING_SAMPLES: AtomicU64 = AtomicU64::new(0);
static TCP_PADDING_BYTES: AtomicU64 = AtomicU64::new(0);
static TCP_PADDING_MIN_OBSERVED: AtomicUsize = AtomicUsize::new(usize::MAX);
static TCP_PADDING_MAX_OBSERVED: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hysteria2PaddingMetricsSnapshot {
    pub auth_samples: u64,
    pub auth_bytes: u64,
    pub auth_min_observed: Option<usize>,
    pub auth_max_observed: Option<usize>,
    pub tcp_request_samples: u64,
    pub tcp_request_bytes: u64,
    pub tcp_request_min_observed: Option<usize>,
    pub tcp_request_max_observed: Option<usize>,
}

pub fn hysteria2_padding_metrics_snapshot() -> Hysteria2PaddingMetricsSnapshot {
    Hysteria2PaddingMetricsSnapshot {
        auth_samples: AUTH_PADDING_SAMPLES.load(Ordering::Relaxed),
        auth_bytes: AUTH_PADDING_BYTES.load(Ordering::Relaxed),
        auth_min_observed: observed_min(&AUTH_PADDING_MIN_OBSERVED),
        auth_max_observed: observed_max(&AUTH_PADDING_MAX_OBSERVED),
        tcp_request_samples: TCP_PADDING_SAMPLES.load(Ordering::Relaxed),
        tcp_request_bytes: TCP_PADDING_BYTES.load(Ordering::Relaxed),
        tcp_request_min_observed: observed_min(&TCP_PADDING_MIN_OBSERVED),
        tcp_request_max_observed: observed_max(&TCP_PADDING_MAX_OBSERVED),
    }
}

pub(super) fn auth_request_padding() -> String {
    let padding = random_padding(
        HYSTERIA2_AUTH_PADDING_MIN,
        HYSTERIA2_AUTH_PADDING_MAX_EXCLUSIVE,
    );
    record_padding(
        padding.len(),
        &AUTH_PADDING_SAMPLES,
        &AUTH_PADDING_BYTES,
        &AUTH_PADDING_MIN_OBSERVED,
        &AUTH_PADDING_MAX_OBSERVED,
    );
    String::from_utf8(padding).expect("Hysteria2 padding alphabet is ASCII")
}

pub(super) fn tcp_request_padding() -> Vec<u8> {
    let padding = random_padding(
        HYSTERIA2_TCP_REQUEST_PADDING_MIN,
        HYSTERIA2_TCP_REQUEST_PADDING_MAX_EXCLUSIVE,
    );
    record_padding(
        padding.len(),
        &TCP_PADDING_SAMPLES,
        &TCP_PADDING_BYTES,
        &TCP_PADDING_MIN_OBSERVED,
        &TCP_PADDING_MAX_OBSERVED,
    );
    padding
}

fn random_padding(minimum: usize, maximum_exclusive: usize) -> Vec<u8> {
    let length = fastrand::usize(minimum..maximum_exclusive);
    let mut padding = Vec::with_capacity(length);
    for _ in 0..length {
        padding.push(PADDING_ALPHABET[fastrand::usize(..PADDING_ALPHABET.len())]);
    }
    padding
}

fn record_padding(
    length: usize,
    samples: &AtomicU64,
    bytes: &AtomicU64,
    minimum: &AtomicUsize,
    maximum: &AtomicUsize,
) {
    samples.fetch_add(1, Ordering::Relaxed);
    bytes.fetch_add(u64::try_from(length).unwrap_or(u64::MAX), Ordering::Relaxed);
    let _ = minimum.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.min(length))
    });
    let _ = maximum.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.max(length))
    });
}

fn observed_min(value: &AtomicUsize) -> Option<usize> {
    let value = value.load(Ordering::Relaxed);
    (value != usize::MAX).then_some(value)
}

fn observed_max(value: &AtomicUsize) -> Option<usize> {
    let value = value.load(Ordering::Relaxed);
    (value > 0).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_and_tcp_padding_are_randomized_inside_official_half_open_ranges() {
        let auth = (0..128).map(|_| auth_request_padding()).collect::<Vec<_>>();
        let tcp = (0..128).map(|_| tcp_request_padding()).collect::<Vec<_>>();

        assert!(auth.iter().all(|padding| {
            (HYSTERIA2_AUTH_PADDING_MIN..HYSTERIA2_AUTH_PADDING_MAX_EXCLUSIVE)
                .contains(&padding.len())
                && padding.bytes().all(|byte| PADDING_ALPHABET.contains(&byte))
        }));
        assert!(tcp.iter().all(|padding| {
            (HYSTERIA2_TCP_REQUEST_PADDING_MIN..HYSTERIA2_TCP_REQUEST_PADDING_MAX_EXCLUSIVE)
                .contains(&padding.len())
                && padding.iter().all(|byte| PADDING_ALPHABET.contains(byte))
        }));
        assert!(auth.windows(2).any(|pair| pair[0] != pair[1]));
        assert!(tcp.windows(2).any(|pair| pair[0] != pair[1]));

        let snapshot = hysteria2_padding_metrics_snapshot();
        assert!(snapshot.auth_samples >= 128);
        assert!(snapshot.tcp_request_samples >= 128);
        assert!(snapshot.auth_min_observed.unwrap() >= HYSTERIA2_AUTH_PADDING_MIN);
        assert!(snapshot.auth_max_observed.unwrap() < HYSTERIA2_AUTH_PADDING_MAX_EXCLUSIVE);
        assert!(snapshot.tcp_request_min_observed.unwrap() >= HYSTERIA2_TCP_REQUEST_PADDING_MIN);
        assert!(
            snapshot.tcp_request_max_observed.unwrap()
                < HYSTERIA2_TCP_REQUEST_PADDING_MAX_EXCLUSIVE
        );
    }
}
