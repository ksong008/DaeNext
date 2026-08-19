use super::*;

#[cfg(feature = "test-boringssl-tls-profile")]
use std::sync::LazyLock;
#[cfg(feature = "test-boringssl-tls-profile")]
use std::sync::atomic::{AtomicU64, Ordering};

const SIZE_BUCKET_UPPER_BOUNDS: [usize; 7] = [64, 256, 1024, 4096, 16_384, 65_536, usize::MAX];

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResidentBoringTlsIoProfileSnapshot {
    enabled: bool,
    ssl_read_calls: u64,
    ssl_read_bytes: u64,
    ssl_read_sizes: [u64; 7],
    ssl_write_calls: u64,
    ssl_write_bytes: u64,
    ssl_write_sizes: [u64; 7],
    bio_read_calls: u64,
    bio_read_bytes: u64,
    bio_read_sizes: [u64; 7],
    bio_write_calls: u64,
    bio_write_bytes: u64,
    bio_write_sizes: [u64; 7],
    tls_read_records: u64,
    tls_read_record_bytes: u64,
    tls_write_records: u64,
    tls_write_record_bytes: u64,
    size_bucket_upper_bounds: [usize; 7],
}

#[cfg(feature = "test-boringssl-tls-profile")]
struct ProfileCounters {
    ssl_read_calls: AtomicU64,
    ssl_read_bytes: AtomicU64,
    ssl_read_sizes: [AtomicU64; 7],
    ssl_write_calls: AtomicU64,
    ssl_write_bytes: AtomicU64,
    ssl_write_sizes: [AtomicU64; 7],
    bio_read_calls: AtomicU64,
    bio_read_bytes: AtomicU64,
    bio_read_sizes: [AtomicU64; 7],
    bio_write_calls: AtomicU64,
    bio_write_bytes: AtomicU64,
    bio_write_sizes: [AtomicU64; 7],
    tls_read_records: AtomicU64,
    tls_read_record_bytes: AtomicU64,
    tls_write_records: AtomicU64,
    tls_write_record_bytes: AtomicU64,
}

#[cfg(feature = "test-boringssl-tls-profile")]
impl ProfileCounters {
    fn new() -> Self {
        Self {
            ssl_read_calls: AtomicU64::new(0),
            ssl_read_bytes: AtomicU64::new(0),
            ssl_read_sizes: std::array::from_fn(|_| AtomicU64::new(0)),
            ssl_write_calls: AtomicU64::new(0),
            ssl_write_bytes: AtomicU64::new(0),
            ssl_write_sizes: std::array::from_fn(|_| AtomicU64::new(0)),
            bio_read_calls: AtomicU64::new(0),
            bio_read_bytes: AtomicU64::new(0),
            bio_read_sizes: std::array::from_fn(|_| AtomicU64::new(0)),
            bio_write_calls: AtomicU64::new(0),
            bio_write_bytes: AtomicU64::new(0),
            bio_write_sizes: std::array::from_fn(|_| AtomicU64::new(0)),
            tls_read_records: AtomicU64::new(0),
            tls_read_record_bytes: AtomicU64::new(0),
            tls_write_records: AtomicU64::new(0),
            tls_write_record_bytes: AtomicU64::new(0),
        }
    }

    fn take(&self) -> ResidentBoringTlsIoProfileSnapshot {
        ResidentBoringTlsIoProfileSnapshot {
            enabled: true,
            ssl_read_calls: self.ssl_read_calls.swap(0, Ordering::Relaxed),
            ssl_read_bytes: self.ssl_read_bytes.swap(0, Ordering::Relaxed),
            ssl_read_sizes: take_histogram(&self.ssl_read_sizes),
            ssl_write_calls: self.ssl_write_calls.swap(0, Ordering::Relaxed),
            ssl_write_bytes: self.ssl_write_bytes.swap(0, Ordering::Relaxed),
            ssl_write_sizes: take_histogram(&self.ssl_write_sizes),
            bio_read_calls: self.bio_read_calls.swap(0, Ordering::Relaxed),
            bio_read_bytes: self.bio_read_bytes.swap(0, Ordering::Relaxed),
            bio_read_sizes: take_histogram(&self.bio_read_sizes),
            bio_write_calls: self.bio_write_calls.swap(0, Ordering::Relaxed),
            bio_write_bytes: self.bio_write_bytes.swap(0, Ordering::Relaxed),
            bio_write_sizes: take_histogram(&self.bio_write_sizes),
            tls_read_records: self.tls_read_records.swap(0, Ordering::Relaxed),
            tls_read_record_bytes: self.tls_read_record_bytes.swap(0, Ordering::Relaxed),
            tls_write_records: self.tls_write_records.swap(0, Ordering::Relaxed),
            tls_write_record_bytes: self.tls_write_record_bytes.swap(0, Ordering::Relaxed),
            size_bucket_upper_bounds: SIZE_BUCKET_UPPER_BOUNDS,
        }
    }
}

#[cfg(feature = "test-boringssl-tls-profile")]
static PROFILE: LazyLock<ProfileCounters> = LazyLock::new(ProfileCounters::new);

#[cfg(feature = "test-boringssl-tls-profile")]
fn record_size(bytes: usize, total: &AtomicU64, histogram: &[AtomicU64; 7]) {
    total.fetch_add(bytes as u64, Ordering::Relaxed);
    let bucket = SIZE_BUCKET_UPPER_BOUNDS
        .iter()
        .position(|upper| bytes <= *upper)
        .unwrap_or(SIZE_BUCKET_UPPER_BOUNDS.len() - 1);
    histogram[bucket].fetch_add(1, Ordering::Relaxed);
}

#[cfg(feature = "test-boringssl-tls-profile")]
fn take_histogram(histogram: &[AtomicU64; 7]) -> [u64; 7] {
    std::array::from_fn(|index| histogram[index].swap(0, Ordering::Relaxed))
}

pub(super) fn record_ssl_read(bytes: Option<usize>) {
    #[cfg(feature = "test-boringssl-tls-profile")]
    {
        PROFILE.ssl_read_calls.fetch_add(1, Ordering::Relaxed);
        if let Some(bytes) = bytes {
            record_size(bytes, &PROFILE.ssl_read_bytes, &PROFILE.ssl_read_sizes);
        }
    }
    #[cfg(not(feature = "test-boringssl-tls-profile"))]
    let _ = bytes;
}

pub(super) fn record_ssl_write(bytes: Option<usize>) {
    #[cfg(feature = "test-boringssl-tls-profile")]
    {
        PROFILE.ssl_write_calls.fetch_add(1, Ordering::Relaxed);
        if let Some(bytes) = bytes {
            record_size(bytes, &PROFILE.ssl_write_bytes, &PROFILE.ssl_write_sizes);
        }
    }
    #[cfg(not(feature = "test-boringssl-tls-profile"))]
    let _ = bytes;
}

pub(super) fn record_bio_read(bytes: Option<usize>) {
    #[cfg(feature = "test-boringssl-tls-profile")]
    {
        PROFILE.bio_read_calls.fetch_add(1, Ordering::Relaxed);
        if let Some(bytes) = bytes {
            record_size(bytes, &PROFILE.bio_read_bytes, &PROFILE.bio_read_sizes);
        }
    }
    #[cfg(not(feature = "test-boringssl-tls-profile"))]
    let _ = bytes;
}

pub(super) fn record_bio_write(bytes: Option<usize>) {
    #[cfg(feature = "test-boringssl-tls-profile")]
    {
        PROFILE.bio_write_calls.fetch_add(1, Ordering::Relaxed);
        if let Some(bytes) = bytes {
            record_size(bytes, &PROFILE.bio_write_bytes, &PROFILE.bio_write_sizes);
        }
    }
    #[cfg(not(feature = "test-boringssl-tls-profile"))]
    let _ = bytes;
}

pub(super) fn configure_boring_tls_profile(builder: &mut SslConnectorBuilder) {
    #[cfg(feature = "test-boringssl-tls-profile")]
    unsafe {
        boring_sys::SSL_CTX_set_msg_callback(builder.as_ptr(), Some(record_tls_message));
    }
    #[cfg(not(feature = "test-boringssl-tls-profile"))]
    let _ = builder;
}

#[cfg(feature = "test-boringssl-tls-profile")]
unsafe extern "C" fn record_tls_message(
    is_write: std::os::raw::c_int,
    _version: std::os::raw::c_int,
    content_type: std::os::raw::c_int,
    buffer: *const std::ffi::c_void,
    length: usize,
    _ssl: *mut boring_sys::SSL,
    _arg: *mut std::ffi::c_void,
) {
    if content_type != boring_sys::SSL3_RT_HEADER as std::os::raw::c_int
        || buffer.is_null()
        || length < 5
    {
        return;
    }
    let header = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), length) };
    let record_bytes = u16::from_be_bytes([header[3], header[4]]) as u64;
    if is_write == 1 {
        PROFILE.tls_write_records.fetch_add(1, Ordering::Relaxed);
        PROFILE
            .tls_write_record_bytes
            .fetch_add(record_bytes, Ordering::Relaxed);
    } else {
        PROFILE.tls_read_records.fetch_add(1, Ordering::Relaxed);
        PROFILE
            .tls_read_record_bytes
            .fetch_add(record_bytes, Ordering::Relaxed);
    }
}

pub fn take_boring_tls_io_profile_snapshot() -> ResidentBoringTlsIoProfileSnapshot {
    #[cfg(feature = "test-boringssl-tls-profile")]
    {
        PROFILE.take()
    }
    #[cfg(not(feature = "test-boringssl-tls-profile"))]
    {
        ResidentBoringTlsIoProfileSnapshot {
            enabled: false,
            ssl_read_calls: 0,
            ssl_read_bytes: 0,
            ssl_read_sizes: [0; 7],
            ssl_write_calls: 0,
            ssl_write_bytes: 0,
            ssl_write_sizes: [0; 7],
            bio_read_calls: 0,
            bio_read_bytes: 0,
            bio_read_sizes: [0; 7],
            bio_write_calls: 0,
            bio_write_bytes: 0,
            bio_write_sizes: [0; 7],
            tls_read_records: 0,
            tls_read_record_bytes: 0,
            tls_write_records: 0,
            tls_write_record_bytes: 0,
            size_bucket_upper_bounds: SIZE_BUCKET_UPPER_BOUNDS,
        }
    }
}

#[cfg(all(test, feature = "test-boringssl-tls-profile"))]
mod tests {
    use super::*;

    #[test]
    fn profile_snapshot_counts_sizes_and_resets() {
        let _ = take_boring_tls_io_profile_snapshot();
        record_ssl_read(Some(63));
        record_ssl_write(None);
        record_bio_read(Some(1024));
        record_bio_write(Some(65_537));
        let snapshot = take_boring_tls_io_profile_snapshot();
        assert_eq!(snapshot.ssl_read_calls, 1);
        assert_eq!(snapshot.ssl_read_bytes, 63);
        assert_eq!(snapshot.ssl_read_sizes[0], 1);
        assert_eq!(snapshot.ssl_write_calls, 1);
        assert_eq!(snapshot.bio_read_sizes[2], 1);
        assert_eq!(snapshot.bio_write_sizes[6], 1);
        assert_eq!(take_boring_tls_io_profile_snapshot().ssl_read_calls, 0);
    }
}
