pub const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 22;
pub const TLS_RECORD_HEADER_LEN: usize = 5;

mod one_shot;
mod options;
mod planner;
mod report;
mod sync_writer;

pub use one_shot::fragment_tls_write;
pub use options::{TlsFragmentOptions, parse_tls_fragment_range};
pub use planner::{
    TLS_FRAGMENT_MAX_BUFFERED_RECORD_LEN, TlsFragmentPlan, TlsFragmentPlanner, TlsFragmentSegment,
};
pub use report::{
    SharedTlsFragmentStats, TlsFragmentStats, TlsFragmentWrite, TlsFragmentWriteReport,
    new_tls_fragment_stats, snapshot_tls_fragment_stats,
};
pub use sync_writer::TlsFragmentingStream;
