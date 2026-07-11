use std::io::{self, Read, Write};
use std::thread;
use std::time::Duration;

use super::{SharedTlsFragmentStats, TlsFragmentOptions, TlsFragmentPlan, TlsFragmentPlanner};

pub struct TlsFragmentingStream<S> {
    inner: S,
    planner: TlsFragmentPlanner,
    stats: SharedTlsFragmentStats,
}

impl<S> TlsFragmentingStream<S> {
    pub fn new(inner: S, options: TlsFragmentOptions, stats: SharedTlsFragmentStats) -> Self {
        Self {
            inner,
            planner: TlsFragmentPlanner::with_reports(options),
            stats,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S> Read for TlsFragmentingStream<S>
where
    S: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<S> Write for TlsFragmentingStream<S>
where
    S: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let plan = self
            .planner
            .push(buf)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        write_tls_fragment_plan(&mut self.inner, &plan)?;
        self.record_reports(&plan)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let plan = self.planner.finish_incomplete();
        write_tls_fragment_plan(&mut self.inner, &plan)?;
        self.record_reports(&plan)?;
        self.inner.flush()
    }
}

impl<S> TlsFragmentingStream<S> {
    fn record_reports(&self, plan: &TlsFragmentPlan) -> io::Result<()> {
        if plan.reports().is_empty() {
            return Ok(());
        }
        let mut stats = self
            .stats
            .lock()
            .map_err(|_| io::Error::other("tls fragment stats mutex poisoned"))?;
        stats.writes.extend_from_slice(plan.reports());
        Ok(())
    }
}

fn write_tls_fragment_plan<S>(inner: &mut S, plan: &TlsFragmentPlan) -> io::Result<()>
where
    S: Write,
{
    let mut start = 0;
    for segment in plan.segments() {
        if segment.delay_before_ms != 0 {
            thread::sleep(Duration::from_millis(segment.delay_before_ms));
        }
        inner.write_all(&plan.bytes()[start..segment.end])?;
        start = segment.end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared_transport::{TLS_HANDSHAKE_CONTENT_TYPE, TLS_RECORD_HEADER_LEN};

    #[test]
    fn synchronous_stream_buffers_split_records_until_complete() {
        let options = TlsFragmentOptions::from_ranges("8-8", "0-0").unwrap();
        let stats = crate::shared_transport::new_tls_fragment_stats();
        let mut stream = TlsFragmentingStream::new(Vec::new(), options, stats.clone());
        let mut input = vec![TLS_HANDSHAKE_CONTENT_TYPE, 0x03, 0x03, 0, 20];
        input.extend(0_u8..20);

        stream
            .write_all(&input[..TLS_RECORD_HEADER_LEN + 3])
            .unwrap();
        assert!(stream.inner.is_empty());
        stream
            .write_all(&input[TLS_RECORD_HEADER_LEN + 3..])
            .unwrap();

        let stats = crate::shared_transport::snapshot_tls_fragment_stats(&stats);
        assert_eq!(stats.fragment_payload_lens(), vec![8, 8, 4]);
        assert_eq!(stream.inner.len(), input.len() + 2 * TLS_RECORD_HEADER_LEN);
    }
}
