use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};

use crate::production_runtime_owner::resident_dataplane::resident_allocator_stats_json;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ProcessResourceSample {
    rss_kib: u64,
    fds: usize,
    threads: usize,
    minor_faults: u64,
    major_faults: u64,
    cpu_ticks: u64,
}

impl ProcessResourceSample {
    pub(super) fn capture() -> Self {
        let (minor_faults, major_faults, cpu_ticks) = process_stat_counters().unwrap_or_default();
        Self {
            rss_kib: process_status_value_kib("VmRSS:").unwrap_or_default(),
            fds: directory_entry_count(Path::new("/proc/self/fd")).unwrap_or_default(),
            threads: directory_entry_count(Path::new("/proc/self/task")).unwrap_or_default(),
            minor_faults,
            major_faults,
            cpu_ticks,
        }
    }

    pub(super) fn observe(&mut self) {
        let current = Self::capture();
        self.rss_kib = self.rss_kib.max(current.rss_kib);
        self.fds = self.fds.max(current.fds);
        self.threads = self.threads.max(current.threads);
        self.minor_faults = self.minor_faults.max(current.minor_faults);
        self.major_faults = self.major_faults.max(current.major_faults);
        self.cpu_ticks = self.cpu_ticks.max(current.cpu_ticks);
    }

    pub(super) fn to_json(self) -> Value {
        json!({
            "rssKiB": self.rss_kib,
            "fds": self.fds,
            "threads": self.threads,
            "minorFaults": self.minor_faults,
            "majorFaults": self.major_faults,
            "cpuTicks": self.cpu_ticks,
        })
    }
}

pub(super) fn duration_micros(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

pub(super) fn percentile(samples: &[u64], percentile: usize) -> Option<u64> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = sorted
        .len()
        .saturating_mul(percentile)
        .div_ceil(100)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    Some(sorted[rank])
}

pub(super) fn allocator_sample() -> Value {
    resident_allocator_stats_json()
}

fn directory_entry_count(path: &Path) -> Option<usize> {
    std::fs::read_dir(path).ok().map(|entries| entries.count())
}

fn process_status_value_kib(label: &str) -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix(label)?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

fn process_stat_counters() -> Option<(u64, u64, u64)> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let fields = stat
        .get(stat.rfind(')')? + 1..)?
        .split_whitespace()
        .collect::<Vec<_>>();
    let minor_faults = fields.get(7)?.parse().ok()?;
    let major_faults = fields.get(9)?.parse().ok()?;
    let user_ticks: u64 = fields.get(11)?.parse().ok()?;
    let system_ticks: u64 = fields.get(12)?.parse().ok()?;
    Some((
        minor_faults,
        major_faults,
        user_ticks.saturating_add(system_ticks),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_uses_nearest_rank_without_floating_point() {
        let samples = [5, 1, 4, 2, 3];
        assert_eq!(percentile(&samples, 50), Some(3));
        assert_eq!(percentile(&samples, 95), Some(5));
        assert_eq!(percentile(&[], 99), None);
    }

    #[test]
    fn process_sample_reads_bounded_linux_counters() {
        let sample = ProcessResourceSample::capture();
        assert!(sample.fds > 0);
        assert!(sample.threads > 0);
        assert!(sample.rss_kib > 0);
    }
}
