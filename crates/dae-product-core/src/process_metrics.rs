use std::fs;
use std::io;
use std::time::Instant;

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessMetrics {
    pub rss_bytes: u64,
    pub anonymous_rss_bytes: u64,
    pub file_rss_bytes: u64,
    pub vm_data_bytes: u64,
    pub thread_count: u64,
    pub cpu_usage_percent: f64,
}

impl ProcessMetrics {
    pub fn heap_alloc_bytes_compat(&self) -> u64 {
        self.anonymous_rss_bytes
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ProcCpuSample {
    pub total_ticks: u64,
    pub observed_at: Instant,
}

#[derive(Debug, Default)]
pub struct ProcessCpuTracker {
    previous: Option<ProcCpuSample>,
}

impl ProcessCpuTracker {
    pub fn sample(&mut self) -> io::Result<ProcessMetrics> {
        let mut metrics = process_status_metrics()?;
        let stat = fs::read_to_string("/proc/self/stat")?;
        let total_ticks = proc_stat_total_cpu_ticks(&stat)?;
        let observed_at = Instant::now();
        metrics.cpu_usage_percent =
            process_cpu_usage_percent_from_samples(&stat, total_ticks, observed_at, self.previous)?;
        self.previous = Some(ProcCpuSample {
            total_ticks,
            observed_at,
        });
        Ok(metrics)
    }
}

pub fn process_metrics_lifetime_snapshot() -> ProcessMetrics {
    let mut metrics = process_status_metrics().unwrap_or_default();
    let usage = fs::read_to_string("/proc/self/stat")
        .and_then(|stat| {
            let total_ticks = proc_stat_total_cpu_ticks(&stat)?;
            process_lifetime_cpu_usage_percent(&stat, total_ticks)
        })
        .unwrap_or(0.0);
    metrics.cpu_usage_percent = round_percent(usage);
    metrics
}

pub fn process_status_metrics() -> io::Result<ProcessMetrics> {
    let status = fs::read_to_string("/proc/self/status")?;
    let mut metrics = process_status_metrics_from_str(&status);
    if metrics.rss_bytes == 0 {
        metrics.rss_bytes = current_rss_bytes_from_statm();
    }
    Ok(metrics)
}

pub fn process_status_metrics_from_str(status: &str) -> ProcessMetrics {
    let mut metrics = ProcessMetrics::default();
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            metrics.rss_bytes = proc_status_kib_value(value).saturating_mul(1024);
        } else if let Some(value) = line.strip_prefix("RssAnon:") {
            metrics.anonymous_rss_bytes = proc_status_kib_value(value).saturating_mul(1024);
        } else if let Some(value) = line.strip_prefix("RssFile:") {
            metrics.file_rss_bytes = proc_status_kib_value(value).saturating_mul(1024);
        } else if let Some(value) = line.strip_prefix("VmData:") {
            metrics.vm_data_bytes = proc_status_kib_value(value).saturating_mul(1024);
        } else if let Some(value) = line.strip_prefix("Threads:") {
            metrics.thread_count = value.trim().parse::<u64>().unwrap_or(0);
        }
    }
    if metrics.anonymous_rss_bytes == 0 {
        metrics.anonymous_rss_bytes = metrics.vm_data_bytes;
    }
    metrics
}

pub fn proc_status_kib_value(value: &str) -> u64 {
    value
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

pub fn process_cpu_usage_percent_from_samples(
    stat: &str,
    total_ticks: u64,
    observed_at: Instant,
    previous: Option<ProcCpuSample>,
) -> io::Result<f64> {
    let usage = if let Some(previous) = previous {
        let elapsed = observed_at
            .saturating_duration_since(previous.observed_at)
            .as_secs_f64();
        if elapsed > 0.0 {
            let delta_ticks = total_ticks.saturating_sub(previous.total_ticks) as f64;
            cpu_ticks_to_percent(delta_ticks, elapsed)
        } else {
            0.0
        }
    } else {
        process_lifetime_cpu_usage_percent(stat, total_ticks).unwrap_or(0.0)
    };
    Ok(round_percent(usage))
}

pub fn proc_stat_total_cpu_ticks(stat: &str) -> io::Result<u64> {
    let fields = proc_stat_fields_after_comm(stat)?;
    let utime = fields
        .get(11)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proc utime"))?;
    let stime = fields
        .get(12)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proc stime"))?;
    Ok(utime.saturating_add(stime))
}

pub fn process_lifetime_cpu_usage_percent(stat: &str, total_ticks: u64) -> io::Result<f64> {
    let fields = proc_stat_fields_after_comm(stat)?;
    let start_ticks = fields
        .get(19)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proc starttime"))?;
    let uptime = system_uptime_seconds()?;
    let process_start = start_ticks as f64 / clock_ticks_per_second() as f64;
    let elapsed = (uptime - process_start).max(0.001);
    Ok(cpu_ticks_to_percent(total_ticks as f64, elapsed))
}

pub fn proc_stat_fields_after_comm(stat: &str) -> io::Result<Vec<&str>> {
    let Some((_, tail)) = stat.rsplit_once(") ") else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid proc stat comm field",
        ));
    };
    Ok(tail.split_whitespace().collect())
}

pub fn system_uptime_seconds() -> io::Result<f64> {
    let uptime = fs::read_to_string("/proc/uptime")?;
    uptime
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<f64>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid uptime"))
}

pub fn clock_ticks_per_second() -> u64 {
    let value = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if value > 0 { value as u64 } else { 100 }
}

pub fn cpu_ticks_to_percent(cpu_ticks: f64, elapsed_seconds: f64) -> f64 {
    if elapsed_seconds <= 0.0 {
        return 0.0;
    }
    let capacity = clock_ticks_per_second() as f64 * cpu_parallelism() as f64 * elapsed_seconds;
    if capacity <= 0.0 {
        return 0.0;
    }
    (cpu_ticks / capacity * 100.0).clamp(0.0, 100.0)
}

pub fn cpu_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .max(1)
}

pub fn round_percent(value: f64) -> f64 {
    if !value.is_finite() {
        0.0
    } else {
        (value * 100.0).round() / 100.0
    }
}

pub fn current_rss_bytes_from_statm() -> u64 {
    let Ok(statm) = fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    let Some(pages) = statm
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return 0;
    };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return 0;
    }
    pages.saturating_mul(page_size as u64)
}
