#[derive(Clone, Copy, Debug, Default)]
struct ProcessMetrics {
    rss_bytes: u64,
    anonymous_rss_bytes: u64,
    file_rss_bytes: u64,
    vm_data_bytes: u64,
    thread_count: u64,
    cpu_usage_percent: f64,
}

impl ProcessMetrics {
    fn heap_alloc_bytes_compat(&self) -> u64 {
        self.anonymous_rss_bytes
    }
}

#[derive(Clone, Copy, Debug)]
struct ProcCpuSample {
    total_ticks: u64,
    observed_at: Instant,
}

static LAST_PROC_CPU_SAMPLE: OnceLock<Mutex<Option<ProcCpuSample>>> = OnceLock::new();

fn current_process_metrics() -> ProcessMetrics {
    let mut metrics = process_status_metrics().unwrap_or_default();
    metrics.cpu_usage_percent = current_process_cpu_usage_percent().unwrap_or(0.0);
    metrics
}

fn process_status_metrics() -> io::Result<ProcessMetrics> {
    let status = fs::read_to_string("/proc/self/status")?;
    let mut metrics = process_status_metrics_from_str(&status);
    if metrics.rss_bytes == 0 {
        metrics.rss_bytes = current_rss_bytes_from_statm();
    }
    Ok(metrics)
}

fn process_status_metrics_from_str(status: &str) -> ProcessMetrics {
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

fn proc_status_kib_value(value: &str) -> u64 {
    value
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

fn current_process_cpu_usage_percent() -> io::Result<f64> {
    let stat = fs::read_to_string("/proc/self/stat")?;
    let total_ticks = proc_stat_total_cpu_ticks(&stat)?;
    let now = Instant::now();
    let lock = LAST_PROC_CPU_SAMPLE.get_or_init(|| Mutex::new(None));
    let mut guard = lock
        .lock()
        .map_err(|_| io::Error::other("process cpu sample lock poisoned"))?;
    let usage = if let Some(previous) = *guard {
        let elapsed = now.duration_since(previous.observed_at).as_secs_f64();
        if elapsed > 0.0 {
            let delta_ticks = total_ticks.saturating_sub(previous.total_ticks) as f64;
            cpu_ticks_to_percent(delta_ticks, elapsed)
        } else {
            0.0
        }
    } else {
        process_lifetime_cpu_usage_percent(&stat, total_ticks).unwrap_or(0.0)
    };
    *guard = Some(ProcCpuSample {
        total_ticks,
        observed_at: now,
    });
    Ok(round_percent(usage))
}

fn proc_stat_total_cpu_ticks(stat: &str) -> io::Result<u64> {
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

fn process_lifetime_cpu_usage_percent(stat: &str, total_ticks: u64) -> io::Result<f64> {
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

fn proc_stat_fields_after_comm(stat: &str) -> io::Result<Vec<&str>> {
    let Some((_, tail)) = stat.rsplit_once(") ") else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid proc stat comm field",
        ));
    };
    Ok(tail.split_whitespace().collect())
}

fn system_uptime_seconds() -> io::Result<f64> {
    let uptime = fs::read_to_string("/proc/uptime")?;
    uptime
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<f64>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid uptime"))
}

fn clock_ticks_per_second() -> u64 {
    let value = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if value > 0 { value as u64 } else { 100 }
}

fn cpu_ticks_to_percent(cpu_ticks: f64, elapsed_seconds: f64) -> f64 {
    if elapsed_seconds <= 0.0 {
        return 0.0;
    }
    let capacity = clock_ticks_per_second() as f64 * cpu_parallelism() as f64 * elapsed_seconds;
    if capacity <= 0.0 {
        return 0.0;
    }
    (cpu_ticks / capacity * 100.0).clamp(0.0, 100.0)
}

fn cpu_parallelism() -> usize {
    thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .max(1)
}

fn round_percent(value: f64) -> f64 {
    if !value.is_finite() {
        0.0
    } else {
        (value * 100.0).round() / 100.0
    }
}

fn current_rss_bytes_from_statm() -> u64 {
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
