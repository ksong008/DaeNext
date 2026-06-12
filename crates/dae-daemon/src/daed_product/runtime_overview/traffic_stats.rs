use super::*;
use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::borrow::Cow;
use std::fmt;
#[derive(Debug, Default)]
pub(crate) struct RuntimeTrafficStats {
    pub(in crate::daed_product) upload_total: u64,
    pub(in crate::daed_product) download_total: u64,
    pub(in crate::daed_product) upload_rate: u64,
    pub(in crate::daed_product) download_rate: u64,
    pub(in crate::daed_product) active_connections: u64,
    pub(in crate::daed_product) udp_sessions: u64,
    pub(in crate::daed_product) samples: Vec<Value>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RuntimeTrafficTotalSample {
    pub(in crate::daed_product) upload_total: u64,
    pub(in crate::daed_product) download_total: u64,
    pub(in crate::daed_product) observed_at: Instant,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RuntimeTrafficSecond {
    pub(in crate::daed_product) upload: u64,
    pub(in crate::daed_product) download: u64,
    pub(in crate::daed_product) active_connections: u64,
    pub(in crate::daed_product) udp_sessions: u64,
}

#[derive(Debug, Default)]
pub(crate) struct RuntimeTrafficEventFileCache {
    pub(in crate::daed_product) entries: BTreeMap<String, RuntimeTrafficEventFileState>,
    next_generation: u64,
}

#[derive(Debug, Default)]
pub(crate) struct RuntimeTrafficEventFileState {
    pub(in crate::daed_product) path: String,
    pub(in crate::daed_product) offset: u64,
    pub(in crate::daed_product) upload_total: u64,
    pub(in crate::daed_product) download_total: u64,
    pub(in crate::daed_product) seconds: BTreeMap<u64, RuntimeTrafficSecond>,
    generation: u64,
}

pub(crate) static LAST_RUNTIME_TRAFFIC_TOTAL_SAMPLE: OnceLock<
    Mutex<Option<RuntimeTrafficTotalSample>>,
> = OnceLock::new();
pub(crate) static RUNTIME_TRAFFIC_RATE_SAMPLES: OnceLock<Mutex<VecDeque<(u64, u64, u64)>>> =
    OnceLock::new();
pub(crate) static RUNTIME_TRAFFIC_EVENT_FILE_CACHE: OnceLock<Mutex<RuntimeTrafficEventFileCache>> =
    OnceLock::new();

const RUNTIME_TRAFFIC_EVENT_FILE_CACHE_MAX_PATHS: usize = 8;

pub(crate) fn resident_runtime_traffic_stats(
    runtime: &Value,
    window_sec: u64,
    max_points: usize,
) -> RuntimeTrafficStats {
    if let Some(stats) = resident_live_runtime_traffic_stats(runtime, window_sec, max_points) {
        return stats;
    }
    let Some(event_file) = runtime
        .pointer("/residentDataplane/event_file")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
    else {
        return RuntimeTrafficStats::default();
    };
    resident_event_file_traffic_stats(event_file, window_sec, max_points).unwrap_or_default()
}

pub(crate) fn resident_event_file_traffic_stats(
    event_file: &str,
    window_sec: u64,
    max_points: usize,
) -> io::Result<RuntimeTrafficStats> {
    let len = fs::metadata(event_file)?.len();
    let cache_lock = RUNTIME_TRAFFIC_EVENT_FILE_CACHE
        .get_or_init(|| Mutex::new(RuntimeTrafficEventFileCache::default()));
    let (read_start, read_end) =
        reserve_runtime_traffic_event_file_range(cache_lock, event_file, len)?;
    let delta = match read_runtime_traffic_event_delta(event_file, read_start, read_end) {
        Ok(delta) => delta,
        Err(err) => {
            restore_runtime_traffic_event_file_range(cache_lock, event_file, read_start, read_end)?;
            return Err(err);
        }
    };
    let (mut stats, sample_tuples) =
        merge_runtime_traffic_event_delta_and_snapshot(cache_lock, event_file, delta, window_sec)?;
    let mut sample_values = sample_tuples
        .into_iter()
        .map(|(timestamp, upload, download)| {
            json!({
                "timestamp": iso8601_utc(timestamp),
                "uploadRate": upload.to_string(),
                "downloadRate": download.to_string(),
            })
        })
        .collect::<Vec<_>>();
    if sample_values.len() > max_points {
        sample_values = sample_values.split_off(sample_values.len() - max_points);
    }
    stats.samples = sample_values;
    Ok(stats)
}

fn reserve_runtime_traffic_event_file_range(
    cache_lock: &Mutex<RuntimeTrafficEventFileCache>,
    event_file: &str,
    len: u64,
) -> io::Result<(u64, u64)> {
    let mut cache = cache_lock
        .lock()
        .map_err(runtime_traffic_cache_lock_error)?;
    let generation = cache.touch_generation();
    let state = cache.state_mut(event_file);
    if state.path.is_empty() {
        state.path = event_file.to_owned();
    }
    if len < state.offset {
        *state = RuntimeTrafficEventFileState {
            path: event_file.to_owned(),
            ..RuntimeTrafficEventFileState::default()
        };
    }
    state.generation = generation;
    let read_start = state.offset;
    state.offset = len;
    cache.prune_except(event_file);
    Ok((read_start, len))
}

fn restore_runtime_traffic_event_file_range(
    cache_lock: &Mutex<RuntimeTrafficEventFileCache>,
    event_file: &str,
    read_start: u64,
    read_end: u64,
) -> io::Result<()> {
    let mut cache = cache_lock
        .lock()
        .map_err(runtime_traffic_cache_lock_error)?;
    if let Some(state) = cache.entries.get_mut(event_file)
        && state.offset == read_end
    {
        state.offset = read_start;
    }
    Ok(())
}

#[derive(Debug, Default)]
struct RuntimeTrafficEventDelta {
    end_offset: u64,
    upload_total: u64,
    download_total: u64,
    seconds: BTreeMap<u64, RuntimeTrafficSecond>,
}

fn read_runtime_traffic_event_delta(
    event_file: &str,
    start: u64,
    end: u64,
) -> io::Result<RuntimeTrafficEventDelta> {
    if start >= end {
        return Ok(RuntimeTrafficEventDelta {
            end_offset: end,
            ..RuntimeTrafficEventDelta::default()
        });
    }
    let mut file = fs::File::open(event_file)?;
    file.seek(SeekFrom::Start(start))?;
    let mut reader = io::BufReader::new(file.take(end - start));
    let mut delta = RuntimeTrafficEventDelta {
        end_offset: start,
        ..RuntimeTrafficEventDelta::default()
    };
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            break;
        }
        delta.end_offset = delta.end_offset.saturating_add(read as u64);
        let Ok(event) = serde_json::from_str::<RuntimeTrafficEvent>(&line) else {
            continue;
        };
        let (upload, download) = event.traffic_bytes();
        delta.upload_total = delta.upload_total.saturating_add(upload);
        delta.download_total = delta.download_total.saturating_add(download);
        let Some(timestamp) = event.timestamp_unix else {
            continue;
        };
        let entry = delta.seconds.entry(timestamp).or_default();
        entry.upload = entry.upload.saturating_add(upload);
        entry.download = entry.download.saturating_add(download);
        if event.is_tcp_connection_event() {
            entry.active_connections = entry.active_connections.saturating_add(1);
        }
        if event.is_udp_session_event() {
            entry.udp_sessions = entry.udp_sessions.saturating_add(1);
        }
    }
    Ok(delta)
}

fn merge_runtime_traffic_event_delta_and_snapshot(
    cache_lock: &Mutex<RuntimeTrafficEventFileCache>,
    event_file: &str,
    delta: RuntimeTrafficEventDelta,
    window_sec: u64,
) -> io::Result<(RuntimeTrafficStats, Vec<(u64, u64, u64)>)> {
    let mut cache = cache_lock
        .lock()
        .map_err(runtime_traffic_cache_lock_error)?;
    let generation = cache.touch_generation();
    let state = cache.state_mut(event_file);
    if state.path.is_empty() {
        *state = RuntimeTrafficEventFileState {
            path: event_file.to_owned(),
            ..RuntimeTrafficEventFileState::default()
        };
    }
    state.generation = generation;
    if delta.end_offset > state.offset {
        state.offset = delta.end_offset;
    }
    state.upload_total = state.upload_total.saturating_add(delta.upload_total);
    state.download_total = state.download_total.saturating_add(delta.download_total);
    for (timestamp, second) in delta.seconds {
        let entry = state.seconds.entry(timestamp).or_default();
        entry.upload = entry.upload.saturating_add(second.upload);
        entry.download = entry.download.saturating_add(second.download);
        entry.active_connections = entry
            .active_connections
            .saturating_add(second.active_connections);
        entry.udp_sessions = entry.udp_sessions.saturating_add(second.udp_sessions);
    }
    let now = unix_now();
    let max_retained_window = 3_600_u64;
    let retain_start = now.saturating_sub(max_retained_window);
    if state
        .seconds
        .first_key_value()
        .is_some_and(|(timestamp, _)| *timestamp < retain_start)
    {
        state.seconds = state.seconds.split_off(&retain_start);
    }

    let window_start = now.saturating_sub(window_sec);
    let rate_window_start = now.saturating_sub(5);
    let mut stats = RuntimeTrafficStats {
        upload_total: state.upload_total,
        download_total: state.download_total,
        ..RuntimeTrafficStats::default()
    };
    let mut sample_tuples = Vec::new();
    for (timestamp, second) in state.seconds.range(window_start..) {
        stats.active_connections = stats
            .active_connections
            .saturating_add(second.active_connections);
        stats.udp_sessions = stats.udp_sessions.saturating_add(second.udp_sessions);
        if *timestamp >= rate_window_start {
            stats.upload_rate = stats.upload_rate.saturating_add(second.upload);
            stats.download_rate = stats.download_rate.saturating_add(second.download);
        }
        sample_tuples.push((*timestamp, second.upload, second.download));
    }
    stats.upload_rate /= 5;
    stats.download_rate /= 5;
    cache.prune_except(event_file);
    Ok((stats, sample_tuples))
}

impl RuntimeTrafficEventFileCache {
    fn touch_generation(&mut self) -> u64 {
        self.next_generation = self.next_generation.saturating_add(1);
        self.next_generation
    }

    fn state_mut(&mut self, event_file: &str) -> &mut RuntimeTrafficEventFileState {
        self.entries
            .entry(event_file.to_owned())
            .or_insert_with(|| RuntimeTrafficEventFileState {
                path: event_file.to_owned(),
                ..RuntimeTrafficEventFileState::default()
            })
    }

    fn prune_except(&mut self, keep: &str) {
        if self.entries.len() <= RUNTIME_TRAFFIC_EVENT_FILE_CACHE_MAX_PATHS {
            return;
        }
        let mut removable = self
            .entries
            .iter()
            .filter(|(path, _)| path.as_str() != keep)
            .map(|(path, state)| (state.generation, path.clone()))
            .collect::<Vec<_>>();
        removable.sort_by_key(|(generation, _)| *generation);
        let remove_count = self
            .entries
            .len()
            .saturating_sub(RUNTIME_TRAFFIC_EVENT_FILE_CACHE_MAX_PATHS);
        for (_, path) in removable.into_iter().take(remove_count) {
            self.entries.remove(&path);
        }
    }
}

fn runtime_traffic_cache_lock_error<T>(_err: std::sync::PoisonError<T>) -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        "runtime traffic event file cache lock poisoned",
    )
}

pub(crate) fn resident_live_runtime_traffic_stats(
    runtime: &Value,
    window_sec: u64,
    max_points: usize,
) -> Option<RuntimeTrafficStats> {
    let metrics = runtime.pointer("/residentDataplane/metrics")?;
    let upload_total = event_u64(metrics, "uploadTotal");
    let download_total = event_u64(metrics, "downloadTotal");
    let (upload_rate, download_rate, samples) =
        live_runtime_traffic_rate_samples(upload_total, download_total, window_sec, max_points);
    Some(RuntimeTrafficStats {
        upload_total,
        download_total,
        upload_rate,
        download_rate,
        active_connections: event_u64(metrics, "activeTcpConnections"),
        udp_sessions: event_u64(metrics, "activeUdpSessions"),
        samples,
    })
}

pub(crate) fn live_runtime_traffic_rate_samples(
    upload_total: u64,
    download_total: u64,
    window_sec: u64,
    max_points: usize,
) -> (u64, u64, Vec<Value>) {
    let now = unix_now();
    let observed_at = Instant::now();
    let sample_lock = LAST_RUNTIME_TRAFFIC_TOTAL_SAMPLE.get_or_init(|| Mutex::new(None));
    let mut previous = sample_lock.lock().ok();
    let mut upload_rate = 0_u64;
    let mut download_rate = 0_u64;
    let mut totals_reset = false;
    if let Some(previous_guard) = previous.as_deref_mut() {
        if let Some(previous_sample) = *previous_guard {
            if upload_total < previous_sample.upload_total
                || download_total < previous_sample.download_total
            {
                totals_reset = true;
            } else {
                let elapsed = observed_at
                    .duration_since(previous_sample.observed_at)
                    .as_secs_f64();
                if elapsed > 0.0 {
                    upload_rate =
                        ((upload_total - previous_sample.upload_total) as f64 / elapsed) as u64;
                    download_rate =
                        ((download_total - previous_sample.download_total) as f64 / elapsed) as u64;
                }
            }
        }
        *previous_guard = Some(RuntimeTrafficTotalSample {
            upload_total,
            download_total,
            observed_at,
        });
    }

    let history_lock = RUNTIME_TRAFFIC_RATE_SAMPLES.get_or_init(|| Mutex::new(VecDeque::new()));
    let mut history = match history_lock.lock() {
        Ok(history) => history,
        Err(_) => return (upload_rate, download_rate, Vec::new()),
    };
    if totals_reset {
        history.clear();
    }
    if history
        .back()
        .is_some_and(|(timestamp, _, _)| *timestamp == now)
    {
        if let Some(back) = history.back_mut() {
            *back = (now, upload_rate, download_rate);
        }
    } else {
        history.push_back((now, upload_rate, download_rate));
    }
    let window_start = now.saturating_sub(window_sec);
    while history
        .front()
        .is_some_and(|(timestamp, _, _)| *timestamp < window_start)
    {
        history.pop_front();
    }
    while history.len() > max_points {
        history.pop_front();
    }
    let samples = history
        .iter()
        .map(|(timestamp, upload, download)| {
            json!({
                "timestamp": iso8601_utc(*timestamp),
                "uploadRate": upload.to_string(),
                "downloadRate": download.to_string(),
            })
        })
        .collect();
    (upload_rate, download_rate, samples)
}

#[derive(Debug, Deserialize)]
struct RuntimeTrafficEvent<'a> {
    #[serde(borrow, default, deserialize_with = "optional_cow_str")]
    event: Option<Cow<'a, str>>,
    #[serde(rename = "timestampUnix", default, deserialize_with = "optional_u64")]
    timestamp_unix: Option<u64>,
    #[serde(default, deserialize_with = "traffic_u64")]
    bytes_client_to_proxy: u64,
    #[serde(default, deserialize_with = "traffic_u64")]
    bytes_client_to_direct: u64,
    #[serde(default, deserialize_with = "traffic_u64")]
    request_len: u64,
    #[serde(default, deserialize_with = "traffic_u64")]
    bytes_proxy_to_client: u64,
    #[serde(default, deserialize_with = "traffic_u64")]
    bytes_direct_to_client: u64,
    #[serde(default, deserialize_with = "traffic_u64")]
    response_len: u64,
}

impl RuntimeTrafficEvent<'_> {
    fn traffic_bytes(&self) -> (u64, u64) {
        let upload = self
            .bytes_client_to_proxy
            .saturating_add(self.bytes_client_to_direct)
            .saturating_add(self.request_len);
        let download = self
            .bytes_proxy_to_client
            .saturating_add(self.bytes_direct_to_client)
            .saturating_add(self.response_len);
        (upload, download)
    }

    fn is_tcp_connection_event(&self) -> bool {
        matches!(
            self.event.as_deref(),
            Some("tcp_connection_finished" | "tcp_connection_failed")
        )
    }

    fn is_udp_session_event(&self) -> bool {
        matches!(
            self.event.as_deref(),
            Some("udp_packet_finished" | "udp_dns_packet_finished")
        )
    }
}

fn optional_cow_str<'de, D>(deserializer: D) -> Result<Option<Cow<'de, str>>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(OptionalCowStrVisitor)
}

struct OptionalCowStrVisitor;

impl<'de> Visitor<'de> for OptionalCowStrVisitor {
    type Value = Option<Cow<'de, str>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string or null")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E> {
        Ok(Some(Cow::Borrowed(value)))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Some(Cow::Owned(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Some(Cow::Owned(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(None)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(None)
    }
}

fn optional_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(OptionalU64Visitor)
}

struct OptionalU64Visitor;

impl<'de> Visitor<'de> for OptionalU64Visitor {
    type Value = Option<u64>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an unsigned integer, decimal string, or null")
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Some(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(u64::try_from(value).ok())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(value.parse::<u64>().ok())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&value)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(None)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(None)
    }
}

fn traffic_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(TrafficU64Visitor)
}

struct TrafficU64Visitor;

impl<'de> Visitor<'de> for TrafficU64Visitor {
    type Value = u64;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an unsigned integer or decimal string")
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(value)
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(u64::try_from(value).unwrap_or(0))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(0)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(value.parse::<u64>().unwrap_or(0))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&value)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(0)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(0)
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(0)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(0)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(0)
    }
}

pub(crate) fn event_u64(event: &Value, key: &str) -> u64 {
    event
        .get(key)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok()))
        })
        .unwrap_or(0)
}
