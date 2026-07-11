use super::*;

mod files;
use self::files::*;
mod location;
use self::location::*;
mod snapshot;
use self::snapshot::*;
#[cfg(test)]
mod tests;

const CGROUP_MEMORY_SNAPSHOT_TTL: Duration = Duration::from_secs(1);
const CGROUP_MEMORY_LOCATION_SUCCESS_TTL: Duration = Duration::from_secs(5);
const CGROUP_MEMORY_LOCATION_FAILURE_TTL: Duration = Duration::from_secs(1);
const CGROUP_V2_VERSION: &str = "v2";

#[derive(Clone, Debug)]
struct CachedCgroupMemorySnapshot {
    observed_at: Instant,
    value: Value,
}

#[derive(Clone, Debug)]
struct CachedCgroupMemoryLocation {
    observed_at: Instant,
    generation: u64,
    result: Result<CgroupMemoryLocation, String>,
}

#[derive(Clone, Debug)]
struct CgroupMemoryLocationResolution {
    generation: u64,
    result: Result<CgroupMemoryLocation, String>,
}

#[derive(Debug, Default)]
struct CgroupMemoryLocationCache {
    entry: Option<CachedCgroupMemoryLocation>,
}

impl CgroupMemoryLocationCache {
    fn resolve(
        &mut self,
        now: Instant,
        force: bool,
        resolver: impl FnOnce() -> Result<CgroupMemoryLocation, String>,
    ) -> CgroupMemoryLocationResolution {
        if !force && let Some(entry) = self.entry.as_ref() {
            let ttl = if entry.result.is_ok() {
                CGROUP_MEMORY_LOCATION_SUCCESS_TTL
            } else {
                CGROUP_MEMORY_LOCATION_FAILURE_TTL
            };
            if now.saturating_duration_since(entry.observed_at) < ttl {
                return CgroupMemoryLocationResolution {
                    generation: entry.generation,
                    result: entry.result.clone(),
                };
            }
        }

        let result = resolver();
        let previous_generation = self
            .entry
            .as_ref()
            .map(|entry| entry.generation)
            .unwrap_or(0);
        let changed = self
            .entry
            .as_ref()
            .is_none_or(|entry| entry.result != result);
        let generation = if changed {
            previous_generation.saturating_add(1)
        } else {
            previous_generation.max(1)
        };
        self.entry = Some(CachedCgroupMemoryLocation {
            observed_at: now,
            generation,
            result: result.clone(),
        });
        CgroupMemoryLocationResolution { generation, result }
    }
}

static CGROUP_MEMORY_LOCATION_CACHE: OnceLock<Mutex<CgroupMemoryLocationCache>> = OnceLock::new();
static CGROUP_MEMORY_SNAPSHOT_CACHE: OnceLock<Mutex<Option<CachedCgroupMemorySnapshot>>> =
    OnceLock::new();

pub(in crate::daed_product) fn cgroup_memory_snapshot_json() -> Value {
    if let Ok(mut guard) = CGROUP_MEMORY_SNAPSHOT_CACHE
        .get_or_init(|| Mutex::new(None))
        .lock()
    {
        let now = Instant::now();
        if let Some(cached) = guard.as_ref()
            && now.saturating_duration_since(cached.observed_at) < CGROUP_MEMORY_SNAPSHOT_TTL
        {
            return cached.value.clone();
        }
        let value = uncached_cgroup_memory_snapshot_json();
        *guard = Some(CachedCgroupMemorySnapshot {
            observed_at: now,
            value: value.clone(),
        });
        return value;
    }
    uncached_cgroup_memory_snapshot_json()
}

fn uncached_cgroup_memory_snapshot_json() -> Value {
    cgroup_memory_snapshot_from_resolver(resolve_cached_cgroup_memory_location)
}

fn cgroup_memory_snapshot_from_resolver(
    mut resolve: impl FnMut(bool) -> CgroupMemoryLocationResolution,
) -> Value {
    let first = resolve(false);
    let first_location = match first.result {
        Ok(location) => location,
        Err(reason) => return unavailable_location(first.generation, reason),
    };
    match read_cgroup_memory_snapshot(&first_location, first.generation) {
        Ok(snapshot) => snapshot,
        Err(first_error) => {
            let refreshed = resolve(true);
            match refreshed.result {
                Ok(location) => {
                    match read_cgroup_memory_snapshot(&location, refreshed.generation) {
                        Ok(snapshot) => snapshot,
                        Err(error) => unavailable_snapshot(
                            &location,
                            refreshed.generation,
                            format!(
                                "read cached cgroup location: {first_error}; read refreshed location: {error}"
                            ),
                        ),
                    }
                }
                Err(reason) => unavailable_snapshot(
                    &first_location,
                    first.generation,
                    format!(
                        "read cached cgroup location: {first_error}; refresh cgroup location: {reason}"
                    ),
                ),
            }
        }
    }
}

fn resolve_cached_cgroup_memory_location(force: bool) -> CgroupMemoryLocationResolution {
    let cache = CGROUP_MEMORY_LOCATION_CACHE
        .get_or_init(|| Mutex::new(CgroupMemoryLocationCache::default()));
    match cache.lock() {
        Ok(mut cache) => cache.resolve(Instant::now(), force, resolve_cgroup_memory_location),
        Err(_) => CgroupMemoryLocationResolution {
            generation: 0,
            result: resolve_cgroup_memory_location(),
        },
    }
}

fn unavailable_location(generation: u64, reason: String) -> Value {
    json!({
        "available": false,
        "version": CGROUP_V2_VERSION,
        "locationGeneration": generation,
        "reason": reason,
    })
}

fn unavailable_snapshot(location: &CgroupMemoryLocation, generation: u64, reason: String) -> Value {
    json!({
        "available": false,
        "version": CGROUP_V2_VERSION,
        "locationGeneration": generation,
        "path": location.path.display().to_string(),
        "cgroupPath": location.cgroup_path,
        "mountPoint": location.mount_point,
        "reason": reason,
    })
}
