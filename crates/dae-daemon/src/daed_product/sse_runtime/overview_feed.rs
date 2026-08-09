use super::*;

const RUNTIME_OVERVIEW_FEED_CAPACITY: usize = 8;
const RUNTIME_OVERVIEW_FULL_CACHE_ENTRIES: usize = 2;
const RUNTIME_OVERVIEW_FULL_CACHE_MAX_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProductRuntimeOverviewFullCacheKey {
    window_sec: u64,
    max_points: usize,
    sequence: u64,
    reload_count: u64,
    publication_id: u64,
}

struct ProductRuntimeOverviewFullCacheEntry {
    key: ProductRuntimeOverviewFullCacheKey,
    payload: Arc<[u8]>,
}

#[derive(Default)]
pub(super) struct ProductRuntimeOverviewFullCache {
    entries: Mutex<VecDeque<ProductRuntimeOverviewFullCacheEntry>>,
}

impl ProductRuntimeOverviewFullCache {
    pub(super) fn serialized(
        &self,
        app: &AppState,
        request: &HttpRequest,
    ) -> io::Result<Arc<[u8]>> {
        let window_sec = query_u64(request, "windowSec")
            .unwrap_or(60)
            .clamp(1, 3_600);
        let max_points = query_usize(request, "maxPoints")
            .unwrap_or(120)
            .clamp(1, 1_000);
        let key = ProductRuntimeOverviewFullCacheKey {
            window_sec,
            max_points,
            sequence: app
                .runtime_sampler
                .as_ref()
                .map(|sampler| sampler.sequence())
                .unwrap_or_default(),
            reload_count: app.runtime.runtime_overview_delta_state().reload_count,
            publication_id: app.runtime.allocator_publication_id(),
        };
        if let Ok(entries) = self.entries.lock()
            && let Some(entry) = entries.iter().find(|entry| entry.key == key)
        {
            return Ok(Arc::clone(&entry.payload));
        }
        let payload: Arc<[u8]> = serde_json::to_vec(&runtime_overview_report(app, request))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .into();
        if payload.len() <= RUNTIME_OVERVIEW_FULL_CACHE_MAX_BYTES
            && let Ok(mut entries) = self.entries.lock()
        {
            if let Some(entry) = entries.iter().find(|entry| entry.key == key) {
                return Ok(Arc::clone(&entry.payload));
            }
            entries.push_back(ProductRuntimeOverviewFullCacheEntry {
                key,
                payload: Arc::clone(&payload),
            });
            while entries.len() > RUNTIME_OVERVIEW_FULL_CACHE_ENTRIES {
                entries.pop_front();
            }
        }
        Ok(payload)
    }
}

pub(super) struct ProductRuntimeOverviewTick {
    pub(super) sequence: u64,
    pub(super) reload_count: u64,
    pub(super) payload: Arc<[u8]>,
}

pub(super) fn runtime_overview_feed() -> (
    tokio::sync::broadcast::Sender<Arc<ProductRuntimeOverviewTick>>,
    tokio::sync::broadcast::Receiver<Arc<ProductRuntimeOverviewTick>>,
) {
    tokio::sync::broadcast::channel(RUNTIME_OVERVIEW_FEED_CAPACITY)
}

pub(super) fn runtime_overview_tick(
    app: &AppState,
    sequence: u64,
) -> io::Result<Arc<ProductRuntimeOverviewTick>> {
    let mut delta = runtime_overview_delta_report(app);
    if let Value::Object(delta) = &mut delta {
        delta.insert("sequence".to_owned(), json!(sequence));
    }
    let reload_count = delta["reloadCount"].as_u64().unwrap_or(0);
    let payload = serde_json::to_vec(&delta)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(Arc::new(ProductRuntimeOverviewTick {
        sequence,
        reload_count,
        payload: payload.into(),
    }))
}
